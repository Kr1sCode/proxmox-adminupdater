#!/usr/bin/env python3
"""proxmox-adminupdater host-side executor.

The ONLY component on the Proxmox host. Stateless and dumb: pulls a plan from the
adminupdater LXC, runs `pct snapshot` + `pct exec` per job, posts results back.
All policy lives in the LXC EXCEPT the ctid whitelist, which is ALSO enforced
here -- a compromised LXC can at most request security-patch / app-update on a
ctid the host itself already allows, never host root and never a raw command.

Runs as root (needs pct). stdlib only -- PVE ships python3.
"""

import configparser
import json
import os
import ssl
import subprocess
import sys
import urllib.request
from datetime import datetime, timezone

CFG = os.environ.get("ADMINUPDATER_HOST_CONF", "/etc/proxmox-adminupdater/host.conf")


def load_cfg():
    c = configparser.ConfigParser()
    if not c.read(CFG):
        sys.exit(f"missing config {CFG}")
    g = c["main"]
    raw = g.get("allowed_ctids", "")
    allow_all = "*" in raw  # "trust the panel" mode: the LXC whitelist suffices
    return {
        "url": g["updater_url"].rstrip("/"),
        "token": g["token"],
        "allow_all": allow_all,
        "allowed": set() if allow_all else {int(x) for x in raw.split(",") if x.strip()},
        "recipes_dir": g.get("recipes_dir", "/etc/proxmox-adminupdater/recipes"),
        "timeout": g.getint("exec_timeout", 1800),
        "insecure": g.getboolean("tls_insecure", False),
    }


def http(cfg, path, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(cfg["url"] + path, data=data, method=method,
        headers={"Authorization": f"Bearer {cfg['token']}", "Content-Type": "application/json"})
    ctx = ssl._create_unverified_context() if cfg["insecure"] else None
    with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
        return json.loads(r.read() or b"{}")


def run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr)
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"


def detect_distro(ctid):
    _, out = run(["pct", "exec", str(ctid), "--", "cat", "/etc/os-release"], 30)
    for line in out.splitlines():
        if line.startswith("ID="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def build_security_patch(d):
    if d in ("debian", "ubuntu"):
        # Full upgrade. For security-only: install unattended-upgrades in the
        # guest and swap for ["bash","-lc","unattended-upgrade -v"].
        return ["bash", "-lc",
                "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && "
                "apt-get -y -o Dpkg::Options::=--force-confold upgrade"]
    if d == "alpine":
        return ["ash", "-lc", "apk update && apk upgrade --no-cache"]
    if d in ("arch", "archarm"):
        return ["bash", "-lc", "pacman -Syu --noconfirm"]
    return None


def _safe_name(app):
    return bool(app) and all(c.isalnum() or c in "-._" for c in app) and app[0].isalnum()


def build_app_update(cfg, ctid, app):
    if not _safe_name(app):
        return None
    recipe = os.path.join(cfg["recipes_dir"], f"{app}.sh")
    if not os.path.isfile(recipe):
        return None
    dest = "/tmp/.adminupdater-recipe.sh"
    rc, _ = run(["pct", "push", str(ctid), recipe, dest, "--perms", "700"], 60)
    if rc != 0:
        return None
    return ["bash", "-lc", f"{dest}; rc=$?; rm -f {dest}; exit $rc"]


def snapshot(ctid, prefix):
    name = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}"
    rc, out = run(["pct", "snapshot", str(ctid), name,
                   "--description", "proxmox-adminupdater pre-update"], 300)
    return (name if rc == 0 else None), out


def rollback(ctid, snap, timeout):
    rc, _ = run(["pct", "rollback", str(ctid), snap], timeout)
    return rc == 0


def do_job(cfg, job):
    ctid = int(job["ctid"])
    # back-compat: accept a list "actions" or a single legacy "action"
    actions = job.get("actions") or ([job["action"]] if job.get("action") else [])
    res = {"ctid": ctid, "ts": datetime.now(timezone.utc).isoformat(),
           "snapshot": None, "steps": []}

    if not (cfg.get("allow_all") or ctid in cfg["allowed"]):
        return {**res, "status": "rejected",
                "steps": [{"action": a, "status": "rejected", "rc": -1,
                           "log": "ctid poza whitelistą hosta"} for a in actions]}

    # 1) ONE snapshot up front — the rollback point for every action below.
    snap = None
    if job.get("pre_snapshot", True):
        snap, snaplog = snapshot(ctid, job.get("snapshot_prefix", "preupd"))
        res["snapshot"] = snap
        if snap is None:
            return {**res, "status": "error",
                    "steps": [{"action": "snapshot", "status": "error", "rc": -1,
                               "log": "snapshot nieudany: " + snaplog[-500:]}]}

    # 2) detect the guest OS ONCE
    distro = detect_distro(ctid)

    # 3) run each action in order under that one snapshot
    overall = "ok"
    for action in actions:
        step = {"action": action}
        if action == "security-patch":
            cmd = build_security_patch(distro)
        elif action == "app-update":
            cmd = build_app_update(cfg, ctid, str(job.get("app", "")))
        else:
            cmd = None
        if cmd is None:
            res["steps"].append({**step, "status": "skipped", "rc": 0,
                                 "log": f"brak obsługi ({distro}) / recepty"})
            continue
        rc, out = run(["pct", "exec", str(ctid), "--", *cmd], cfg["timeout"])
        res["steps"].append({**step, "status": ("ok" if rc == 0 else "failed"),
                             "rc": rc, "log": out[-2000:]})
        if rc != 0:
            overall = "failed"
            if snap and job.get("rollback_on_fail"):
                overall = "rolled-back" if rollback(ctid, snap, cfg["timeout"]) else "failed-rollback"
            break  # stop the chain; the snapshot is the safety net

    res["status"] = overall
    return res


def main():
    cfg = load_cfg()
    jobs = http(cfg, "/plan").get("jobs", [])
    if not jobs:
        print("nic do zrobienia")
        return
    results = [do_job(cfg, j) for j in jobs]
    http(cfg, "/report", "POST", {"results": results})
    bad = [r for r in results if r["status"] not in ("ok", "skipped")]
    print(f"wykonano {len(results)} zadań, {len(bad)} problemów")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
