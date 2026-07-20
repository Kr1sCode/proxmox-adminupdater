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
import re
import shlex
import smtplib
import ssl
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText

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
        "notify_email": g.get("notify_email", "").strip(),
        "notify_on": g.get("notify_on", "errors").strip().lower(),   # always | errors | never
        "notify_from": g.get("notify_from", "adminupdater@" + os.uname().nodename).strip(),
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


def _snap_epoch(name):
    m = re.search(r"_(\d{8})_(\d{6})$", name)
    if not m:
        return 0
    try:
        return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
    except ValueError:
        return 0


def prune_snapshots(ctid, prefix, keep, max_age_days):
    """Delete old managed snapshots. ONLY names matching ^<prefix>_\\d{8}_\\d{6}$
    are ever touched (re-checked right before each delete), so manual snapshots
    and autosnap's auto_* are physically incapable of matching. Time is read
    from the name itself, so no date parsing of `pct listsnapshot` is needed."""
    keep, max_age_days = int(keep or 0), int(max_age_days or 0)
    if keep <= 0 and max_age_days <= 0:
        return []
    rx = re.compile(r"^" + re.escape(prefix) + r"_\d{8}_\d{6}$")
    rc, out = run(["pct", "listsnapshot", str(ctid)], 60)
    if rc != 0:
        return []
    names = sorted({t for t in re.findall(r"[A-Za-z0-9_]+", out) if rx.match(t)})
    to_del = set()
    if keep > 0 and len(names) > keep:
        to_del |= set(names[:len(names) - keep])          # oldest beyond keep
    if max_age_days > 0:
        cutoff = time.time() - max_age_days * 86400
        to_del |= {n for n in names if _snap_epoch(n) and _snap_epoch(n) < cutoff}
    deleted = []
    for n in sorted(to_del):
        if not rx.match(n):        # belt-and-suspenders
            continue
        rc, _ = run(["pct", "delsnapshot", str(ctid), n], 120)
        if rc == 0:
            deleted.append(n)
    return deleted


def build_health_check(hc):
    """Structured post-update probe -> a command, built HOST-side from a
    type+arg. No raw command string ever crosses from the LXC."""
    t = (hc or {}).get("type", "none")
    arg = str((hc or {}).get("arg", "")).strip()
    if t == "none" or not arg:
        return None
    if t == "systemd":
        if not re.match(r"^[A-Za-z0-9@._:-]+$", arg):
            return None
        return ["bash", "-lc", f"systemctl is-active --quiet {arg}"]
    if t == "http":
        if not re.match(r"^https?://[^\s'\"`;$\\]+$", arg):
            return None
        return ["bash", "-lc", f"curl -fsS -o /dev/null --max-time 10 -- {shlex.quote(arg)}"]
    return None


def _rollback_verdict(snap, job, ctid, timeout):
    if snap and job.get("rollback_on_fail"):
        return "rolled-back" if rollback(ctid, snap, timeout) else "failed-rollback"
    return "failed"


def do_job(cfg, job):
    ctid = int(job["ctid"])
    kind = job.get("kind", "update")
    prefix = job.get("snapshot_prefix", "preupd")
    res = {"ctid": ctid, "kind": kind, "ts": datetime.now(timezone.utc).isoformat(),
           "snapshot": None, "steps": [], "pruned": []}

    if not (cfg.get("allow_all") or ctid in cfg["allowed"]):
        return {**res, "status": "rejected",
                "steps": [{"action": kind, "status": "rejected", "rc": -1,
                           "log": "ctid poza whitelistą hosta"}]}

    # ===== independent scheduled snapshot job (autosnap-style) =====
    if kind == "snapshot":
        if job.get("dryrun"):
            name = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}"
            res.update(snapshot=name, status="ok",
                       steps=[{"action": "snapshot", "status": "dryrun", "rc": 0,
                               "log": f"[DRY-RUN] utworzyłbym {name}"}])
            return res
        snap, snaplog = snapshot(ctid, prefix)
        res["snapshot"] = snap
        if snap is None:
            res.update(status="error",
                       steps=[{"action": "snapshot", "status": "error", "rc": -1,
                               "log": "snapshot nieudany: " + snaplog[-500:]}])
            return res
        res["steps"].append({"action": "snapshot", "status": "ok", "rc": 0, "log": snap})
        res["pruned"] = prune_snapshots(ctid, prefix, job.get("keep", 0), job.get("max_age_days", 0))
        res["status"] = "ok"
        return res

    # ===== update job =====
    actions = job.get("actions") or ([job["action"]] if job.get("action") else [])

    # 1) ONE snapshot up front — the rollback point for every step below.
    snap = None
    if job.get("pre_snapshot", True):
        snap, snaplog = snapshot(ctid, prefix)
        res["snapshot"] = snap
        if snap is None:
            res.update(status="error",
                       steps=[{"action": "snapshot", "status": "error", "rc": -1,
                               "log": "snapshot nieudany: " + snaplog[-500:]}])
            return res

    # 1b) retention on preupd_ (fresh one protected by keep>=1 / age 0)
    res["pruned"] = prune_snapshots(ctid, prefix, job.get("keep", 0), job.get("max_age_days", 0))

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
            res["status"] = _rollback_verdict(snap, job, ctid, cfg["timeout"])
            return res  # stop the chain; the snapshot is the safety net

    # 4) post-update health-check — verify the guest actually works. A failing
    # probe fails the run (and rolls back) even though apt/apk returned 0.
    hcmd = build_health_check(job.get("health_check"))
    if hcmd:
        rc, out = run(["pct", "exec", str(ctid), "--", *hcmd], cfg["timeout"])
        res["steps"].append({"action": "health-check",
                             "status": ("ok" if rc == 0 else "failed"),
                             "rc": rc, "log": out[-2000:]})
        if rc != 0:
            overall = _rollback_verdict(snap, job, ctid, cfg["timeout"])

    res["status"] = overall
    return res


GOOD = ("ok", "skipped", "dryrun")


def _color(s):
    return {"ok": "#16a34a", "dryrun": "#0891b2", "skipped": "#64748b"}.get(s, "#dc2626")


def build_email_html(results, host):
    ok = sum(1 for r in results if r["status"] == "ok")
    bad = [r for r in results if r["status"] not in GOOD]
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    cards = []
    for r in results:
        col = _color(r["status"])
        steps = "".join(
            f"<tr><td style='padding:2px 10px;color:#475569'>{s.get('action')}</td>"
            f"<td style='padding:2px 10px;color:{_color(s.get('status'))};font-weight:600'>{s.get('status')}</td>"
            f"<td style='padding:2px 10px;color:#94a3b8'>rc={s.get('rc')}</td></tr>"
            for s in r.get("steps", []))
        pruned = r.get("pruned") or []
        prune = f" · pruned {len(pruned)}" if pruned else ""
        cards.append(
            f"<div style='border:1px solid #e2e8f0;border-radius:10px;margin:10px 0;overflow:hidden'>"
            f"<div style='background:{col};color:#fff;padding:8px 12px;font-weight:700'>"
            f"CT {r['ctid']} · {r.get('kind', 'update')} · {str(r['status']).upper()}</div>"
            f"<div style='padding:8px 12px;font-size:13px;color:#334155'>"
            f"<div>snapshot: <code>{r.get('snapshot') or '—'}</code>{prune}</div>"
            f"<table style='border-collapse:collapse;margin-top:6px'>{steps}</table></div></div>")
    banner = "#dc2626" if bad else "#16a34a"
    title = f"{len(bad)} problem(ów)" if bad else "wszystko OK"
    return (
        "<!doctype html><html><body style='margin:0;background:#f1f5f9;"
        "font-family:system-ui,Arial,sans-serif'>"
        "<div style='max-width:680px;margin:0 auto;padding:20px'>"
        f"<div style='background:{banner};color:#fff;border-radius:12px;padding:16px 20px'>"
        f"<div style='font-size:18px;font-weight:800'>◆ adminupdater — {title}</div>"
        f"<div style='opacity:.9;font-size:13px;margin-top:4px'>host {host} · {when} · "
        f"zadań: {len(results)} · OK: {ok} · problemy: {len(bad)}</div></div>"
        f"{''.join(cards)}"
        "<div style='color:#94a3b8;font-size:11px;text-align:center;margin-top:12px'>"
        "proxmox-adminupdater</div></div></body></html>")


def send_email(cfg, subject, html):
    msg = MIMEText(html, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg["notify_from"]
    msg["To"] = cfg["notify_email"]
    raw = msg.as_bytes()
    # 1) Proxmox host mail transport (postfix) via sendmail — the host's config
    for sm in ("/usr/sbin/sendmail", "/usr/lib/sendmail"):
        if os.path.exists(sm):
            try:
                if subprocess.run([sm, "-t", "-i"], input=raw, timeout=30).returncode == 0:
                    return True
            except Exception:  # noqa: BLE001
                pass
    # 2) fallback: local SMTP
    try:
        with smtplib.SMTP("localhost", 25, timeout=15) as s:
            s.send_message(msg)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"e-mail nieudany: {e}")
        return False


def maybe_notify(cfg, results):
    if not cfg["notify_email"] or cfg["notify_on"] == "never" or not results:
        return
    bad = [r for r in results if r["status"] not in GOOD]
    if cfg["notify_on"] == "errors" and not bad:
        return
    host = os.uname().nodename
    subject = f"[adminupdater] {host}: {'problemy' if bad else 'OK'} ({len(results)} zadań)"
    if send_email(cfg, subject, build_email_html(results, host)):
        print(f"raport e-mail wysłany do {cfg['notify_email']}")


def ping_progress(cfg, job):
    """Best-effort: tell the LXC we're starting this guest (drives the spinner)."""
    try:
        http(cfg, "/progress", "POST",
             {"ctid": int(job["ctid"]), "kind": job.get("kind", "update")})
    except Exception:  # noqa: BLE001 - a failed ping must never block the run
        pass


def host_status():
    """Read-only view of the PVE host's own update state for the top banner.
    Uses the existing apt lists (no forced refresh) — the host's own cron keeps
    them current. Never modifies anything."""
    st = {"checked": datetime.now(timezone.utc).isoformat(), "pve": "",
          "pending": None, "reboot": os.path.exists("/var/run/reboot-required")}
    rc, out = run(["pveversion"], 15)
    if rc == 0 and out.strip():
        st["pve"] = out.strip().splitlines()[0]
    rc, out = run(["bash", "-lc", "apt-get -s dist-upgrade 2>/dev/null | grep -c '^Inst '"], 60)
    if rc in (0, 1):  # grep -c returns 1 when count is 0
        try:
            st["pending"] = int(out.strip() or 0)
        except ValueError:
            st["pending"] = None
    return st


def post_host_status(cfg):
    try:
        http(cfg, "/host-status", "POST", host_status())
    except Exception:  # noqa: BLE001 - status is best-effort
        pass


def main():
    cfg = load_cfg()
    post_host_status(cfg)   # always refresh the banner, even with no jobs
    jobs = http(cfg, "/plan").get("jobs", [])
    if not jobs:
        print("nic do zrobienia")
        return
    results = []
    for j in jobs:
        ping_progress(cfg, j)
        results.append(do_job(cfg, j))
    http(cfg, "/report", "POST", {"results": results})
    maybe_notify(cfg, results)
    bad = [r for r in results if r["status"] not in GOOD]
    print(f"wykonano {len(results)} zadań, {len(bad)} problemów")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
