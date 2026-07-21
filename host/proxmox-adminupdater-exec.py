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
        "notify_via": g.get("notify_via", "pve").strip().lower(),    # pve | sendmail
        "notify_from": g.get("notify_from", "adminupdater@" + os.uname().nodename).strip(),
        # PVE host self-update (defence in depth: must be enabled host-side too)
        "host_update": g.getboolean("host_update", False),
        "host_update_cmd": g.get("host_update_cmd",
                                 "apt update && apt --yes --no-new-pkgs upgrade"),
        "host_update_log": g.get("host_update_log", "/var/log/proxmox-apt-upgrade.log"),
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


def build_app_update(cfg, ctid, app, distro="debian"):
    # "auto" = community-scripts behaviour: run the container's own /usr/bin/update
    # helper (present in helper-script CTs). Faithful to tools/pve/update-apps.sh:
    # PHS_SILENT=1 for unattended, TERM=dumb + a no-op `clear` on PATH (no TTY),
    # and a clean skip (exit 0) when the CT is not a helper-script container.
    if app == "auto":
        shell = "ash" if distro == "alpine" else "bash"
        # Run `update` with stdin from /dev/null and its output redirected to a FILE,
        # not our capture pipe. Community-scripts updaters often (re)start the app as
        # a daemon that would inherit our stdout pipe and keep it open -> the executor
        # would block reading until exec_timeout. Redirecting to a file means any
        # daemon inherits the file fd, and we just `tail` the file back afterwards.
        # A guest-side `timeout` also caps a genuinely stuck updater.
        to = "" if shell == "ash" else "timeout 1500 "  # busybox timeout differs; skip on alpine
        script = (
            "command -v update >/dev/null 2>&1 || "
            "{ echo 'brak /usr/bin/update — nie jest to kontener community-scripts, pomijam'; exit 0; }; "
            "mkdir -p /tmp/.nc; printf '#!/bin/sh\\n:\\n' > /tmp/.nc/clear; chmod +x /tmp/.nc/clear; "
            "export PATH=/tmp/.nc:$PATH; export TERM=dumb; export PHS_SILENT=1; "
            f"{to}update </dev/null >/tmp/.au-upd.log 2>&1; rc=$?; "
            "tail -c 8000 /tmp/.au-upd.log 2>/dev/null; rm -f /tmp/.au-upd.log; exit $rc"
        )
        return [shell, "-lc", script]
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


def reboot_and_verify(ctid, timeout, wait=150):
    """Reboot a container and confirm it comes back and is responsive. Returns
    (ok, log). Used after an update when the guest opted into auto-reboot AND the
    update left /var/run/reboot-required. If it never returns, the caller rolls
    back — so a wedged reboot is caught, not left broken."""
    t0 = time.time()
    rc, out = run(["pct", "reboot", str(ctid)], timeout)
    if rc != 0:  # some setups need an explicit stop/start
        run(["pct", "stop", str(ctid)], timeout)
        run(["pct", "start", str(ctid)], timeout)
    deadline = time.time() + wait
    while time.time() < deadline:
        if "running" in _sh(["pct", "status", str(ctid)], 15):
            rc2, _ = run(["pct", "exec", str(ctid), "--", "true"], 30)
            if rc2 == 0:
                return True, f"restart OK, wrócił po {int(time.time() - t0)}s"
        time.sleep(3)
    return False, f"kontener nie wrócił po restarcie w {wait}s"


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


def purge_managed(ctid, prefixes):
    """Delete ALL managed snapshots for the given prefixes. Same strict regex as
    prune_snapshots -- only ^<prefix>_\\d{8}_\\d{6}$ can ever match, re-checked
    right before each delete, so manual snapshots are physically safe."""
    rc, out = run(["pct", "listsnapshot", str(ctid)], 60)
    if rc != 0:
        return [], "listsnapshot nieudany: " + out[-300:]
    deleted = []
    for prefix in prefixes:
        if not _safe_name(prefix):
            continue
        rx = re.compile(r"^" + re.escape(prefix) + r"_\d{8}_\d{6}$")
        for n in sorted({t for t in re.findall(r"[A-Za-z0-9_]+", out) if rx.match(t)}):
            if not rx.match(n):        # belt-and-suspenders
                continue
            drc, _ = run(["pct", "delsnapshot", str(ctid), n], 120)
            if drc == 0:
                deleted.append(n)
    return deleted, ""


def build_health_check(hc):
    """Structured post-update probe -> a command, built HOST-side from a
    type+arg. No raw command string ever crosses from the LXC."""
    t = (hc or {}).get("type", "none")
    arg = str((hc or {}).get("arg", "")).strip()
    if t == "none":
        return None
    if t == "auto":
        # Universal, no-arg liveness probe that fits ANY LXC: if the guest runs
        # systemd, its system state must not be failed/offline; otherwise just
        # require a live init (PID 1). Covers both worlds so one setting works
        # fleet-wide — passes if the box is up, whichever init it uses.
        return ["bash", "-lc",
                "if command -v systemctl >/dev/null 2>&1; then "
                "case \"$(systemctl is-system-running 2>/dev/null)\" in "
                "running|degraded|starting|initializing|maintenance) exit 0;; *) exit 1;; esac; "
                "else [ -d /proc/1 ]; fi"]
    if not arg:
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


def do_host_update(cfg):
    """Update the PVE host itself. The command comes from host.conf (host-trusted),
    never from the plan. Gated by host_update=on (a compromised LXC can request it
    but the host still refuses unless opted in). No snapshot — it's the hypervisor."""
    res = {"kind": "host-update", "ts": datetime.now(timezone.utc).isoformat(),
           "snapshot": None, "steps": [], "pruned": [], "reboot": False}
    if not cfg.get("host_update"):
        return {**res, "status": "rejected",
                "steps": [{"action": "host-update", "status": "rejected", "rc": -1,
                           "log": "host_update wyłączony w host.conf"}]}
    log = cfg["host_update_log"]
    full = f"({cfg['host_update_cmd']}) >> {shlex.quote(log)} 2>&1"
    rc, out = run(["bash", "-lc", full], cfg["timeout"])
    res["reboot"] = os.path.exists("/var/run/reboot-required")
    res["steps"].append({"action": "host-update", "status": ("ok" if rc == 0 else "failed"),
                         "rc": rc, "log": (out or "")[-2000:]})
    res["status"] = "ok" if rc == 0 else "failed"
    return res


def do_job(cfg, job):
    kind = job.get("kind", "update")
    if kind == "host-update":
        return do_host_update(cfg)
    ctid = int(job["ctid"])
    prefix = job.get("snapshot_prefix", "preupd")
    res = {"ctid": ctid, "kind": kind, "ts": datetime.now(timezone.utc).isoformat(),
           "snapshot": None, "steps": [], "pruned": []}

    if not (cfg.get("allow_all") or ctid in cfg["allowed"]):
        return {**res, "status": "rejected",
                "steps": [{"action": kind, "status": "rejected", "rc": -1,
                           "log": "ctid poza whitelistą hosta"}]}

    # ===== ad-hoc purge: drop ALL managed snapshots (never touches manual ones) =====
    if kind == "purge":
        deleted, err = purge_managed(ctid, job.get("prefixes") or [])
        res["pruned"] = deleted
        if err:
            res.update(status="error",
                       steps=[{"action": "purge", "status": "error", "rc": -1, "log": err}])
            return res
        res["steps"].append({"action": "purge", "status": "ok", "rc": 0,
                             "log": f"usunięto {len(deleted)}: " + (", ".join(deleted) or "—")})
        res["status"] = "ok"
        return res

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

    # 2) detect the guest OS ONCE (also surfaced to the panel via the report)
    distro = detect_distro(ctid)
    res["distro"] = distro

    # 3) run each action in order under that one snapshot
    overall = "ok"
    for action in actions:
        step = {"action": action}
        if action == "security-patch":
            cmd = build_security_patch(distro)
        elif action == "app-update":
            cmd = build_app_update(cfg, ctid, str(job.get("app", "")), distro)
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

    # 4) optional post-update reboot — ONLY if the guest opted in AND the update
    # actually left /var/run/reboot-required (community-scripts convention). Verify
    # the container comes back; if not, roll back to the pre-update snapshot.
    if job.get("auto_reboot") and overall == "ok":
        rc, _ = run(["pct", "exec", str(ctid), "--",
                     "test", "-e", "/var/run/reboot-required"], 30)
        if rc == 0:
            ok, rlog = reboot_and_verify(ctid, cfg["timeout"])
            res["steps"].append({"action": "reboot", "status": ("ok" if ok else "failed"),
                                 "rc": 0 if ok else -1, "log": rlog})
            if not ok:
                res["status"] = _rollback_verdict(snap, job, ctid, cfg["timeout"])
                return res

    # 5) post-update health-check — verify the guest actually works. A failing
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
        label = "PVE host" if r.get("kind") == "host-update" else f"CT {r.get('ctid')}"
        cards.append(
            f"<div style='border:1px solid #e2e8f0;border-radius:10px;margin:10px 0;overflow:hidden'>"
            f"<div style='background:{col};color:#fff;padding:8px 12px;font-weight:700'>"
            f"{label} · {r.get('kind', 'update')} · {str(r['status']).upper()}</div>"
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


def _parse_notifications(path):
    """Parse a PVE notifications.cfg-style file -> {smtp_target_name: {key: val}}."""
    out, cur = {}, None
    try:
        lines = open(path).read().splitlines()
    except OSError:
        return out
    for ln in lines:
        if not ln.strip():
            cur = None
            continue
        if not ln[0].isspace():
            m = re.match(r"^(\w+):\s*(\S+)", ln)
            cur = m.group(2) if (m and m.group(1) == "smtp") else None
            if cur:
                out[cur] = {}
        elif cur:
            kv = ln.strip().split(None, 1)
            if len(kv) == 2:
                out[cur][kv[0]] = kv[1]
    return out


def pve_smtp_target():
    """Reuse Proxmox's configured SMTP notification target (server, creds,
    recipient) so e-mail is never configured twice. Public part in
    /etc/pve/notifications.cfg, the password in /etc/pve/priv/notifications.cfg."""
    pub = _parse_notifications("/etc/pve/notifications.cfg")
    if not pub:
        return None
    name = next(iter(pub))            # first smtp target (e.g. gmail-smtp)
    t = pub[name]
    pw = (_parse_notifications("/etc/pve/priv/notifications.cfg").get(name) or {}).get("password")
    if not (t.get("server") and t.get("mailto")):
        return None
    return {"server": t["server"], "port": int(t.get("port", 587)),
            "mode": (t.get("mode") or "starttls").lower(),
            "username": t.get("username"), "password": pw,
            "from": t.get("from-address") or t.get("username") or "adminupdater@localhost",
            "mailto": re.split(r"[,\s]+", t["mailto"].strip())}


def send_via_smtp(t, msg):
    if t["mode"] == "tls" or t["port"] == 465:
        srv = smtplib.SMTP_SSL(t["server"], t["port"], timeout=30)
    else:
        srv = smtplib.SMTP(t["server"], t["port"], timeout=30)
        srv.ehlo()
        if t["mode"] == "starttls":
            srv.starttls()
            srv.ehlo()
    if t.get("username") and t.get("password"):
        srv.login(t["username"], t["password"])
    srv.send_message(msg)
    srv.quit()


def _send_sendmail(msg):
    raw = msg.as_bytes()
    for sm in ("/usr/sbin/sendmail", "/usr/lib/sendmail"):
        if os.path.exists(sm):
            try:
                if subprocess.run([sm, "-t", "-i"], input=raw, timeout=30).returncode == 0:
                    return True
            except Exception:  # noqa: BLE001
                pass
    try:
        with smtplib.SMTP("localhost", 25, timeout=15) as s:
            s.send_message(msg)
        return True
    except Exception as e:  # noqa: BLE001
        print(f"sendmail/SMTP lokalny nieudany: {e}")
        return False


def deliver(cfg, subject, body, is_html=True):
    subtype = "html" if is_html else "plain"
    override = (cfg.get("notify_email") or "").strip()   # panel recipient override
    via = cfg.get("notify_via", "pve")
    if via == "pve":
        t = pve_smtp_target()
        if t:
            rcpts = [override] if override else t["mailto"]
            msg = MIMEText(body, subtype, "utf-8")
            msg["Subject"], msg["From"], msg["To"] = subject, t["from"], ", ".join(rcpts)
            try:
                send_via_smtp(t, msg)
                print(f"raport ({subtype}) wysłany przez PVE SMTP ({t['server']}) -> {', '.join(rcpts)}")
                return True
            except Exception as e:  # noqa: BLE001
                print(f"PVE SMTP nieudany: {e}; próbuję sendmail")
        else:
            print("brak skonfigurowanego targetu SMTP w PVE; próbuję sendmail")
    to = override or cfg.get("notify_email")
    if not to:
        print("brak notify_email do fallbacku — pomijam wysyłkę")
        return False
    msg = MIMEText(body, subtype, "utf-8")
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["notify_from"], to
    return _send_sendmail(msg)


def build_email_text(results, host):
    """Plain-text version of the report (for notify_format = text)."""
    ok = sum(1 for r in results if r["status"] == "ok")
    bad = [r for r in results if r["status"] not in GOOD]
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"adminupdater — {'PROBLEMY' if bad else 'wszystko OK'}",
             f"host {host} · {when} · zadań: {len(results)} · OK: {ok} · problemy: {len(bad)}",
             "-" * 56]
    for r in results:
        label = "PVE host" if r.get("kind") == "host-update" else f"CT {r.get('ctid')}"
        lines.append(f"{label} · {r.get('kind', 'update')} · {str(r['status']).upper()}")
        if r.get("snapshot"):
            lines.append(f"  snapshot: {r['snapshot']}")
        for s in r.get("steps", []):
            lines.append(f"  - {s.get('action')}: {s.get('status')} (rc={s.get('rc')})")
        pruned = r.get("pruned") or []
        if pruned:
            lines.append(f"  pruned: {len(pruned)}")
        lines.append("")
    lines.append("-- proxmox-adminupdater")
    return "\n".join(lines)


def _notify_batch(cfg, results):
    """Send ONE message for the given result set, honouring when/format."""
    bad = [r for r in results if r["status"] not in GOOD]
    if cfg.get("notify_on") == "errors" and not bad:
        return
    host = os.uname().nodename
    subject = f"[adminupdater] {host}: {'problemy' if bad else 'OK'} ({len(results)} zadań)"
    if cfg.get("notify_format", "html") == "text":
        deliver(cfg, subject, build_email_text(results, host), is_html=False)
    else:
        deliver(cfg, subject, build_email_html(results, host), is_html=True)


def maybe_notify(cfg, results):
    if cfg.get("notify_on") == "never" or not results:
        return
    if cfg.get("notify_grouping", "digest") == "per-run":
        for r in results:                 # one e-mail per guest/job
            _notify_batch(cfg, [r])
    else:
        _notify_batch(cfg, results)       # one digest for the whole window


def apply_notify_cfg(cfg, notify):
    """Overlay the panel-controlled notification settings (from /plan) onto cfg.
    The transport (Proxmox SMTP) stays host-side; the panel only picks
    when/grouping/format/recipient."""
    if not isinstance(notify, dict):
        return
    cfg["notify_on"] = str(notify.get("when", cfg.get("notify_on", "errors")))
    cfg["notify_grouping"] = str(notify.get("grouping", "digest"))
    cfg["notify_format"] = str(notify.get("format", "html"))
    if str(notify.get("email", "")).strip():
        cfg["notify_email"] = str(notify["email"]).strip()


def ping_progress(cfg, job):
    """Best-effort: tell the LXC we're starting this guest (drives the spinner)."""
    if "ctid" not in job:   # host-update has no ctid
        return
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


# ---- fleet inventory: backup jobs + windows + per-guest coverage --------------
INVENTORY_TS = "/var/lib/proxmox-adminupdater/inventory.ts"
INVENTORY_TTL = 3600   # re-scan at most hourly (pvesm over network is slow)


def _sh(cmd, t=25):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=t).stdout
    except Exception:  # noqa: BLE001
        return ""


def detect_backup_jobs():
    jobs, cur = [], None
    try:
        lines = open("/etc/pve/jobs.cfg").read().splitlines()
    except OSError:
        lines = []
    for ln in lines:
        if not ln.strip():
            cur = None
            continue
        if not ln[0].isspace():
            m = re.match(r"^(\w+):\s*(\S+)", ln)
            cur = {"id": m.group(2), "vmids": []} if (m and m.group(1) == "vzdump") else None
            if cur:
                jobs.append(cur)
        elif cur:
            k, _, v = ln.strip().partition(" ")
            v = v.strip()
            cur["vmids"] = [x for x in re.split(r"[,\s]+", v) if x] if k == "vmid" else cur.get("vmids", [])
            if k != "vmid":
                cur[k] = v
    return jobs


def _hhmm_min(s):
    m = re.search(r"\b(\d{1,2}):(\d{2})\b", s or "")
    return int(m.group(1)) * 60 + int(m.group(2)) if m else None


def _ts_min(ts):
    m = re.search(r"\b(\d\d):(\d\d):\d\d\b", ts or "")
    return int(m.group(1)) * 60 + int(m.group(2)) if m else None


def backup_coverage(storages):
    cov = {}
    for st in storages:
        for line in _sh(["pvesm", "list", st], 25).splitlines()[1:]:
            c = line.split()
            if len(c) < 2 or "backup" not in c[0]:
                continue
            volid, vmid = c[0], c[-1]
            m = re.search(r"(\d{4})[-_](\d\d)[-_](\d\d)[T_](\d\d)[:_](\d\d)[:_](\d\d)", volid)
            if not m:
                continue
            ts = "{}-{}-{} {}:{}:{}".format(*m.groups())
            if vmid not in cov or ts > cov[vmid]["ts"]:
                cov[vmid] = {"storage": st, "ts": ts}
    return cov


# ---- host maintenance scan (read-only situational awareness) ------------------
# Other scheduled work on the host competes for disk IO with LXC updates (ZFS
# scrub/trim, mdadm check, e2scrub, fstrim, unattended apt, offsite backups, cron).
# We only INFORM; the planner ignores these unless the user promotes one to a
# forbidden zone in the panel.
_JOB_CLASS = [
    (r"mdcheck|checkarray",                          "RAID check (mdadm)",        "heavy"),
    (r"zfs.*scrub|/scrub\b|zpool.*scrub",            "ZFS scrub",                 "heavy"),
    (r"zfs.*trim|/trim\b|zpool.*trim",               "ZFS trim",                  "medium"),
    (r"e2scrub",                                     "ext4 scrub (e2scrub)",      "medium"),
    (r"fstrim",                                      "fstrim (SSD TRIM)",         "medium"),
    (r"offsite|rsync",                               "offsite backup",            "heavy"),
    (r"proxmox-backup|garbage|verify|prune|\bpbs",   "PBS job",                   "heavy"),
    (r"apt-daily-upgrade|unattended",                "host apt upgrades",         "medium"),
    (r"config-backup",                               "PVE config backup",         "light"),
    (r"apt-daily\b",                                 "apt metadata refresh",      "light"),
    (r"pve-daily-update",                            "PVE update check",          "light"),
    (r"certbot|acme|letsencrypt",                    "cert renewal",              "light"),
    (r"logrotate|man-db|tmpfiles|dpkg-db-backup|mdmonitor|motd|beszel|update-notifier|run-parts",
                                                     "",                          "light"),
]


def _classify_job(text):
    t = text.lower()
    for rx, name, io in _JOB_CLASS:
        if re.search(rx, t):
            return (name or None), io
    return None, "light"


def _hhmm_of(s):
    m = re.search(r"\b(\d{1,2}):(\d{2})(?::\d{2})?\b", s)
    return (int(m.group(1)) * 60 + int(m.group(2))) if m else None


def scan_host_jobs():
    """Read-only list of scheduled host maintenance (systemd timers + cron),
    classified by disk-IO weight. Heavy/medium items returned individually;
    trivial ones only counted. INFORM-ONLY."""
    seen, jobs, light = set(), [], 0

    def add(key, name, io, start_min, sched, source, approx, wd=None):
        nonlocal light
        if key in seen:
            return
        seen.add(key)
        if io == "light":
            light += 1
            return
        jobs.append({"id": key, "name": name, "io": io, "start_min": start_min,
                     "sched": sched, "source": source, "approx": approx, "wd": wd})

    # systemd timers: NEXT time-of-day + unit (weekday left unknown -> treated daily)
    for ln in _sh(["systemctl", "list-timers", "--all", "--no-pager"], 15).splitlines():
        mu = re.search(r"(\S+)\.timer\b", ln)
        if not mu or mu.group(1).startswith("proxmox-adminupdater"):
            continue
        unit = mu.group(1)
        name, io = _classify_job(unit)
        start = _hhmm_of(ln)
        sched = (f"{start // 60:02d}:{start % 60:02d}" if start is not None else unit)
        add("timer:" + unit, name or unit, io, start, sched, "timer", start is None)

    # cron: /etc/crontab + /etc/cron.d/* + root crontab
    srcs, lines = ["/etc/crontab"], []
    try:
        srcs += [os.path.join("/etc/cron.d", f) for f in sorted(os.listdir("/etc/cron.d"))]
    except OSError:
        pass
    for pth in srcs:
        try:
            lines += [(os.path.basename(pth), l) for l in open(pth).read().splitlines()]
        except OSError:
            pass
    lines += [("root", l) for l in _sh(["crontab", "-l"], 10).splitlines()]
    for src, l in lines:
        l = l.strip()
        f = l.split()
        if len(f) < 6 or not re.match(r"^[\d*/,\-]+$", f[0]) or not re.match(r"^[\d*/,\-]+$", f[1]):
            continue                                   # skips comments, VAR= and non-cron lines
        mn, hr, dom, dow = f[0], f[1], f[2], f[4]
        system = src != "root"                          # system crontabs carry a user field
        cmd = " ".join(f[6:]) if (system and len(f) > 6) else " ".join(f[5:])
        if re.search(r"vzdump", cmd + " " + src):       # already shown as the backup window
            continue
        name, io = _classify_job(cmd + " " + src)
        start = int(hr) * 60 + int(mn) if re.match(r"^\d+$", hr) and re.match(r"^\d+$", mn) else None
        freq = "daily" if (dom == "*" and dow == "*") else ("monthly" if dom != "*" else "weekly")
        sched = freq + (f" {start // 60:02d}:{start % 60:02d}" if start is not None else "")
        approx = freq != "daily" or start is None
        # weekday (Mon=0..Sun=6) when determinable: numeric cron dow, or a `date +%w -eq N`
        # guard inside the command (the ZFS scrub/trim pattern). Else None = every night.
        wd = None
        mdow = re.match(r"^([0-7])$", dow)
        if mdow:
            wd = (int(mdow.group(1)) % 7 + 6) % 7      # cron 0/7=Sun,1=Mon -> Py Mon0..Sun6
        else:
            mw = re.search(r"date \+.?%w.?\s*-eq\s*([0-6])", cmd)
            if mw:
                wd = (int(mw.group(1)) + 6) % 7        # %w 0=Sun -> Py Sun=6
        add("cron:" + src + ":" + hr + ":" + mn + ":" + (cmd[:80] or l[:40]),
            name or (cmd.split()[0][:22] if cmd else src), io, start, sched, "cron", approx, wd)

    jobs.sort(key=lambda j: (j["start_min"] is None, j["start_min"] or 0))
    return {"jobs": jobs, "light_count": light}


def build_inventory():
    """Read-only fleet scan. Windows are LEARNED: start from the job schedule,
    end from the latest actual backup completion among the job's guests (+15 min)."""
    jobs = detect_backup_jobs()
    storages = sorted({j.get("storage") for j in jobs if j.get("storage")})
    cov = backup_coverage(storages)
    windows = []
    for j in jobs:
        smin = _hhmm_min(j.get("schedule"))
        if smin is None:            # monthly / non-daily -> no daily window
            continue
        # latest completion = max of FULL timestamps (lexicographic = chronological,
        # so a backup that crosses midnight is handled correctly), then +15 min margin.
        tss = [cov[v]["ts"] for v in j.get("vmids", []) if v in cov]
        end = (_ts_min(max(tss)) + 15) % 1440 if tss and _ts_min(max(tss)) is not None else (smin + 180) % 1440
        windows.append({"job": j["id"], "start_min": smin, "end_min": end, "storage": j.get("storage")})
    guests = {}
    for line in _sh(["pct", "list"], 15).splitlines()[1:]:
        c = line.split()
        if not c:
            continue
        vmid, name = c[0], (c[-1] if len(c) > 2 else "")
        snaps = sum(1 for l in _sh(["pct", "listsnapshot", vmid], 15).splitlines()
                    if re.search(r"_\d{8}_\d{6}", l))
        b = cov.get(vmid)
        guests[vmid] = {"name": name, "snapshots": snaps,
                        "backup": {"storage": b["storage"], "ts": b["ts"]} if b else None}
    return {"checked": datetime.now(timezone.utc).isoformat(),
            "jobs": [{"id": j["id"], "schedule": j.get("schedule"),
                      "storage": j.get("storage"), "vmids": j.get("vmids", [])} for j in jobs],
            "windows": windows, "guests": guests, "host_jobs": scan_host_jobs()}


def scan_ok(inv):
    """A scan is trustworthy only if it saw guests, and (when backup jobs exist)
    at least one real backup. Prevents a timed-out pvesm/pct from clobbering good
    data with an empty scan + a guessed window."""
    if not inv.get("guests"):
        return False
    if inv.get("jobs") and not any(g.get("backup") for g in inv["guests"].values()):
        return False
    return True


def maybe_refresh_inventory(cfg):
    """Throttled, best-effort. Never blocks jobs — called after report."""
    try:
        if time.time() - os.path.getmtime(INVENTORY_TS) < INVENTORY_TTL:
            return
    except OSError:
        pass
    inv = build_inventory()
    if not scan_ok(inv):
        print("inventory: skan niepełny (timeout?) — NIE nadpisuję dobrych danych")
        return   # no stamp update -> retry on the next tick
    try:
        http(cfg, "/inventory", "POST", inv)
    except Exception as e:  # noqa: BLE001
        print(f"inventory post nieudany: {e}")
        return
    os.makedirs(os.path.dirname(INVENTORY_TS), exist_ok=True)
    open(INVENTORY_TS, "w").write(str(int(time.time())))
    print(f"inventory odświeżone: {len(inv['guests'])} guestów, {len(inv['windows'])} okien backupu")


def sample_results():
    return [
        {"ctid": 108, "kind": "update", "status": "ok",
         "snapshot": "preupd_20260720_020000", "pruned": ["preupd_20260713_020000"],
         "steps": [{"action": "security-patch", "status": "ok", "rc": 0},
                   {"action": "app-update", "status": "ok", "rc": 0},
                   {"action": "health-check", "status": "ok", "rc": 0}]},
        {"kind": "host-update", "status": "failed", "reboot": True,
         "steps": [{"action": "host-update", "status": "failed", "rc": 100}]},
    ]


def main():
    cfg = load_cfg()
    post_host_status(cfg)   # always refresh the banner, even with no jobs
    plan = http(cfg, "/plan")
    apply_notify_cfg(cfg, plan.get("notify"))   # panel-controlled when/grouping/format/recipient
    results = []
    for j in plan.get("jobs", []):
        ping_progress(cfg, j)
        r = do_job(cfg, j)
        if j.get("qid"):        # echo so the brain can dequeue this ad-hoc job
            r["qid"] = j["qid"]
        results.append(r)
    if results:
        http(cfg, "/report", "POST", {"results": results})
        maybe_notify(cfg, results)
    if plan.get("notify_test"):    # "Send test" from the panel
        tcfg = dict(cfg); tcfg["notify_on"] = "always"; tcfg["notify_grouping"] = "digest"
        print("wysyłam e-mail testowy (żądanie z panelu)")
        _notify_batch(tcfg, sample_results())
    maybe_refresh_inventory(cfg)   # throttled hourly; runs even when nothing was due
    bad = [r for r in results if r["status"] not in GOOD]
    print(f"wykonano {len(results)} zadań, {len(bad)} problemów")
    sys.exit(1 if bad else 0)


def test_notify():
    """Send a sample report through the configured channel (for setup checks)."""
    cfg = load_cfg()
    cfg["notify_on"] = "always"
    _notify_batch(cfg, sample_results())


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "test-notify":
        test_notify()
    elif len(sys.argv) > 1 and sys.argv[1] == "inventory":
        inv = build_inventory()
        print(json.dumps(inv, indent=2, ensure_ascii=False))
        try:
            http(load_cfg(), "/inventory", "POST", inv)
            print("-> wysłane do mózgu (/inventory)")
        except Exception as e:  # noqa: BLE001
            print(f"-> post nieudany: {e}")
    else:
        main()
