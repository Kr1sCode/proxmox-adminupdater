#!/usr/bin/env python3
"""adminupdater brain: decide WHAT to update and WHERE, record results.

Produces the plan the host-side executor pulls; stores the reports it posts
back. No execution happens here. Guest schedule fields reuse core.is_due, so a
guest can update on a fixed interval or on calendar days/times.
"""

import datetime as dt
import re
import time

import core

# Independent snapshot schedule (autosnap-style), decoupled from updates.
SNAPSHOT_DEFAULTS = {
    "enabled": False,
    "mode": "calendar",          # "interval" | "calendar"
    "interval_minutes": 1440,    # daily, interval mode
    "times": ["02:00"],
    "weekdays": [],              # [] = every day
    "prefix": "auto",            # snapshot name prefix (distinct from preupd_)
    "keep": None,                # None = inherit default_keep
    "max_age_days": None,        # None = inherit default_max_age_days
    "dryrun": False,             # log what would happen, take nothing
}

# One entry per guest the user opted in.
GUEST_DEFAULTS = {
    "enabled": False,            # UPDATE schedule enabled
    "mode": "calendar",          # "interval" | "calendar"
    "interval_minutes": 10080,   # weekly, interval mode
    "times": ["03:30"],          # calendar mode
    "weekdays": [6],             # calendar mode: Sunday ([] = every day)
    "security_patch": True,      # OS patch upgrade (distro auto-detected on host)
    "app_update": None,          # None, or a recipe name present in host recipes dir
    "pre_snapshot": True,        # rollback snapshot before touching the guest
    "keep": None,                # preupd_ retention: keep newest N (0 = off); None = inherit
    "max_age_days": None,        # preupd_ retention: delete older than N days (0 = off); None = inherit
    "health_check": {"type": "none", "arg": ""},  # post-update probe; fail -> rollback
    "snapshot": None,            # None = inherit SNAPSHOT_DEFAULTS (disabled)
}

# The ONLY actions the host executor accepts. Plans never carry raw commands.
ACTIONS = ("security-patch", "app-update")

_APP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")  # recipe name safety


def guest_settings(cfg, vmid):
    g = dict(GUEST_DEFAULTS)
    g.update(cfg.get("guests", {}).get(str(vmid), {}))
    sett = cfg.get("settings", {})
    dk, da = int(sett.get("default_keep", 3)), int(sett.get("default_max_age_days", 0))
    if g.get("keep") is None:
        g["keep"] = dk
    if g.get("max_age_days") is None:
        g["max_age_days"] = da
    hc = g.get("health_check") if isinstance(g.get("health_check"), dict) else {}
    g["health_check"] = {"type": hc.get("type", "none"), "arg": str(hc.get("arg", ""))}
    s = dict(SNAPSHOT_DEFAULTS)
    s.update(g.get("snapshot") or {})
    if s.get("keep") is None:
        s["keep"] = dk
    if s.get("max_age_days") is None:
        s["max_age_days"] = da
    g["snapshot"] = s
    return g


def compute_plan():
    """Jobs due right now. Computed live -> the host timer is the clock; a run,
    once reported, sets last_run and stops being due (idempotent)."""
    cfg = core.load_config()
    sett = cfg["settings"]
    if sett.get("paused"):
        return []
    state = core.load_state()
    now = int(time.time())
    inv = state.get(INVENTORY_KEY, {})

    # GUARD 1: never collide with a running backup window (the IO-storm lesson).
    if sett.get("avoid_backup_window", True):
        win = active_backup_window(now, inv)
        if win:
            core.log(f"tick: okno backupu aktywne ({win.get('job')}) — odkładam wszystkie zadania")
            return []

    jobs = []
    for vmid in cfg.get("guests", {}):
        g = guest_settings(cfg, vmid)
        st = state.get(str(vmid), {})

        # --- UPDATE job: ONE pre-snapshot covers all actions, run in order
        # (security patches, then app recipe, then health-check) under one
        # rollback point. Its own clock: last_run.
        due = g["enabled"] and core.is_due(g, st.get("last_run", 0), now)
        # GUARD 2: don't auto-update a guest without a fresh backup.
        no_backup = (due and sett.get("require_backup", True)
                     and not guest_backup_fresh(vmid, inv, int(sett.get("backup_fresh_hours", 24)), now))
        if no_backup:
            core.log(f"guest {vmid}: brak świeżej kopii — auto-update wstrzymany (require_backup)")
        if due and not no_backup:
            actions = []
            if g["security_patch"]:
                actions.append("security-patch")
            app = g.get("app_update")
            if app and _APP_RE.match(str(app)):
                actions.append("app-update")
            elif app:
                core.log(f"guest {vmid}: invalid app recipe {app!r} -> skipped")
                app = None
            if actions:
                jobs.append({
                    "kind": "update",
                    "ctid": int(vmid),
                    "actions": actions,
                    "app": str(app) if app else None,
                    "pre_snapshot": bool(g["pre_snapshot"]),
                    "snapshot_prefix": sett["snapshot_prefix"],
                    "rollback_on_fail": bool(sett["rollback_on_fail"]),
                    "keep": int(g["keep"]),
                    "max_age_days": int(g["max_age_days"]),
                    "health_check": g["health_check"],
                })

        # --- SNAPSHOT job: independent scheduled snapshot (autosnap-style),
        # separate clock: last_snap_run. Distinct prefix so retention families
        # never collide.
        s = g["snapshot"]
        if s["enabled"] and core.is_due(s, st.get("last_snap_run", 0), now):
            jobs.append({
                "kind": "snapshot",
                "ctid": int(vmid),
                "snapshot_prefix": s["prefix"],
                "keep": int(s["keep"]),
                "max_age_days": int(s["max_age_days"]),
                "dryrun": bool(s["dryrun"]),
            })

    # --- HOST UPDATE job: update the PVE host itself (own clock in _host).
    hu = host_update_settings(cfg)
    if hu["enabled"]:
        last_host = state.get(HOST_KEY, {}).get("last_run", 0)
        if core.is_due(hu, last_host, now):
            jobs.append({"kind": "host-update"})
    return jobs


def record_report(results):
    """Persist host-posted results; last_run per guest drives is_due()."""
    state = core.load_state()
    now = int(time.time())
    for r in results:
        kind = r.get("kind", "update")
        rec = {"kind": kind, "status": r.get("status"), "snapshot": r.get("snapshot"),
               "ts": r.get("ts"), "steps": r.get("steps", []),
               "pruned": r.get("pruned", []), "reboot": r.get("reboot", False)}
        if kind == "host-update":
            hs = state.get(HOST_KEY, {})
            hs["last_run"] = now
            hs["last"] = rec
            state[HOST_KEY] = hs
            core.log(f"host-update -> {r.get('status')} reboot={r.get('reboot', False)}")
            continue
        vmid = str(r.get("ctid"))
        entry = state.get(vmid, {})
        if kind == "snapshot":
            entry["last_snap_run"] = now
            entry["last_snap"] = rec
        else:
            entry["last_run"] = now
            entry["last"] = rec
        entry.pop("running", None)   # a finished report clears the spinner
        entry.setdefault("history", [])
        entry["history"] = ([rec] + entry["history"])[:30]
        state[vmid] = entry
        step_summary = ", ".join(f"{s.get('action')}:{s.get('status')}" for s in r.get("steps", []))
        pruned = r.get("pruned", [])
        prune_note = f" pruned={len(pruned)}" if pruned else ""
        core.log(f"{vmid} [{kind}] -> {r.get('status')} snap={r.get('snapshot')} [{step_summary}]{prune_note}")
    core.save_state(state)
    return {"recorded": len(results)}


RUNNING_STALE = 2 * 3600   # a "running" marker older than this is treated as dead
HOST_KEY = "_host"         # state slot for the PVE host's own update status + schedule
INVENTORY_KEY = "_inventory"   # fleet scan posted by the host executor


def set_inventory(data):
    state = core.load_state()
    state[INVENTORY_KEY] = dict(data or {})
    core.save_state(state)
    return {"ok": True}


def get_inventory():
    return core.load_state().get(INVENTORY_KEY, {})


def _now_minute(now_ts):
    lt = time.localtime(now_ts)
    return lt.tm_hour * 60 + lt.tm_min


def active_backup_window(now_ts, inv):
    """Return the backup window covering 'now' (handles wrap past midnight), else None."""
    m = _now_minute(now_ts)
    for w in inv.get("windows", []):
        s, e = int(w.get("start_min", 0)), int(w.get("end_min", 0))
        inside = (s <= m < e) if s <= e else (m >= s or m < e)
        if inside:
            return w
    return None


def guest_backup_fresh(vmid, inv, fresh_hours, now_ts):
    g = (inv.get("guests") or {}).get(str(vmid))
    if not g or not g.get("backup"):
        return False
    try:
        t = dt.datetime.strptime(g["backup"]["ts"], "%Y-%m-%d %H:%M:%S")
        age = now_ts - t.replace(tzinfo=dt.timezone.utc).timestamp()
        return 0 <= age < fresh_hours * 3600
    except (ValueError, KeyError):
        return False

# Schedule for updating the PVE host itself. The ACTUAL command lives host-side
# in host.conf (host_update_cmd) — the panel only decides timing + enable, never
# ships a command. Weekday default 5 = Saturday (Mon=0..Sun=6), matching the
# typical "Sat 02:00" host cron.
HOST_UPDATE_DEFAULTS = {
    "enabled": False,
    "mode": "calendar",
    "interval_minutes": 10080,
    "times": ["02:00"],
    "weekdays": [5],
}


def host_update_settings(cfg):
    h = dict(HOST_UPDATE_DEFAULTS)
    h.update(cfg.get("host_update") or {})
    return h


def set_host_status(data):
    """Merge the PVE host's update status (pending count, reboot flag, version)
    posted by the host executor. Merges so it never clobbers last_run/last."""
    state = core.load_state()
    hs = state.get(HOST_KEY, {})
    hs.update(dict(data or {}))
    state[HOST_KEY] = hs
    core.save_state(state)
    return {"ok": True}


def get_host_status():
    return core.load_state().get(HOST_KEY)


def set_running(ctid, kind):
    """Mark a guest as currently being processed by the host executor (drives the
    UI spinner). Cleared by the matching report, or aged out after RUNNING_STALE."""
    state = core.load_state()
    vmid = str(ctid)
    entry = state.get(vmid, {})
    entry["running"] = {"kind": kind, "since": int(time.time())}
    state[vmid] = entry
    core.save_state(state)
    return {"ok": True}


def guest_view():
    """UI helper: merge API guest list with config + last report + running flag."""
    cfg = core.load_config()
    pve = core.PVE(cfg["settings"])
    idx = core.guest_index(pve, lxc_only=True)
    state = core.load_state()
    now = int(time.time())
    sett = cfg["settings"]
    inv = state.get(INVENTORY_KEY, {})
    fresh_h = int(sett.get("backup_fresh_hours", 24))
    out = []
    for vmid, meta in sorted(idx.items(), key=lambda kv: int(kv[0])):
        st = state.get(vmid, {})
        run = st.get("running")
        running = run if (run and now - int(run.get("since", 0)) < RUNNING_STALE) else None
        inv_g = (inv.get("guests") or {}).get(vmid, {})
        fresh = guest_backup_fresh(vmid, inv, fresh_h, now)
        g = guest_settings(cfg, vmid)
        blocked = bool(g["enabled"] and sett.get("require_backup", True) and not fresh)
        out.append({"vmid": int(vmid), "name": meta["name"], "status": meta["status"],
                    "config": g,
                    "report": st.get("last"), "report_snap": st.get("last_snap"),
                    "running": running,
                    "backup": {"info": inv_g.get("backup"), "fresh": fresh},
                    "snapshots": inv_g.get("snapshots"),
                    "blocked_no_backup": blocked})
    return {"settings": sett, "guests": out,
            "host": state.get(HOST_KEY), "host_update": host_update_settings(cfg),
            "inventory": inv}


if __name__ == "__main__":
    import json
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "plan"
    if cmd == "plan":
        print(json.dumps({"generated_at": dt.datetime.utcnow().isoformat() + "Z",
                          "jobs": compute_plan()}, indent=2))
    elif cmd == "state":
        print(json.dumps(core.load_state(), indent=2))
    else:
        sys.exit(f"unknown cmd {cmd}")
