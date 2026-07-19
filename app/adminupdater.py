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

# One entry per guest the user opted in.
GUEST_DEFAULTS = {
    "enabled": False,
    "mode": "calendar",          # "interval" | "calendar"
    "interval_minutes": 10080,   # weekly, interval mode
    "times": ["03:30"],          # calendar mode
    "weekdays": [6],             # calendar mode: Sunday ([] = every day)
    "security_patch": True,      # OS patch upgrade (distro auto-detected on host)
    "app_update": None,          # None, or a recipe name present in host recipes dir
    "pre_snapshot": True,        # rollback snapshot before touching the guest
    "keep": None,                # keep newest N preupd_ snapshots (0 = no count limit); None = inherit
    "max_age_days": None,        # delete preupd_ older than N days (0 = off); None = inherit
}

# The ONLY actions the host executor accepts. Plans never carry raw commands.
ACTIONS = ("security-patch", "app-update")

_APP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")  # recipe name safety


def guest_settings(cfg, vmid):
    g = dict(GUEST_DEFAULTS)
    g.update(cfg.get("guests", {}).get(str(vmid), {}))
    sett = cfg.get("settings", {})
    if g.get("keep") is None:
        g["keep"] = int(sett.get("default_keep", 3))
    if g.get("max_age_days") is None:
        g["max_age_days"] = int(sett.get("default_max_age_days", 0))
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
    jobs = []
    for vmid in cfg.get("guests", {}):
        g = guest_settings(cfg, vmid)
        if not g["enabled"]:
            continue
        last = state.get(str(vmid), {}).get("last_run", 0)
        if not core.is_due(g, last, now):
            continue
        # One job per guest: a SINGLE pre-snapshot covers all actions, run in
        # order (security patches, then the app recipe) under one rollback point.
        actions = []
        if g["security_patch"]:
            actions.append("security-patch")
        app = g.get("app_update")
        if app and _APP_RE.match(str(app)):
            actions.append("app-update")
        elif app:
            core.log(f"guest {vmid}: invalid app recipe {app!r} -> skipped")
            app = None
        if not actions:
            continue
        jobs.append({
            "ctid": int(vmid),
            "actions": actions,
            "app": str(app) if app else None,
            "pre_snapshot": bool(g["pre_snapshot"]),
            "snapshot_prefix": sett["snapshot_prefix"],
            "rollback_on_fail": bool(sett["rollback_on_fail"]),
            "keep": int(g["keep"]),
            "max_age_days": int(g["max_age_days"]),
        })
    return jobs


def record_report(results):
    """Persist host-posted results; last_run per guest drives is_due()."""
    state = core.load_state()
    now = int(time.time())
    for r in results:
        vmid = str(r.get("ctid"))
        entry = state.get(vmid, {})
        entry["last_run"] = now
        last = {"status": r.get("status"), "snapshot": r.get("snapshot"),
                "ts": r.get("ts"), "steps": r.get("steps", []),
                "pruned": r.get("pruned", [])}
        entry["last"] = last
        entry["history"] = ([last] + entry.get("history", []))[:20]
        state[vmid] = entry
        step_summary = ", ".join(f"{s.get('action')}:{s.get('status')}" for s in r.get("steps", []))
        pruned = r.get("pruned", [])
        prune_note = f" pruned={len(pruned)}" if pruned else ""
        core.log(f"{vmid} -> {r.get('status')} snap={r.get('snapshot')} [{step_summary}]{prune_note}")
    core.save_state(state)
    return {"recorded": len(results)}


def guest_view():
    """UI helper: merge API guest list with config + last report."""
    cfg = core.load_config()
    pve = core.PVE(cfg["settings"])
    idx = core.guest_index(pve, lxc_only=True)
    state = core.load_state()
    out = []
    for vmid, meta in sorted(idx.items(), key=lambda kv: int(kv[0])):
        out.append({"vmid": int(vmid), "name": meta["name"], "status": meta["status"],
                    "config": guest_settings(cfg, vmid),
                    "report": state.get(vmid, {}).get("last")})
    return {"settings": cfg["settings"], "guests": out}


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
