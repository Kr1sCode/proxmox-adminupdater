#!/usr/bin/env python3
"""adminupdater brain: decide WHAT to update and WHERE, record results.

Produces the plan the host-side executor pulls; stores the reports it posts
back. No execution happens here. Guest schedule fields reuse core.is_due, so a
guest can update on a fixed interval or on calendar days/times.
"""

import datetime as dt
import re
import time
import uuid

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
    "auto_reboot": False,        # reboot after update IF /var/run/reboot-required, then verify
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


def build_update_job(g, vmid, sett):
    """Assemble ONE update job (a single pre-snapshot covering security-patch,
    then the app recipe, then the health-check). Shared by the scheduler and by
    ad-hoc 'update now' so both go through the exact same, host-validated shape."""
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
        return None
    return {
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
        "auto_reboot": bool(g.get("auto_reboot")),
    }


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
            job = build_update_job(g, vmid, sett)
            if job:
                jobs.append(job)

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
    done_qids = set()
    for r in results:
        kind = r.get("kind", "update")
        if r.get("qid"):            # ad-hoc job finished -> drop it from the queue
            done_qids.add(r["qid"])
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
        elif kind == "purge":
            entry["last_purge"] = rec   # ad-hoc: touches no schedule clock
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
    if done_qids:
        q = [j for j in state.get(QUEUE_KEY, []) if j.get("qid") not in done_qids]
        state[QUEUE_KEY] = q
    core.save_state(state)
    return {"recorded": len(results)}


RUNNING_STALE = 2 * 3600   # a "running" marker older than this is treated as dead
HOST_KEY = "_host"         # state slot for the PVE host's own update status + schedule
INVENTORY_KEY = "_inventory"   # fleet scan posted by the host executor
QUEUE_KEY = "_queue"       # one-shot ad-hoc jobs (snapshot/purge/update now)


def set_inventory(data):
    # Backstop: never let an empty/failed scan clobber good inventory. A scan
    # that timed out (pvesm/pct) can come back with zero guests; if we already
    # hold real data, keep it — otherwise propose_schedule would see 0 fresh
    # guests and a fallback window, and could plan into a real backup slot.
    data = dict(data or {})
    if not data.get("guests"):
        if get_inventory().get("guests"):
            return {"ok": False, "kept": True}
    state = core.load_state()
    state[INVENTORY_KEY] = data
    core.save_state(state)
    return {"ok": True}


def get_inventory():
    return core.load_state().get(INVENTORY_KEY, {})


# ---- ad-hoc job queue --------------------------------------------------------
# One-shot actions a user triggers from the panel (snapshot / purge / update
# "now"). They ride the SAME pull model: the panel appends jobs here, /plan hands
# them to the host executor once, and the matching report removes them by qid.
# Ad-hoc jobs deliberately bypass the backup-window defer (the user asked for it
# explicitly); the host ctid whitelist still gates every one of them.

def enqueue(jobs):
    """Append one-shot jobs to the queue, each tagged with a unique qid."""
    jobs = [jobs] if isinstance(jobs, dict) else list(jobs)
    if not jobs:
        return []
    state = core.load_state()
    q = state.get(QUEUE_KEY, [])
    qids = []
    for job in jobs:
        j = dict(job)
        j["qid"] = uuid.uuid4().hex[:12]
        j["enqueued_at"] = int(time.time())
        q.append(j)
        qids.append(j["qid"])
    state[QUEUE_KEY] = q
    core.save_state(state)
    return qids


def take_queue():
    """Return queued jobs ready to dispatch and mark them in-flight. A job is
    re-dispatched only if a prior dispatch went stale (executor died mid-run)."""
    state = core.load_state()
    q = state.get(QUEUE_KEY, [])
    if not q:
        return []
    now = int(time.time())
    out, changed = [], False
    for job in q:
        d = job.get("dispatched_at", 0)
        if d and now - d < RUNNING_STALE:
            continue                       # still in flight
        job["dispatched_at"] = now
        changed = True
        out.append({k: v for k, v in job.items() if k != "enqueued_at"})
    if changed:
        state[QUEUE_KEY] = q
        core.save_state(state)
    return out


def queue_pending():
    """UI view: what's still queued, per ctid (drives the 'queued' badge)."""
    q = core.load_state().get(QUEUE_KEY, [])
    return [{"ctid": j.get("ctid"), "kind": j.get("kind"),
             "dispatched": bool(j.get("dispatched_at"))} for j in q]


def enqueue_actions(action, vmids):
    """Build + enqueue ad-hoc jobs for a list of ctids. Returns (qids, skipped)."""
    cfg = core.load_config()
    sett = cfg["settings"]
    jobs, skipped = [], []
    for vmid in vmids:
        g = guest_settings(cfg, vmid)
        if action == "snapshot":
            s = g["snapshot"]
            jobs.append({"kind": "snapshot", "ctid": int(vmid),
                         "snapshot_prefix": s["prefix"], "keep": int(s["keep"]),
                         "max_age_days": int(s["max_age_days"]), "dryrun": False})
        elif action == "purge":
            prefixes = sorted({sett["snapshot_prefix"], g["snapshot"]["prefix"]})
            jobs.append({"kind": "purge", "ctid": int(vmid), "prefixes": prefixes})
        elif action == "update":
            job = build_update_job(g, vmid, sett)
            if job:
                jobs.append(job)
            else:
                skipped.append(int(vmid))   # nothing to do (no patch, no recipe)
        else:
            raise ValueError(f"unknown action {action!r}")
    return enqueue(jobs), skipped


def apply_schedule(plan, weekday):
    """Write a proposed schedule back into guest configs: calendar mode, the
    assigned time, the maintenance weekday, update enabled. Idempotent per guest."""
    cfg = core.load_config()
    applied = []
    for item in plan or []:
        vmid = str(item.get("vmid"))
        tm = str(item.get("time", "")).strip()
        if not _hhmm(tm):
            continue
        g = dict(GUEST_DEFAULTS)
        g.update(cfg.get("guests", {}).get(vmid, {}))
        g["enabled"] = True
        g["mode"] = "calendar"
        g["times"] = [tm]
        g["weekdays"] = [int(weekday)]
        cfg.setdefault("guests", {})[vmid] = g
        applied.append(int(vmid))
    if applied:
        core.save_config(cfg)
    return applied


def save_maintenance(patch):
    cfg = core.load_config()
    m = maintenance_settings(cfg)
    for k in MAINTENANCE_DEFAULTS:
        if k in patch:
            m[k] = patch[k]
    cfg["maintenance"] = m
    core.save_config(cfg)
    return m


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


# ---- intelligent service-window planner --------------------------------------
MAINTENANCE_DEFAULTS = {
    "window_start": "01:30",   # updates may run from here...
    "window_end": "05:00",     # ...to here
    "weekdays": [6],           # Sunday (Mon=0..Sun=6)
    "spacing_min": 20,         # gap between two guests (HDD: serialize)
    "concurrency": 1,          # max guests updating at once (HDD default 1)
}


def maintenance_settings(cfg):
    m = dict(MAINTENANCE_DEFAULTS)
    m.update(cfg.get("maintenance") or {})
    return m


def _hhmm(s):
    mt = re.match(r"^\s*(\d{1,2}):(\d{2})\s*$", str(s or ""))
    return int(mt.group(1)) * 60 + int(mt.group(2)) if mt else None


def _in_zone(minute, zones):
    for s, e in zones:
        inside = (s <= minute < e) if s <= e else (minute >= s or minute < e)
        if inside:
            return (s, e)
    return None


def forbidden_zones(cfg, inv, weekday):
    """Minute ranges where NOTHING may be scheduled: every detected backup window
    (daily, PBS + built-in vzdump alike) + the host-update slot. The host update
    is treated as an anchor to avoid REGARDLESS of its weekday — even if the host
    updates on a different day than the LXC window, we keep that clock slot clear
    so the two never line up (the user's second pillar next to the backup)."""
    zones = [(int(w["start_min"]), int(w["end_min"])) for w in inv.get("windows", [])]
    hu = host_update_settings(cfg)
    if hu.get("enabled") and hu.get("mode") == "calendar":
        hs = _hhmm((hu.get("times") or ["02:00"])[0])
        if hs is not None:
            zones.append((hs, (hs + 30) % 1440))
    return zones


def time_in_backup_window(cfg, hhmm, inv=None):
    """FOOLPROOF check: is this HH:MM inside a detected backup window? Used to
    reject/warn manual schedule entries before they can ever run."""
    inv = inv if inv is not None else get_inventory()
    m = _hhmm(hhmm)
    if m is None:
        return None
    for w in inv.get("windows", []):
        s, e = int(w["start_min"]), int(w["end_min"])
        if ((s <= m < e) if s <= e else (m >= s or m < e)):
            return w
    return None


def propose_schedule(cfg, vmids=None):
    """Place enrolled guests into conflict-free slots inside the maintenance
    window, skipping every forbidden zone, spaced out, honouring concurrency."""
    inv = get_inventory()
    m = maintenance_settings(cfg)
    ws, we = _hhmm(m["window_start"]), _hhmm(m["window_end"])
    spacing = max(1, int(m["spacing_min"]))
    conc = max(1, int(m["concurrency"]))
    weekday = (m["weekdays"] or [6])[0]
    zones = forbidden_zones(cfg, inv, weekday)

    if vmids is None:  # default: every LXC with a fresh backup
        now = int(time.time())
        fh = int(cfg["settings"].get("backup_fresh_hours", 24))
        vmids = sorted((v for v in (inv.get("guests") or {})
                        if guest_backup_fresh(v, inv, fh, now)), key=int)
    vmids = [str(v) for v in vmids]

    lanes = [ws] * conc
    assign, unplaceable = {}, []
    for v in vmids:
        placed = False
        for _ in range(conc):
            li = min(range(conc), key=lambda i: lanes[i])   # earliest-free lane
            cur = lanes[li]
            z = _in_zone(cur, zones)
            while z and cur < we:                            # jump past forbidden zones
                cur = z[1]
                z = _in_zone(cur, zones)
            if cur is not None and cur < we and not _in_zone(cur, zones):
                assign[v] = cur
                lanes[li] = cur + spacing
                placed = True
                break
            lanes[li] = we                                   # this lane is full
        if not placed:
            unplaceable.append(int(v))

    names = inv.get("guests") or {}
    fmt = lambda mn: f"{(mn // 60) % 24:02d}:{mn % 60:02d}"
    plan = [{"vmid": int(v), "name": names.get(v, {}).get("name", ""), "time": fmt(assign[v])}
            for v in sorted(assign, key=lambda x: assign[x])]
    slots = -(-(we - ws) // spacing) if (we is not None and ws is not None and we > ws) else 0  # ceil
    return {
        "maintenance": m, "weekday": weekday,
        "forbidden": [{"start": fmt(s), "end": fmt(e)} for s, e in zones],
        "plan": plan, "unplaceable": unplaceable,
        "capacity": {"slots_estimate": slots, "requested": len(vmids), "placed": len(assign)},
    }

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


# ---- notifications (panel-controlled; delivery uses the host's Proxmox mail) ----
# The panel decides WHEN / grouping / format / recipient; the actual transport
# (SMTP server + credentials) stays host-side in Proxmox's notifications.cfg. The
# executor reads this over /plan and applies it.
NOTIFY_DEFAULTS = {
    "when": "errors",       # always | errors | never
    "grouping": "digest",   # digest = one e-mail per service window | per-run = one per guest
    "format": "html",       # html | text
    "email": "",            # optional recipient override; empty = Proxmox target's own recipient
}
NOTIFY_TEST_KEY = "_notify_test"


def notify_settings(cfg):
    n = dict(NOTIFY_DEFAULTS)
    n.update(cfg.get("notify") or {})
    return n


def save_notify(patch):
    cfg = core.load_config()
    n = notify_settings(cfg)
    for k in NOTIFY_DEFAULTS:
        if k in patch:
            n[k] = patch[k]
    cfg["notify"] = n
    core.save_config(cfg)
    return n


def request_notify_test():
    st = core.load_state()
    st[NOTIFY_TEST_KEY] = int(time.time())
    core.save_state(st)


def take_notify_test():
    """True at most once per request: consumes the pending test flag."""
    st = core.load_state()
    if st.pop(NOTIFY_TEST_KEY, None):
        core.save_state(st)
        return True
    return False


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
        distro = (st.get("last") or {}).get("distro")
        out.append({"vmid": int(vmid), "name": meta["name"], "status": meta["status"],
                    "os": distro.capitalize() if distro and distro != "unknown" else None,
                    "config": g,
                    "report": st.get("last"), "report_snap": st.get("last_snap"),
                    "running": running,
                    "backup": {"info": inv_g.get("backup"), "fresh": fresh},
                    "snapshots": inv_g.get("snapshots"),
                    "blocked_no_backup": blocked})
    return {"settings": sett, "guests": out,
            "host": state.get(HOST_KEY), "host_update": host_update_settings(cfg),
            "notify": notify_settings(cfg), "inventory": inv}


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
