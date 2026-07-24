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
    "auto_reboot": True,         # reboot after a successful update, then verify it comes back
    "reboot_mode": "required",   # "required" = only if /var/run/reboot-required | "always"
    "offline_mode": "skip",      # powered-off guest: "skip" | "start_stop" | "start_keep"
    "ram_boost": None,           # temporary RAM raise for the app-update build; None = inherit global
    "ram_boost_mb": None,        # target floor in MB; None = inherit global
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
    # RAM boost is per guest (a build-heavy n8n needs it, a tiny AdGuard doesn't);
    # unset falls back to the global setting, which is where it used to live.
    if g.get("ram_boost") is None:
        g["ram_boost"] = bool(sett.get("ram_boost", False))
    if g.get("ram_boost_mb") is None:
        g["ram_boost_mb"] = int(sett.get("ram_boost_mb", 4096) or 4096)
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
        # "always" reboots every successful update; "required" waits for the guest to
        # ask for it (/var/run/reboot-required) — rare in LXC, no kernel of its own.
        "reboot_mode": "always" if g.get("reboot_mode") == "always" else "required",
        # what to do when the container is powered off at update time
        "offline_mode": (g.get("offline_mode") if g.get("offline_mode")
                         in ("start_stop", "start_keep") else "skip"),
        # Temporary RAM boost for the memory-heavy app-update build (opt-in, per
        # guest). The host clamps the target to its own ram_boost_max_mb and only ever
        # raises — see maybe_ram_boost in the executor.
        "ram_boost": {"enabled": bool(g.get("ram_boost")),
                      "mb": int(g.get("ram_boost_mb") or 4096)},
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
               "pruned": r.get("pruned", []), "reboot": r.get("reboot", False),
               "ram_boost": r.get("ram_boost")}
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
EXEC_SEEN_KEY = "_exec_seen"   # last time the host executor authenticated (heartbeat)


def touch_exec():
    """Stamp the executor heartbeat. Called on every authenticated /plan poll, so a
    dead timer / wrong exec-token shows up in the watchdog within one tick."""
    state = core.load_state()
    state[EXEC_SEEN_KEY] = int(time.time())
    core.save_state(state)


def _short_err(e):
    """A compact, secret-free reason string for the watchdog."""
    import requests as _rq
    if isinstance(e, _rq.HTTPError) and e.response is not None:
        code = e.response.status_code
        if code in (401, 403):
            return f"token PVE odrzucony ({code})"
        return f"PVE HTTP {code}"
    if isinstance(e, _rq.exceptions.SSLError):
        return "błąd TLS (certyfikat)"
    if isinstance(e, _rq.exceptions.ConnectionError):
        return "brak połączenia z PVE"
    if isinstance(e, _rq.exceptions.Timeout):
        return "PVE nie odpowiada (timeout)"
    return e.__class__.__name__


def health():
    """Watchdog: is the brain->PVE API path alive (token valid, host reachable), and
    is the host executor still checking in? Surfaces both failure modes that leave the
    panel blank — a dead PVE token (no guest list) and a wrong exec-token (no inventory)."""
    cfg = core.load_config()
    pve = {"ok": False, "error": None, "ms": None}
    t0 = time.time()
    try:
        core.PVE(cfg["settings"])._req("GET", "/version")
        pve["ok"] = True
    except Exception as e:  # noqa: BLE001
        pve["error"] = _short_err(e)
    pve["ms"] = int((time.time() - t0) * 1000)
    state = core.load_state()
    seen = state.get(EXEC_SEEN_KEY)
    inv = state.get(INVENTORY_KEY, {})
    now = int(time.time())
    return {"now": now, "pve": pve,
            "exec": {"last_seen": seen, "age_s": (now - int(seen)) if seen else None},
            "inventory": {"checked": inv.get("checked"),
                          "guests": len(inv.get("guests") or {}),
                          "windows": len(inv.get("windows") or [])}}


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


def apply_schedule(plan, weekday=None):
    """Write a proposed schedule back into guest configs: calendar mode, the assigned
    time, and its OWN weekday (the weekly planner gives each guest a night). Falls
    back to the passed weekday for legacy callers. Idempotent per guest."""
    cfg = core.load_config()
    applied = []
    for item in plan or []:
        vmid = str(item.get("vmid"))
        tm = str(item.get("time", "")).strip()
        if not _hhmm(tm):
            continue
        wd = item.get("weekday", weekday if weekday is not None else 6)
        g = dict(GUEST_DEFAULTS)
        g.update(cfg.get("guests", {}).get(vmid, {}))
        g["enabled"] = True
        g["mode"] = "calendar"
        g["times"] = [tm]
        g["weekdays"] = [int(wd) % 7]
        cfg.setdefault("guests", {})[vmid] = g
        applied.append(int(vmid))
    if applied:
        core.save_config(cfg)
    return applied


def save_maintenance(patch):
    cfg = core.load_config()
    m = maintenance_settings(cfg)
    for k in ("window_start", "window_end", "days", "spacing_min", "concurrency"):
        if k in patch:
            m[k] = patch[k]
    m["days"] = sorted({int(d) % 7 for d in (m.get("days") or [6])}) or [6]
    m.pop("weekdays", None)   # drop the migrated legacy field
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
    "window_start": "01:30",   # nightly window: updates may run from here...
    "window_end": "05:00",     # ...to here
    "days": [6],               # weekdays AVAILABLE for updates (Mon=0..Sun=6) — the fleet
                               # is spread across these nights, not crammed into one
    "spacing_min": 20,         # gap between two guests (HDD: serialize)
    "concurrency": 1,          # max guests updating at once per night (HDD default 1)
}


def maintenance_settings(cfg):
    m = dict(MAINTENANCE_DEFAULTS)
    src = cfg.get("maintenance") or {}
    m.update(src)
    if "days" not in src and "weekdays" in src:   # migrate the old single-day field
        m["days"] = src["weekdays"]
    m["days"] = sorted({int(d) % 7 for d in (m.get("days") or [6])}) or [6]
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


def forbidden_zones(cfg, inv, weekday=None):
    """Hard zones for a given weekday: each detected backup window that runs that day
    (windows carry their own 'days'; None = every day) + host-maintenance zones the
    user promoted to 'avoid'. With weekday=None every window applies (conservative,
    used by the manual-entry guard). Day-specific host jobs are added by day_zones()."""
    zones = []
    for w in inv.get("windows", []):
        wd = w.get("days")
        if weekday is not None and wd is not None and weekday not in wd:
            continue                              # this backup runs on other days only
        zones.append((int(w["start_min"]), int(w["end_min"])))
    for z in (cfg.get("extra_forbidden") or {}).values():
        try:
            zones.append((int(z["start_min"]), int(z["end_min"])))
        except (KeyError, TypeError, ValueError):
            pass
    return zones


def _job_dur(io):
    return 90 if io == "heavy" else 45


def day_zones(cfg, inv, weekday):
    """ALL blockers to avoid on a given weekday: the everyday zones (backups +
    promoted) + the host update on its own weekday + every detected host-maintenance
    job (heavy AND medium — red/amber) that runs that day. The weekly planner uses
    this so each night dodges exactly that night's real disk-IO."""
    zones = list(forbidden_zones(cfg, inv, weekday))
    hu = host_update_settings(cfg)
    if hu.get("enabled") and hu.get("mode") == "calendar":
        hwds = hu.get("weekdays") or list(range(7))
        if weekday in hwds:
            hs = _hhmm((hu.get("times") or ["02:00"])[0])
            if hs is not None:
                zones.append((hs, (hs + 30) % 1440))
    for j in ((inv.get("host_jobs") or {}).get("jobs") or []):
        sm = j.get("start_min")
        if sm is None:
            continue
        wd = j.get("wd")
        if wd is not None and int(wd) != weekday:   # runs on another weekday
            continue
        zones.append((int(sm), (int(sm) + _job_dur(j.get("io"))) % 1440))
    return zones


def set_extra_forbidden(job_id, on, start_min=None, end_min=None, label=""):
    """Promote/demote a detected host-maintenance job to a hard forbidden zone."""
    cfg = core.load_config()
    ef = dict(cfg.get("extra_forbidden") or {})
    if on and start_min is not None and end_min is not None:
        ef[str(job_id)] = {"start_min": int(start_min), "end_min": int(end_min),
                           "label": str(label)}
    else:
        ef.pop(str(job_id), None)
    cfg["extra_forbidden"] = ef
    core.save_config(cfg)
    return ef


def time_in_backup_window(cfg, hhmm, inv=None, weekdays=None):
    """FOOLPROOF check: is this HH:MM inside a detected backup window? Used to
    reject/warn manual schedule entries before they can ever run. Day-aware: a window
    that only runs Sat (or the guest that only runs Wed) is no collision — pass the
    guest's weekdays ([] / None = every night, so every window counts)."""
    inv = inv if inv is not None else get_inventory()
    m = _hhmm(hhmm)
    if m is None:
        return None
    gwd = {int(d) % 7 for d in (weekdays or [])}
    for w in inv.get("windows", []):
        wwd = w.get("days")
        if gwd and wwd is not None and not (gwd & {int(d) % 7 for d in wwd}):
            continue                      # they never share a night
        s, e = int(w["start_min"]), int(w["end_min"])
        if ((s <= m < e) if s <= e else (m >= s or m < e)):
            return w
    return None


def _place_one(lanes, ws, we_lin, conc, spacing, zones):
    """Place ONE item into the earliest free lane of a night; return its LINEAR minute
    (>= 1440 when it lands after midnight) or None if the night is full. Works in a
    linear timeline [ws, we_lin) so a window that crosses midnight (e.g. 23:30->05:00,
    we_lin = 05:00 + 1440) is handled; zone tests use the wall-clock minute (cur % 1440).
    Mutates lanes."""
    for _ in range(conc):
        li = min(range(conc), key=lambda i: lanes[i])   # earliest-free lane
        cur = lanes[li]
        guard = 0
        while cur < we_lin and guard < 96:               # jump past forbidden zones
            z = _in_zone(cur % 1440, zones)
            if not z:
                break
            adv = (z[1] - (cur % 1440) + 1440) % 1440     # distance forward to the zone end
            cur += adv or 1
            guard += 1
        if cur < we_lin and not _in_zone(cur % 1440, zones):
            lanes[li] = cur + spacing
            return cur
        lanes[li] = we_lin                               # this lane is full
    return None


def _night_capacity(ws, we_lin, conc, spacing, zones):
    """How many placements fit in one night (used for ranking + the capacity meter)."""
    lanes, n = [ws] * conc, 0
    while n < 1000:
        if _place_one(lanes, ws, we_lin, conc, spacing, zones) is None:
            break
        n += 1
    return n


def propose_schedule(cfg, vmids=None):
    """WEEKLY planner: spread enrolled guests across the chosen nights of the week,
    preferring the QUIETEST nights (fewest host-maintenance blockers), each guest in
    a conflict-free spaced slot that dodges that night's real zones."""
    inv = get_inventory()
    m = maintenance_settings(cfg)
    ws, we = _hhmm(m["window_start"]), _hhmm(m["window_end"])
    spacing = max(1, int(m["spacing_min"]))
    conc = max(1, int(m["concurrency"]))
    days = m["days"] or [6]
    fmt = lambda mn: f"{(mn // 60) % 24:02d}:{mn % 60:02d}"
    names = inv.get("guests") or {}

    if vmids is None:  # default: every LXC with a fresh backup
        now = int(time.time())
        fh = int(cfg["settings"].get("backup_fresh_hours", 24))
        vmids = sorted((v for v in names if guest_backup_fresh(v, inv, fh, now)), key=int)
    vmids = [str(v) for v in vmids]

    # a window whose end is <= start crosses midnight -> extend it past 24:00 so the
    # night is one continuous span (23:30->05:00 becomes [1410, 1740)).
    we_lin = we if (we is not None and ws is not None and we > ws) else (we + 1440 if we is not None else None)
    if ws is None or we is None or we_lin <= ws:
        return {"maintenance": m, "days": days, "plan": [], "per_day": [],
                "unplaceable": [int(v) for v in vmids],
                "capacity": {"slots_per_week": 0, "requested": len(vmids), "placed": 0}}

    # one lane-set + zone-set per available night, with its free capacity
    nights = []
    for d in days:
        z = day_zones(cfg, inv, d)
        nights.append({"weekday": d, "zones": z, "lanes": [ws] * conc,
                       "cap": _night_capacity(ws, we_lin, conc, spacing, z), "placed": []})
    # quietest (most free) nights first
    order = sorted(range(len(nights)), key=lambda i: -nights[i]["cap"])

    assign, unplaceable, di = {}, [], 0
    for v in vmids:                        # round-robin across nights, biased to quiet ones
        placed = False
        for k in range(len(order)):
            night = nights[order[(di + k) % len(order)]]
            slot = _place_one(night["lanes"], ws, we_lin, conc, spacing, night["zones"])
            if slot is not None:
                night["placed"].append(v)
                # a slot past midnight belongs to the NEXT calendar day
                awd = (night["weekday"] + (1 if slot >= 1440 else 0)) % 7
                assign[v] = (awd, slot % 1440)
                night["cross"] = night.get("cross") or slot >= 1440
                di = (di + k + 1) % len(order)
                placed = True
                break
        if not placed:
            unplaceable.append(int(v))

    plan = [{"vmid": int(v), "name": names.get(v, {}).get("name", ""),
             "weekday": assign[v][0], "time": fmt(assign[v][1])}
            for v in sorted(assign, key=lambda x: (assign[x][0], assign[x][1]))]
    per_day = [{"weekday": nt["weekday"], "cap": nt["cap"],
                "forbidden": [{"start": fmt(s), "end": fmt(e)} for s, e in nt["zones"]],
                "items": [{"vmid": int(v), "name": names.get(v, {}).get("name", ""),
                           "time": fmt(assign[v][1])} for v in nt["placed"]]}
               for nt in nights]
    total = sum(nt["cap"] for nt in nights)
    return {
        "maintenance": m, "days": days, "plan": plan, "per_day": per_day,
        "unplaceable": unplaceable,
        "capacity": {"slots_per_week": total, "requested": len(vmids), "placed": len(assign),
                     "nights": len(days)},
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
    """UI helper: merge API guest list with config + last report + running flag.
    Resilient: if the PVE API is momentarily unreachable (dead token, host down) we
    fall back to the last inventory's guest list and flag pve_ok=False, so the panel
    stays usable and the watchdog explains why — instead of a blank 500."""
    cfg = core.load_config()
    state = core.load_state()
    now = int(time.time())
    sett = cfg["settings"]
    inv = state.get(INVENTORY_KEY, {})
    pve_ok = True
    try:
        idx = core.guest_index(core.PVE(sett), lxc_only=True)
    except Exception:  # noqa: BLE001
        pve_ok = False
        idx = {vid: {"type": "lxc", "node": "?", "name": g.get("name", ""), "status": "?"}
               for vid, g in (inv.get("guests") or {}).items()}
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
    return {"settings": sett, "guests": out, "pve_ok": pve_ok,
            "host": state.get(HOST_KEY), "host_update": host_update_settings(cfg),
            "notify": notify_settings(cfg), "extra_forbidden": cfg.get("extra_forbidden") or {},
            "maintenance": maintenance_settings(cfg), "inventory": inv}


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
