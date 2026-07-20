#!/usr/bin/env python3
"""adminupdater shared core: config/state/log, Proxmox REST client, schedule math.

Runs inside the adminupdater LXC. Talks to the Proxmox host only through a
scoped API token (VM.Audit) for READ purposes (guest list/status). It performs
no writes to guests and no command execution -- an LXC cannot `pct exec` a
sibling. Actual updates are carried out by the host-side executor, which pulls a
plan from this container and posts results back.

Primitives here are deliberately generic (vendored from the proxmox-autosnap
lineage) so app/adminupdater.py and app/web.py stay small.
"""

import datetime as dt
import json
import os
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = os.environ.get("ADMINUPDATER_CONFIG", "/etc/adminupdater/config.json")
TOKEN_PATH = os.environ.get("ADMINUPDATER_TOKEN", "/etc/adminupdater/token")
STATE_PATH = os.environ.get("ADMINUPDATER_STATE", "/var/lib/adminupdater/state.json")
LOG_PATH = os.environ.get("ADMINUPDATER_LOG", "/var/log/adminupdater/adminupdater.log")

DEFAULT_SETTINGS = {
    "pve_host": "CHANGE_ME",
    "pve_port": 8006,
    "verify_tls": False,
    "paused": False,             # master switch: /plan returns nothing
    "snapshot_prefix": "preupd", # pre-update snapshot name prefix (host builds the name)
    "rollback_on_fail": False,   # host rolls back the pre-snapshot if a job fails
    "default_keep": 3,           # retention: keep newest N preupd_ snapshots (0 = no count limit)
    "default_max_age_days": 0,   # retention: delete preupd_ older than N days (0 = off)
    "require_backup": True,      # skip auto-update of a guest without a fresh backup
    "backup_fresh_hours": 24,    # a backup counts as "fresh" if newer than this
    "avoid_backup_window": True, # never run jobs while a detected backup window is active
}
DEFAULT_AUTH = {
    "allowlist": ["root@pam"],   # who may log in to the panel
}


def log(msg):
    line = f"[{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _atomic_write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def load_config():
    cfg = _read_json(CONFIG_PATH, {})
    settings = dict(DEFAULT_SETTINGS)
    settings.update(cfg.get("settings", {}))
    auth = dict(DEFAULT_AUTH)
    auth.update(cfg.get("auth", {}))
    return {"settings": settings, "guests": cfg.get("guests", {}), "auth": auth,
            "host_update": cfg.get("host_update", {}),
            "maintenance": cfg.get("maintenance", {})}


def save_config(cfg):
    _atomic_write_json(CONFIG_PATH, cfg)


def load_state():
    return _read_json(STATE_PATH, {})


def save_state(state):
    _atomic_write_json(STATE_PATH, state)


class PVE:
    """Minimal Proxmox REST client (read-only usage here) via an API token."""

    def __init__(self, settings):
        self.base = f"https://{settings['pve_host']}:{settings['pve_port']}/api2/json"
        self.verify = bool(settings.get("verify_tls", False))
        with open(TOKEN_PATH) as f:
            token = f.read().strip()
        self.headers = {"Authorization": f"PVEAPIToken={token}"}

    def _req(self, method, path, **kw):
        r = requests.request(method, self.base + path, headers=self.headers,
                             verify=self.verify, timeout=30, **kw)
        r.raise_for_status()
        return r.json().get("data") if r.text else None

    def resources(self):
        return self._req("GET", "/cluster/resources?type=vm") or []


def guest_index(pve, lxc_only=True):
    """Map vmid(str) -> {type, node, name, status}. Updates apply to LXC only."""
    idx = {}
    for r in pve.resources():
        t = r.get("type")
        if t not in ("lxc", "qemu"):
            continue
        if lxc_only and t != "lxc":
            continue
        idx[str(r["vmid"])] = {"type": t, "node": r["node"],
                               "name": r.get("name", ""), "status": r.get("status", "")}
    return idx


# ---- auth against the host (nothing stored; validated live) ----------------

def check_token(settings, token):
    url = f"https://{settings['pve_host']}:{settings['pve_port']}/api2/json/version"
    try:
        r = requests.get(url, headers={"Authorization": f"PVEAPIToken={token}"},
                         verify=bool(settings.get("verify_tls", False)), timeout=10)
    except requests.RequestException:
        return False
    return r.status_code == 200


def verify_credentials(settings, username, password):
    url = f"https://{settings['pve_host']}:{settings['pve_port']}/api2/json/access/ticket"
    try:
        r = requests.post(url, data={"username": username, "password": password},
                          verify=bool(settings.get("verify_tls", False)), timeout=15)
    except requests.RequestException:
        return False
    return r.status_code == 200 and bool((r.json() or {}).get("data", {}).get("ticket"))


def is_configured():
    cfg = load_config()
    host = cfg["settings"].get("pve_host", "")
    if not host or host == "CHANGE_ME":
        return False
    try:
        with open(TOKEN_PATH) as f:
            return bool(f.read().strip())
    except OSError:
        return False


# ---- schedule math (interval | calendar) -----------------------------------

def _parse_hhmm(s):
    h, m = str(s).split(":")
    return int(h), int(m)


def next_occurrence(g, now_ts):
    if g.get("mode") != "calendar":
        return None
    times, weekdays = g.get("times") or [], g.get("weekdays") or []
    if not times:
        return None
    now = dt.datetime.fromtimestamp(now_ts)
    best = None
    for day in range(0, 8):
        d = (now + dt.timedelta(days=day)).date()
        if weekdays and d.weekday() not in weekdays:
            continue
        for t in times:
            try:
                hh, mm = _parse_hhmm(t)
            except ValueError:
                continue
            cand = dt.datetime.combine(d, dt.time(hh, mm)).timestamp()
            if cand > now_ts and (best is None or cand < best):
                best = cand
    return int(best) if best else None


# First-run catch-up window for calendar mode. MUST exceed the host timer period
# (else a scheduled time can fall in the gap between this window and the next tick
# and never fire, leaving last_run at 0 forever). Timer runs every ~5 min.
CALENDAR_FIRST_GRACE = 1800  # 30 min


def is_due(g, last_run, now_ts):
    if g.get("mode") == "calendar":
        times, weekdays = g.get("times") or [], g.get("weekdays") or []
        if not times:
            return False
        window_start = last_run if last_run else now_ts - CALENDAR_FIRST_GRACE
        now = dt.datetime.fromtimestamp(now_ts)
        for day in range(-2, 1):
            d = (now + dt.timedelta(days=day)).date()
            if weekdays and d.weekday() not in weekdays:
                continue
            for t in times:
                try:
                    hh, mm = _parse_hhmm(t)
                except ValueError:
                    continue
                occ = dt.datetime.combine(d, dt.time(hh, mm)).timestamp()
                if window_start < occ <= now_ts:
                    return True
        return False
    interval = int(g.get("interval_minutes", 10080)) * 60
    return now_ts - last_run >= interval
