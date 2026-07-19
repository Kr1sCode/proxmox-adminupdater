#!/usr/bin/env python3
"""adminupdater web UI + JSON API. Served by gunicorn; put HTTPS in front (NPM).

Two audiences:
  * browser UI  -> session cookie, validated live against Proxmox credentials.
  * host executor -> static bearer token on /plan and /report only.
"""

import hmac
import os
import secrets
import time
from datetime import timedelta

from flask import (Flask, jsonify, redirect, request, send_from_directory,
                   session)

import adminupdater as up
import core

app = Flask(__name__, static_folder=None)
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

SECRET_PATH = os.environ.get("ADMINUPDATER_SECRET", "/etc/adminupdater/secret")
EXEC_TOKEN_PATH = os.environ.get("ADMINUPDATER_EXEC_TOKEN", "/etc/adminupdater/exec_token")


def _load_secret():
    try:
        with open(SECRET_PATH) as f:
            if (s := f.read().strip()):
                return s
    except OSError:
        pass
    s = secrets.token_hex(32)
    try:
        os.makedirs(os.path.dirname(SECRET_PATH), exist_ok=True)
        with open(SECRET_PATH, "w") as f:
            f.write(s)
        os.chmod(SECRET_PATH, 0o600)
    except OSError:
        pass
    return s


app.secret_key = _load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=False,
                  PERMANENT_SESSION_LIFETIME=timedelta(hours=12))

_FAILS, _MAX_FAILS, _WINDOW = {}, 6, 300


def _throttled(ip):
    now = time.time()
    _FAILS[ip] = [t for t in _FAILS.get(ip, []) if now - t < _WINDOW]
    return len(_FAILS[ip]) >= _MAX_FAILS


def _record_fail(ip):
    _FAILS.setdefault(ip, []).append(time.time())


def _exec_token():
    try:
        with open(EXEC_TOKEN_PATH) as f:
            return f.read().strip()
    except OSError:
        return None


def _bearer_ok(req):
    want = _exec_token()
    got = (req.headers.get("Authorization") or "").removeprefix("Bearer ").strip()
    return bool(want) and hmac.compare_digest(got, want)


@app.before_request
def _guard():
    p = request.path
    configured = core.is_configured()
    if p == "/setup" or p.startswith("/api/setup"):
        if configured and p == "/setup":
            return redirect("/")
        return None
    if not configured:
        return (jsonify({"error": "setup required"}), 503) if p.startswith("/api/") \
            else redirect("/setup")
    # host executor endpoints: bearer auth enforced in the handlers
    if p in ("/plan", "/report"):
        return None
    if p == "/login" or p.startswith("/api/login"):
        return None
    if session.get("user"):
        return None
    return (jsonify({"error": "unauthorized"}), 401) if p.startswith("/api/") \
        else redirect("/login")


# ---- setup / auth ----------------------------------------------------------

@app.route("/setup")
def setup_page():
    return send_from_directory(STATIC_DIR, "setup.html")


@app.route("/api/setup", methods=["GET", "POST"])
def api_setup():
    cfg = core.load_config()
    if request.method == "GET":
        host = cfg["settings"].get("pve_host", "")
        return jsonify({"configured": core.is_configured(),
                        "pve_host": "" if host == "CHANGE_ME" else host,
                        "pve_port": cfg["settings"].get("pve_port", 8006)})
    if core.is_configured():
        return jsonify({"error": "already configured"}), 409
    body = request.get_json(force=True) or {}
    host, token = str(body.get("pve_host", "")).strip(), str(body.get("token", "")).strip()
    port, verify = int(body.get("pve_port", 8006) or 8006), bool(body.get("verify_tls", False))
    if not host or not token:
        return jsonify({"error": "host and token are required"}), 400
    if not core.check_token({"pve_host": host, "pve_port": port, "verify_tls": verify}, token):
        return jsonify({"error": "token does not work with this host"}), 400
    cfg["settings"].update({"pve_host": host, "pve_port": port, "verify_tls": verify})
    core.save_config(cfg)
    with open(core.TOKEN_PATH, "w") as f:
        f.write(token)
    os.chmod(core.TOKEN_PATH, 0o600)
    return jsonify({"ok": True})


@app.route("/login")
def login_page():
    return send_from_directory(STATIC_DIR, "login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "?"
    if _throttled(ip):
        return jsonify({"error": "too many attempts, wait a few minutes"}), 429
    body = request.get_json(force=True) or {}
    user, pw = str(body.get("username", "")).strip(), str(body.get("password", ""))
    cfg = core.load_config()
    if user not in cfg["auth"].get("allowlist", ["root@pam"]):
        _record_fail(ip)
        return jsonify({"error": "user not allowed"}), 403
    if not core.verify_credentials(cfg["settings"], user, pw):
        _record_fail(ip)
        return jsonify({"error": "invalid credentials"}), 401
    session.permanent = True
    session["user"] = user
    return jsonify({"ok": True, "user": user})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/api/me")
def api_me():
    return jsonify({"user": session.get("user")})


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


# ---- browser UI: guests + settings ----------------------------------------

@app.route("/api/guests")
def api_guests():
    return jsonify(up.guest_view())


@app.route("/api/guests/<vmid>", methods=["POST"])
def api_guest_save(vmid):
    body = request.get_json(force=True) or {}
    cfg = core.load_config()
    g = dict(up.GUEST_DEFAULTS)
    g.update(cfg.get("guests", {}).get(str(vmid), {}))
    for k in up.GUEST_DEFAULTS:
        if k in body:
            g[k] = body[k]
    cfg.setdefault("guests", {})[str(vmid)] = g
    core.save_config(cfg)
    return jsonify({"ok": True, "config": g})


@app.route("/api/settings", methods=["POST"])
def api_settings():
    body = request.get_json(force=True) or {}
    cfg = core.load_config()
    for k in ("paused", "snapshot_prefix", "rollback_on_fail",
              "default_keep", "default_max_age_days"):
        if k in body:
            cfg["settings"][k] = body[k]
    core.save_config(cfg)
    return jsonify({"ok": True, "settings": cfg["settings"]})


@app.route("/api/log")
def api_log():
    try:
        with open(core.LOG_PATH) as f:
            return jsonify({"log": "".join(f.readlines()[-200:])})
    except OSError:
        return jsonify({"log": ""})


# ---- host executor: bearer-authed plan / report ---------------------------

@app.route("/plan")
def api_plan():
    if not _bearer_ok(request):
        return jsonify({"error": "unauthorized"}), 401
    import datetime as dt
    return jsonify({"generated_at": dt.datetime.utcnow().isoformat() + "Z",
                    "jobs": up.compute_plan()})


@app.route("/report", methods=["POST"])
def api_report():
    if not _bearer_ok(request):
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json(force=True, silent=True) or {}
    results = body.get("results", [])
    if not isinstance(results, list):
        return jsonify({"error": "results must be a list"}), 400
    return jsonify(up.record_report(results))


@app.route("/api/health")
def api_health():
    return jsonify({"ok": True})
