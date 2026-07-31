#!/usr/bin/env python3
"""proxmox-adminupdater host-side executor.

The ONLY component on the Proxmox host. Stateless and dumb: pulls a plan from the
adminupdater LXC, runs the right per-guest-type commands, posts results back.
All policy lives in the LXC EXCEPT the ctid whitelist, which is ALSO enforced
here -- a compromised LXC can at most request security-patch / app-update on a
ctid the host itself already allows, never host root and never a raw command.

Guests come in two flavours, each behind a small Driver with the same interface
(exec/snapshot/rollback/start/stop/detect_os/...): LXC via `pct`, QEMU VMs via
`qm` + the QEMU Guest Agent (works for both Linux and Windows guests). The host
resolves a ctid's REAL type itself (`pct status` then `qm status`) rather than
trusting a type claim from the plan -- the plan only ever carries ctid + an
action enum, exactly as before.

Runs as root (needs pct/qm). stdlib only -- PVE ships python3.
"""

import base64
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
        # Ceiling for the temporary app-update RAM boost. The panel picks the target,
        # the HOST caps it here — a compromised LXC can never set an absurd limit on a
        # whitelisted guest (defence in depth, same spirit as host_update).
        "ram_boost_max_mb": g.getint("ram_boost_max_mb", 8192),
        # Minimum free space (MB) required on the guest's system drive right
        # before an update runs -- a blunt but robust guard (no per-package
        # size prediction, which is fragile/locale-dependent across package
        # managers) against a full disk wedging the guest mid-install.
        "min_free_disk_mb": g.getint("min_free_disk_mb", 1024),
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


# Many community-scripts LXC templates print a colourful ANSI banner (app name,
# "Provided by", OS/hostname/IP) from /etc/profile.d/* on every LOGIN shell -- a
# `pct exec ... -- bash -lc "..."` triggers it same as an interactive `pct enter`
# would. The escape bytes don't render in a plain-text dialog/e-mail, they just
# show up as literal "[1m", "[33m" garbage. Strip them from anything a guest
# actually produced before it's stored/displayed anywhere.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b[()][A-Za-z0-9]")


def _strip_ansi(s):
    return _ANSI_RE.sub("", s) if s else s


def _sh(cmd, t=25):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=t).stdout
    except Exception:  # noqa: BLE001
        return ""


# ---- per-guest-type drivers --------------------------------------------------
# Same interface for LXC (pct) and QEMU (qm + QEMU Guest Agent), so do_job() and
# everything downstream of it (snapshot/rollback/reboot/health-check/app-update)
# doesn't need to know which one it's talking to.

class LxcDriver:
    kind = "lxc"

    def __init__(self, vmid):
        self.id = str(vmid)

    def running(self):
        return "running" in _sh(["pct", "status", self.id], 15)

    def exec(self, argv, timeout):
        rc, out = run(["pct", "exec", self.id, "--", *argv], timeout)
        return rc, _strip_ansi(out)

    def alive_probe(self):
        return self.exec(["true"], 30)[0] == 0

    def snapshot(self, name, description):
        return run(["pct", "snapshot", self.id, name, "--description", description], 300)

    def rollback(self, name, timeout):
        return run(["pct", "rollback", self.id, name], timeout)

    def listsnapshot(self):
        return run(["pct", "listsnapshot", self.id], 60)

    def delsnapshot(self, name):
        return run(["pct", "delsnapshot", self.id, name], 120)

    def start(self, timeout):
        return run(["pct", "start", self.id], timeout)

    def stop(self, timeout):
        return run(["pct", "stop", self.id], timeout)

    def reboot(self, timeout):
        return run(["pct", "reboot", self.id], timeout)

    def detect_os(self):
        _, out = self.exec(["cat", "/etc/os-release"], 30)
        for line in out.splitlines():
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"')
        return "unknown"

    def push_file(self, local_path, dest, perms="700"):
        return run(["pct", "push", self.id, local_path, dest, "--perms", perms], 60)


class QemuDriver:
    kind = "qemu"

    def __init__(self, vmid):
        self.id = str(vmid)

    def running(self):
        return "status: running" in _sh(["qm", "status", self.id], 15)

    def agent_ready(self, timeout=10):
        return run(["qm", "agent", self.id, "ping"], timeout)[0] == 0

    def alive_probe(self):
        return self.agent_ready()

    def exec(self, argv, timeout):
        # `qm guest exec` is synchronous by default (--synchronous 1): it blocks and
        # returns the guest's exit code + output as JSON in one call. Give the
        # subprocess itself a little headroom over --timeout so qm gets to return
        # its own timeout message instead of us hard-killing it mid-response.
        rc, out = run(["qm", "guest", "exec", self.id, "--timeout", str(timeout),
                       "--", *argv], timeout + 30)
        if rc != 0:
            return 1, (out.strip() or f"qm guest exec nieudany (rc={rc})")
        try:
            data = json.loads(out)
        except ValueError:
            return 1, out
        if not data.get("exited"):
            return 124, "guest agent nie zwrócił wyniku w czasie (timeout)"
        out_data = data.get("out-data") or ""
        err_data = data.get("err-data") or ""
        exitcode = int(data.get("exitcode", 1) or 0)
        if err_data.startswith("#< CLIXML") and exitcode == 0:
            err_data = ""   # PowerShell progress-stream noise on success, not a real error
        return exitcode, _strip_ansi(out_data + err_data)

    def snapshot(self, name, description):
        # --vmstate 0: disk-only, no RAM dump -- fast, matches pct snapshot's semantics
        # (LXC snapshots never carry memory state either).
        return run(["qm", "snapshot", self.id, name, "--vmstate", "0",
                    "--description", description], 300)

    def rollback(self, name, timeout):
        return run(["qm", "rollback", self.id, name], timeout)

    def listsnapshot(self):
        return run(["qm", "listsnapshot", self.id], 60)

    def delsnapshot(self, name):
        return run(["qm", "delsnapshot", self.id, name], 120)

    def start(self, timeout):
        return run(["qm", "start", self.id], timeout)

    def stop(self, timeout):
        return run(["qm", "stop", self.id], timeout)

    def reboot(self, timeout):
        return run(["qm", "reboot", self.id], timeout)

    def detect_os(self):
        rc, out = run(["qm", "guest", "cmd", self.id, "get-osinfo"], 15)
        if rc != 0:
            return "unknown"
        try:
            data = json.loads(out)
        except ValueError:
            return "unknown"
        osid = str(data.get("id") or "").strip().lower()
        if osid in ("mswindows", "windows"):
            return "windows"
        return osid or "unknown"


def resolve_driver(ctid):
    """Ground truth for what a ctid actually is -- probed on the host, never taken
    on faith from the plan. A guest that answers neither pct nor qm is rejected."""
    if run(["pct", "status", str(ctid)], 15)[0] == 0:
        return LxcDriver(ctid)
    if run(["qm", "status", str(ctid)], 15)[0] == 0:
        return QemuDriver(ctid)
    return None


def _win_encoded(script):
    """Windows guest agent has no file-write in the `qm` CLI, so built-in scripts
    and recipes alike are handed over as a single -EncodedCommand argument (the
    standard way to run ad-hoc PowerShell without touching disk)."""
    b64 = base64.b64encode(script.encode("utf-16-le")).decode()
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
            "Bypass", "-EncodedCommand", b64]


# ---- built-in Windows Update (COM API, no external module) -------------------
# Microsoft's published update-classification GUIDs: Security Updates + Critical
# Updates -- the two classifications that matter for "security-only" on a server
# that isn't meant to chase every feature/driver update. See
# https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-security
_WIN_SECURITY_CRITERIA = (
    "IsInstalled=0 and IsHidden=0 and "
    "(CategoryIDs contains '0fa1201d-4330-4fa8-8ae9-b877473b6441' or "
    "CategoryIDs contains 'e6cf1350-c01b-414d-a61f-263d14d133b4')"
)
_WIN_ALL_CRITERIA = "IsInstalled=0 and IsHidden=0"


_WIN_UPDATE_PS_TMPL = r"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("__CRITERIA__")
    if ($result.Updates.Count -eq 0) {
        Write-Output "brak dostepnych aktualizacji / no updates available"
        exit 0
    }
    $toDownload = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $result.Updates) { [void]$toDownload.Add($u) }
    $downloader = $session.CreateUpdateDownloader()
    $downloader.Updates = $toDownload
    $dlResult = $downloader.Download()
    Write-Output "Download ResultCode: $($dlResult.ResultCode)"
    $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $result.Updates) { if ($u.IsDownloaded) { [void]$toInstall.Add($u) } }
    if ($toInstall.Count -eq 0) {
        Write-Output "nic nie pobrano poprawnie / nothing downloaded successfully"
        exit 1
    }
    $installer = $session.CreateUpdateInstaller()
    $installer.Updates = $toInstall
    $instResult = $installer.Install()
    Write-Output "Install ResultCode: $($instResult.ResultCode) RebootRequired: $($instResult.RebootRequired)"
    for ($i = 0; $i -lt $toInstall.Count; $i++) {
        $u = $toInstall.Item($i)
        $r = $instResult.GetUpdateResult($i)
        Write-Output ("{0} -> resultCode={1} hresult={2}" -f $u.Title, $r.ResultCode, $r.HResult)
    }
    # ResultCode: 2=Succeeded, 3=SucceededWithErrors, 4=Failed, 5=Aborted
    if ($instResult.ResultCode -eq 2 -or $instResult.ResultCode -eq 3) { exit 0 } else { exit 1 }
} catch {
    Write-Output "BLAD/ERROR: $($_.Exception.Message)"
    exit 1
}
"""


def _win_update_ps(scope):
    """scope: 'security' -> Security+Critical classifications only, else every
    applicable, non-hidden update (today's default behaviour)."""
    criteria = _WIN_SECURITY_CRITERIA if scope == "security" else _WIN_ALL_CRITERIA
    return _WIN_UPDATE_PS_TMPL.replace("__CRITERIA__", criteria)


WIN_REBOOT_CHECK_PS = (
    "$a = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired'; "
    "$b = Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending'; "
    "if ($a -or $b) { exit 0 } else { exit 1 }"
)

WIN_HEALTH_AUTO_PS = (
    "$ProgressPreference='SilentlyContinue'; "
    "$s = Get-Service RpcSs, Winmgmt -ErrorAction SilentlyContinue; "
    "if (-not $s -or ($s | Where-Object Status -ne 'Running')) { exit 1 } else { exit 0 }"
)

# ---- read-only update check: list what's pending, install nothing ------------
WIN_CHECK_PS = r"""
$ProgressPreference = 'SilentlyContinue'
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
    if ($result.Updates.Count -eq 0) { Write-Output "OK: brak zaleglych aktualizacji" }
    else { foreach ($u in $result.Updates) { Write-Output $u.Title } }
} catch {
    Write-Output ("BLAD: " + $_.Exception.Message)
}
exit 0
"""


def build_check_updates(d):
    """Read-only probe: what's available but NOT installed. Never downloads or
    installs anything -- safe to run on demand from the panel without touching
    the guest. Each branch normalizes to exit 0 (the text itself carries the
    result, including a distinguishable 'OK:' line when nothing is pending).
    A plain (non-login) shell -- package managers don't need /etc/profile.d, and
    a LOGIN shell is exactly what triggers a community-scripts container's
    colourful "Provided by / OS / Hostname / IP" welcome banner ahead of the
    real answer (same thing `pct enter` shows); -c skips all of that noise."""
    if d in ("debian", "ubuntu"):
        return ["bash", "-c",
                "apt-get update -qq >/dev/null 2>&1; "
                "n=$(apt list --upgradable 2>/dev/null | tail -n +2); "
                "if [ -z \"$n\" ]; then echo 'OK: brak zaleglych aktualizacji'; else echo \"$n\"; fi"]
    if d == "alpine":
        return ["ash", "-c",
                "apk update -q >/dev/null 2>&1; n=$(apk list -u 2>/dev/null); "
                "if [ -z \"$n\" ]; then echo 'OK: brak zaleglych aktualizacji'; else echo \"$n\"; fi"]
    if d in ("arch", "archarm"):
        return ["bash", "-c",
                "pacman -Sy --noconfirm -q >/dev/null 2>&1; n=$(pacman -Qu 2>/dev/null); "
                "if [ -z \"$n\" ]; then echo 'OK: brak zaleglych aktualizacji'; else echo \"$n\"; fi"]
    if d in ("fedora", "rhel", "centos", "rocky", "almalinux"):
        return ["bash", "-c",
                "n=$( (dnf check-update -q 2>/dev/null || yum check-update -q 2>/dev/null) "
                "| grep -v '^$' | grep -vi '^Last metadata'); "
                "if [ -z \"$n\" ]; then echo 'OK: brak zaleglych aktualizacji'; else echo \"$n\"; fi"]
    if d == "windows":
        return _win_encoded(WIN_CHECK_PS)
    return None


def check_free_disk_mb(driver, distro):
    """Free space (MB) on the guest's system drive. Deliberately a blunt
    free-space floor rather than a per-package size prediction -- parsing
    apt/dnf/pacman "will use N MB" output is locale-dependent and fragile
    across package managers; a plain threshold is robust everywhere and is
    what actually prevents a full disk from wedging the guest mid-install.
    Returns (free_mb:int|None, error:str|None) -- exactly one is not-None."""
    if distro == "windows":
        cmd = _win_encoded(
            "$ProgressPreference='SilentlyContinue'; "
            "$d = (Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\").FreeSpace; "
            "if ($null -eq $d) { exit 1 }; Write-Output ([math]::Floor($d/1MB))"
        )
    else:
        # df -P (POSIX format, avoids long-device-name line wrapping), -k (1K
        # blocks); column 4 is "Available" on the data row. Works unmodified on
        # any coreutils/busybox df, so no per-distro branching needed here.
        cmd = ["sh", "-c", "df -Pk / | awk 'NR==2{print int($4/1024)}'"]
    rc, out = driver.exec(cmd, 30)
    lines = [ln.strip() for ln in out.strip().splitlines() if ln.strip()]
    if rc != 0 or not lines or not lines[-1].isdigit():
        return None, f"nie udało się odczytać wolnego miejsca (rc={rc}): {out[-200:]}"
    return int(lines[-1]), None


def detect_distro(driver):
    return driver.detect_os()


def build_security_patch(d, win_scope="all"):
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
    if d in ("fedora", "rhel", "centos", "rocky", "almalinux"):
        return ["bash", "-lc", "dnf -y upgrade || yum -y update"]
    if d == "windows":
        return _win_encoded(_win_update_ps(win_scope))
    return None


def _safe_name(app):
    return bool(app) and all(c.isalnum() or c in "-._" for c in app) and app[0].isalnum()


def build_app_update(cfg, driver, app, distro="debian"):
    # "auto" = community-scripts behaviour: run the container's own /usr/bin/update
    # helper. LXC-only -- there is no such convention for a VM.
    if app == "auto":
        if driver.kind != "lxc":
            return None
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
    ext = ".ps1" if distro == "windows" else ".sh"
    recipe = os.path.join(cfg["recipes_dir"], f"{app}{ext}")
    if not os.path.isfile(recipe):
        return None
    if driver.kind == "lxc":
        dest = "/tmp/.adminupdater-recipe.sh"
        rc, _ = driver.push_file(recipe, dest, "700")
        if rc != 0:
            return None
        return ["bash", "-lc", f"{dest}; rc=$?; rm -f {dest}; exit $rc"]
    # QEMU: `qm` has no file-write CLI -> embed the recipe content directly, same
    # trick as the built-in Windows Update script (base64 argv, nothing touches disk
    # on the host side, and the guest never has a dangling script file to clean up).
    try:
        content = open(recipe, encoding="utf-8").read()
    except OSError:
        return None
    if distro == "windows":
        return _win_encoded(content)
    b64 = base64.b64encode(content.encode()).decode()
    return ["bash", "-lc", f"echo {b64} | base64 -d | bash -s --; exit $?"]


def _ct_memory(ctid):
    """Current memory limit (MB) of an LXC container, read from `pct config`. None on
    error. LXC-only -- there's no equivalent RAM-boost mechanism wired up for VMs yet."""
    rc, out = run(["pct", "config", str(ctid)], 30)
    if rc != 0:
        return None
    m = re.search(r"^memory:\s*(\d+)", out, re.M)
    return int(m.group(1)) if m else None


def maybe_ram_boost(cfg, driver, job, actions):
    """Temporarily raise an LXC's RAM for the memory-heavy app-update BUILD step
    (npm install / from-source compiles OOM at tight limits — that's rc=137, and some
    community-scripts updaters self-abort with rc=113 when under-provisioned).

    Panel-gated per job (ram_boost.enabled); the target floor comes from the panel but
    the HOST clamps it to ram_boost_max_mb. Only ever RAISES — never lowers a guest that
    is already generous. Returns {"from": MB, "to": MB} when a boost was applied (so the
    report/e-mail can show it), else None. The caller restores in a finally, whatever
    happens — a crash, a rollback or a normal finish all put the RAM back."""
    if driver.kind != "lxc":
        return None   # no analogous mechanism wired up for QEMU yet
    rb = job.get("ram_boost") or {}
    if not rb.get("enabled") or "app-update" not in actions:
        return None
    cur = _ct_memory(driver.id)
    if cur is None:
        return None
    cap = int(cfg.get("ram_boost_max_mb", 8192))
    target = min(max(int(rb.get("mb") or 0), cur), cap)   # raise toward the floor, never past the cap
    if target <= cur:
        return None                                       # already has enough — nothing to do
    rc, _ = run(["pct", "set", driver.id, "-memory", str(target)], 60)
    return {"from": cur, "to": target} if rc == 0 else None


def restore_ram(ctid, mb):
    """Put a boosted container's RAM back. Idempotent — safe even if a rollback already
    reverted the config (snapshot predates the boost), since we just re-assert the original."""
    run(["pct", "set", str(ctid), "-memory", str(int(mb))], 60)


def start_and_wait(driver, timeout, wait=120):
    """Start a stopped guest and wait until it actually accepts commands, so the
    update doesn't fire into a half-booted guest. Returns (ok, log)."""
    t0 = time.time()
    rc, out = driver.start(timeout)
    if rc != 0:
        return False, "start nieudany: " + out[-500:]
    deadline = time.time() + wait
    while time.time() < deadline:
        if driver.running() and driver.alive_probe():
            return True, f"maszyna wystartowana na czas aktualizacji ({int(time.time() - t0)}s)"
        time.sleep(3)
    return False, f"maszyna nie wstała w {wait}s"


def snapshot(driver, prefix):
    name = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}"
    rc, out = driver.snapshot(name, "proxmox-adminupdater pre-update")
    return (name if rc == 0 else None), out


def rollback(driver, snap, timeout):
    rc, _ = driver.rollback(snap, timeout)
    return rc == 0


def reboot_and_verify(driver, timeout, wait=150):
    """Reboot a guest and confirm it comes back and is responsive. Returns
    (ok, log). Used after an update when the guest opted into auto-reboot AND the
    update left a reboot-required marker. If it never returns, the caller rolls
    back — so a wedged reboot is caught, not left broken."""
    t0 = time.time()
    rc, _ = driver.reboot(timeout)
    if rc != 0:  # some setups need an explicit stop/start
        driver.stop(timeout)
        driver.start(timeout)
    deadline = time.time() + wait
    while time.time() < deadline:
        if driver.running() and driver.alive_probe():
            return True, f"restart OK, wrócił po {int(time.time() - t0)}s"
        time.sleep(3)
    return False, f"maszyna nie wróciła po restarcie w {wait}s"


def reboot_required(driver, distro):
    """rc==0 means 'a reboot is pending', matching the Linux /var/run/reboot-required
    convention. Windows has no such file -- read the registry markers WU/CBS set."""
    if distro == "windows":
        rc, _ = driver.exec(_win_encoded(WIN_REBOOT_CHECK_PS), 30)
        return rc
    rc, _ = driver.exec(["test", "-e", "/var/run/reboot-required"], 30)
    return rc


def _snap_epoch(name):
    m = re.search(r"_(\d{8})_(\d{6})$", name)
    if not m:
        return 0
    try:
        return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
    except ValueError:
        return 0


def prune_snapshots(driver, prefix, keep, max_age_days):
    """Delete old managed snapshots. ONLY names matching ^<prefix>_\\d{8}_\\d{6}$
    are ever touched (re-checked right before each delete), so manual snapshots
    and autosnap's auto_* are physically incapable of matching. Time is read
    from the name itself, so no date parsing of `pct/qm listsnapshot` is needed."""
    keep, max_age_days = int(keep or 0), int(max_age_days or 0)
    if keep <= 0 and max_age_days <= 0:
        return []
    rx = re.compile(r"^" + re.escape(prefix) + r"_\d{8}_\d{6}$")
    rc, out = driver.listsnapshot()
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
        rc, _ = driver.delsnapshot(n)
        if rc == 0:
            deleted.append(n)
    return deleted


def purge_managed(driver, prefixes):
    """Delete ALL managed snapshots for the given prefixes. Same strict regex as
    prune_snapshots -- only ^<prefix>_\\d{8}_\\d{6}$ can ever match, re-checked
    right before each delete, so manual snapshots are physically safe."""
    rc, out = driver.listsnapshot()
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
            drc, _ = driver.delsnapshot(n)
            if drc == 0:
                deleted.append(n)
    return deleted, ""


def build_health_check(hc, distro=None):
    """Structured post-update probe -> a command, built HOST-side from a
    type+arg. No raw command string ever crosses from the LXC."""
    t = (hc or {}).get("type", "none")
    arg = str((hc or {}).get("arg", "")).strip()
    if t == "none":
        return None
    if t == "auto":
        if distro == "windows":
            return _win_encoded(WIN_HEALTH_AUTO_PS)
        # Universal, no-arg liveness probe that fits ANY Linux guest: if it runs
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
        if distro == "windows":
            ps = ("$ProgressPreference='SilentlyContinue'; try { "
                  f"$r = Invoke-WebRequest -UseBasicParsing -Uri '{arg}' -TimeoutSec 10; "
                  "if ($r.StatusCode -ge 200 -and $r.StatusCode -lt 400) { exit 0 } else { exit 1 } "
                  "} catch { exit 1 }")
            return _win_encoded(ps)
        return ["bash", "-lc", f"curl -fsS -o /dev/null --max-time 10 -- {shlex.quote(arg)}"]
    return None


def _rollback_verdict(snap, job, driver, timeout):
    if snap and job.get("rollback_on_fail"):
        return "rolled-back" if rollback(driver, snap, timeout) else "failed-rollback"
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

    driver = resolve_driver(ctid)
    if driver is None:
        return {**res, "status": "error",
                "steps": [{"action": kind, "status": "error", "rc": -1,
                           "log": "nieznany gość — ani `pct status`, ani `qm status` nie odpowiada"}]}
    res["gtype"] = driver.kind

    # ===== ad-hoc purge: drop ALL managed snapshots (never touches manual ones) =====
    if kind == "purge":
        deleted, err = purge_managed(driver, job.get("prefixes") or [])
        res["pruned"] = deleted
        if err:
            res.update(status="error",
                       steps=[{"action": "purge", "status": "error", "rc": -1, "log": err}])
            return res
        res["steps"].append({"action": "purge", "status": "ok", "rc": 0,
                             "log": f"usunięto {len(deleted)}: " + (", ".join(deleted) or "—")})
        res["status"] = "ok"
        return res

    # ===== ad-hoc check: read-only list of pending updates, installs nothing,
    # touches no snapshot -- safe to run anytime, including on the sole DC. =====
    if kind == "check":
        if not driver.running():
            res.update(status="skipped",
                       steps=[{"action": "check", "status": "skipped", "rc": 0,
                               "log": "maszyna wyłączona — pomijam"}])
            return res
        if driver.kind == "qemu" and not driver.agent_ready():
            res.update(status="error",
                       steps=[{"action": "check", "status": "error", "rc": -1,
                               "log": "brak odpowiedzi QEMU Guest Agenta"}])
            return res
        distro = detect_distro(driver)
        res["distro"] = distro
        cmd = build_check_updates(distro)
        if cmd is None:
            res.update(status="skipped",
                       steps=[{"action": "check", "status": "skipped", "rc": 0,
                               "log": f"brak obsługi dla systemu ({distro})"}])
            return res
        rc, out = driver.exec(cmd, cfg["timeout"])
        text = out.strip()
        res["pending"] = [ln for ln in text.splitlines() if ln.strip()] if text else []
        res["steps"].append({"action": "check", "status": ("ok" if rc == 0 else "failed"),
                             "rc": rc, "log": text[-4000:]})
        res["status"] = "ok" if rc == 0 else "error"
        return res

    # ===== independent scheduled snapshot job (autosnap-style) =====
    if kind == "snapshot":
        if job.get("dryrun"):
            name = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}"
            res.update(snapshot=name, status="ok",
                       steps=[{"action": "snapshot", "status": "dryrun", "rc": 0,
                               "log": f"[DRY-RUN] utworzyłbym {name}"}])
            return res
        snap, snaplog = snapshot(driver, prefix)
        res["snapshot"] = snap
        if snap is None:
            res.update(status="error",
                       steps=[{"action": "snapshot", "status": "error", "rc": -1,
                               "log": "snapshot nieudany: " + snaplog[-500:]}])
            return res
        res["steps"].append({"action": "snapshot", "status": "ok", "rc": 0, "log": snap})
        res["pruned"] = prune_snapshots(driver, prefix, job.get("keep", 0), job.get("max_age_days", 0))
        res["status"] = "ok"
        return res

    # ===== update job =====
    actions = job.get("actions") or ([job["action"]] if job.get("action") else [])

    # 0) a POWERED-OFF guest: nothing can be updated inside it. Per the guest's
    # setting either leave it alone, or start it for the update — and then put it back
    # the way we found it (start_stop) or leave it running (start_keep).
    stop_after = False
    if not driver.running():
        mode = job.get("offline_mode", "skip")
        if mode not in ("start_stop", "start_keep"):
            res.update(status="skipped",
                       steps=[{"action": "power", "status": "skipped", "rc": 0,
                               "log": "maszyna wyłączona — pomijam (ustawienie: nie włączaj)"}])
            return res
        ok, plog = start_and_wait(driver, cfg["timeout"])
        res["steps"].append({"action": "power-on", "status": ("ok" if ok else "failed"),
                             "rc": 0 if ok else -1, "log": plog})
        if not ok:
            res["status"] = "error"
            return res
        stop_after = mode == "start_stop"

    # 1) ONE snapshot up front — the rollback point for every step below.
    snap = None
    if job.get("pre_snapshot", True):
        snap, snaplog = snapshot(driver, prefix)
        res["snapshot"] = snap
        if snap is None:
            res.update(status="error",
                       steps=[{"action": "snapshot", "status": "error", "rc": -1,
                               "log": "snapshot nieudany: " + snaplog[-500:]}])
            return res

    # 1b) retention on preupd_ (fresh one protected by keep>=1 / age 0)
    res["pruned"] = prune_snapshots(driver, prefix, job.get("keep", 0), job.get("max_age_days", 0))

    # 1c) QEMU-only preflight: there is no `pct exec` equivalent without a live guest
    # agent, so fail fast with a clear reason instead of every step below timing out.
    if driver.kind == "qemu" and not driver.agent_ready():
        res["steps"].append({"action": "agent-check", "status": "failed", "rc": -1,
                             "log": "brak odpowiedzi QEMU Guest Agenta — zainstaluj/uruchom agenta w "
                                    "gościu i włącz „agent: 1” w konfiguracji VM / no response from the "
                                    "QEMU Guest Agent — install and start it in the guest and enable "
                                    "\u201eagent: 1\u201d on the VM"})
        res["status"] = _rollback_verdict(snap, job, driver, cfg["timeout"])
        return res

    # 2) detect the guest OS ONCE (also surfaced to the panel via the report)
    distro = detect_distro(driver)
    res["distro"] = distro

    # 2a) disk-space preflight -- refuse to start an install that could wedge the
    # guest mid-way through (full disk during apt/dnf/Windows Update is a classic
    # way to leave a guest half-patched and broken). A probe failure does NOT
    # block the update (fail-open: an unrelated df/CIM hiccup shouldn't hold a
    # guest back from real patches -- the pre-update snapshot is still the safety
    # net for a genuine mid-update failure).
    min_free = int(cfg.get("min_free_disk_mb", 1024))
    free_mb, disk_err = check_free_disk_mb(driver, distro)
    if disk_err:
        res["steps"].append({"action": "disk-space", "status": "skipped", "rc": 0,
                             "log": f"sonda miejsca nieudana, kontynuuję mimo to: {disk_err}"})
    elif free_mb < min_free:
        res["steps"].append({"action": "disk-space", "status": "failed", "rc": -1,
                             "log": f"za mało wolnego miejsca: {free_mb} MB < wymagane {min_free} MB — "
                                    f"aktualizacja WSTRZYMANA (low free disk space: {free_mb} MB < "
                                    f"required {min_free} MB — update HELD)"})
        res["status"] = "low-disk"
        res["disk_free_mb"] = free_mb
        res["disk_min_mb"] = min_free
        return res
    else:
        res["steps"].append({"action": "disk-space", "status": "ok", "rc": 0,
                             "log": f"wolne miejsce: {free_mb} MB (próg {min_free} MB)"})

    # 2b) optional temporary RAM boost for the memory-heavy app-update build (LXC only,
    # see maybe_ram_boost). Applied AFTER the snapshot (so a rollback reverts to the
    # original size) and restored in the finally below no matter how the job exits.
    boost = maybe_ram_boost(cfg, driver, job, actions)
    if boost:
        res["ram_boost"] = boost
        res["steps"].append({"action": "ram-boost", "status": "ok", "rc": 0,
                             "log": f"RAM {boost['from']}→{boost['to']} MB na czas aktualizacji"})

    try:
        # 3) run each action in order under that one snapshot
        overall = "ok"
        for action in actions:
            step = {"action": action}
            if action == "security-patch":
                cmd = build_security_patch(distro, job.get("win_update_scope", "all"))
            elif action == "app-update":
                cmd = build_app_update(cfg, driver, str(job.get("app", "")), distro)
            else:
                cmd = None
            if cmd is None:
                res["steps"].append({**step, "status": "skipped", "rc": 0,
                                     "log": f"brak obsługi ({distro}) / recepty"})
                continue
            rc, out = driver.exec(cmd, cfg["timeout"])
            res["steps"].append({**step, "status": ("ok" if rc == 0 else "failed"),
                                 "rc": rc, "log": out[-2000:]})
            if rc != 0:
                res["status"] = _rollback_verdict(snap, job, driver, cfg["timeout"])
                return res  # stop the chain; the snapshot is the safety net

        # 4) optional post-update reboot — the guest has to opt in, and then either the
        # update left a reboot-required marker (community-scripts convention on Linux,
        # the WU/CBS registry keys on Windows) or the guest is set to "always" (rare on
        # LXC — no kernel of its own). Verify the guest comes back; if not, roll back.
        if job.get("auto_reboot") and overall == "ok":
            if job.get("reboot_mode") == "always":
                rc = 0
            else:
                rc = reboot_required(driver, distro)
            if rc == 0:
                ok, rlog = reboot_and_verify(driver, cfg["timeout"])
                res["steps"].append({"action": "reboot", "status": ("ok" if ok else "failed"),
                                     "rc": 0 if ok else -1, "log": rlog})
                if not ok:
                    res["status"] = _rollback_verdict(snap, job, driver, cfg["timeout"])
                    return res

        # 5) post-update health-check — verify the guest actually works. A failing
        # probe fails the run (and rolls back) even though the update step returned 0.
        hcmd = build_health_check(job.get("health_check"), distro)
        if hcmd:
            rc, out = driver.exec(hcmd, cfg["timeout"])
            res["steps"].append({"action": "health-check",
                                 "status": ("ok" if rc == 0 else "failed"),
                                 "rc": rc, "log": out[-2000:]})
            if rc != 0:
                overall = _rollback_verdict(snap, job, driver, cfg["timeout"])

        # 6) post-update verification -- did it actually finish, not just "did the
        # guest come back"? Re-runs the SAME read-only probe as the panel's "check"
        # button (nothing installed, nothing rolled back on its own result -- purely
        # informational, reported alongside health-check). Only on a run that's still
        # "ok": a rolled-back guest is back at its pre-update state, so re-checking it
        # would just repeat the original pending list, telling nobody anything new.
        if overall == "ok":
            ccmd = build_check_updates(distro)
            if ccmd:
                rc, out = driver.exec(ccmd, cfg["timeout"])
                text = out.strip()
                pending = [ln for ln in text.splitlines() if ln.strip()] if text else []
                clean = (not pending) or (len(pending) == 1 and pending[0].startswith("OK:"))
                res["post_pending"] = [] if clean else pending
                if rc == 0:
                    log = "brak zaległych aktualizacji / no updates left pending" if clean else \
                          f"nadal oczekuje {len(pending)} / {len(pending)} still pending: " + "; ".join(pending[:10])
                    res["steps"].append({"action": "post-check", "status": "ok", "rc": 0, "log": log})
                else:
                    # a failed probe is noise, not news -- never touches overall/rollback
                    res["steps"].append({"action": "post-check", "status": "skipped", "rc": rc,
                                         "log": "sonda nieudana, pomijam / probe failed, skipping"})

        res["status"] = overall
        return res
    finally:
        if boost:
            restore_ram(ctid, boost["from"])
        # we powered it on only for this run — shut it back down however the job ended
        # (a rollback may already have stopped it; stopping an already-stopped guest is
        # a no-op either way).
        if stop_after:
            rc, out = driver.stop(cfg["timeout"]) if driver.running() else (0, "")
            res["steps"].append({"action": "power-off", "status": ("ok" if rc == 0 else "failed"),
                                 "rc": rc, "log": ("maszyna wyłączona po aktualizacji"
                                                   if rc == 0 else out[-500:])})


GOOD = ("ok", "skipped", "dryrun")


def _color(s):
    return {"ok": "#16a34a", "dryrun": "#0891b2", "skipped": "#64748b",
            "low-disk": "#d97706"}.get(s, "#dc2626")


def rc_hint(rc):
    """Plain-language reason for a non-zero exit code, in Polish AND English — so a bare
    `rc=137` in the mail actually tells you what to DO about it. Returns (pl, en) or None
    for rc==0 / unknown. Covers the ones that actually bite an unattended app-update:
    OOM (137), community-scripts under-provisioned self-abort (113), timeout, apt errors."""
    try:
        rc = int(rc)
    except (TypeError, ValueError):
        return None
    if rc == 0:
        return None
    table = {
        137: ("pamięć wyczerpana — proces zabity przez OOM. Zwiększ przydział RAM kontenera, "
              "albo włącz „tymczasowe zwiększanie RAM na czas aktualizacji” w ustawieniach.",
              "out of memory — process OOM-killed. Increase the container's RAM, or enable "
              "“temporary RAM boost during updates” in settings."),
        113: ("kontener nie spełnia wymagań aktualizacji (za mało RAM/CPU) i aktualizator sam "
              "przerwał pracę. Zwiększ zasoby kontenera (RAM/rdzenie).",
              "container is under-provisioned for the update (too little RAM/CPU) and the "
              "updater aborted itself. Raise the container's resources (RAM/cores)."),
        124: ("przekroczono limit czasu — aktualizacja trwała za długo i została przerwana.",
              "timed out — the update ran too long and was stopped."),
        100: ("błąd menedżera pakietów (apt/dpkg) — sprawdź źródła pakietów i blokady dpkg.",
              "package-manager error (apt/dpkg) — check the package sources and dpkg locks."),
        126: ("polecenia nie można było wykonać (uprawnienia).",
              "command could not be executed (permissions)."),
        127: ("nie znaleziono polecenia w kontenerze.",
              "command not found in the container."),
        1:   ("ogólny błąd aktualizacji — szczegóły w logu poniżej.",
              "generic update error — see the log below."),
        -1:  ("odrzucone/przerwane przez adminupdater (whitelist, snapshot lub błąd wewnętrzny).",
              "rejected/aborted by adminupdater (whitelist, snapshot, or internal error)."),
    }
    if rc in table:
        return table[rc]
    if 129 <= rc <= 165:                              # 128 + POSIX signal
        sig = rc - 128
        names = {2: "SIGINT", 9: "SIGKILL", 11: "SIGSEGV", 15: "SIGTERM"}
        nm = names.get(sig, f"sygnał {sig}")
        if sig == 9:  # SIGKILL is almost always the OOM killer for a build step
            return ("proces zabity (SIGKILL) — najczęściej brak pamięci. Zwiększ RAM kontenera.",
                    "process killed (SIGKILL) — usually out of memory. Increase the container's RAM.")
        return (f"proces zakończony sygnałem {sig} ({nm}).",
                f"process terminated by signal {sig} ({nm}).")
    return None


def build_email_html(results, host):
    ok = sum(1 for r in results if r["status"] == "ok")
    bad = [r for r in results if r["status"] not in GOOD]
    when = datetime.now().strftime("%Y-%m-%d %H:%M")
    cards = []
    for r in results:
        col = _color(r["status"])
        rows = []
        for s in r.get("steps", []):
            rows.append(
                f"<tr><td style='padding:2px 10px;color:#475569'>{s.get('action')}</td>"
                f"<td style='padding:2px 10px;color:{_color(s.get('status'))};font-weight:600'>{s.get('status')}</td>"
                f"<td style='padding:2px 10px;color:#94a3b8'>rc={s.get('rc')}</td></tr>")
            hint = rc_hint(s.get("rc")) if s.get("status") not in GOOD else None
            if hint:      # decode the exit code right under the step that produced it
                rows.append(
                    "<tr><td colspan='3' style='padding:0 10px 8px;color:#b45309;"
                    "font-size:12px;line-height:1.5'>"
                    f"⚠ {hint[0]}<br><span style='color:#94a3b8'>{hint[1]}</span></td></tr>")
        steps = "".join(rows)
        pruned = r.get("pruned") or []
        prune = f" · pruned {len(pruned)}" if pruned else ""
        rb = r.get("ram_boost")
        rb_html = (f"<div style='color:#0891b2'>RAM tymczasowo {rb['from']}→{rb['to']} MB "
                   f"na czas aktualizacji / temporary RAM boost</div>") if rb else ""
        gtype = r.get("gtype")
        kind_label = ("VM" if gtype == "qemu" else "CT") if gtype else "CT"
        label = "PVE host" if r.get("kind") == "host-update" else f"{kind_label} {r.get('ctid')}"
        cards.append(
            f"<div style='border:1px solid #e2e8f0;border-radius:10px;margin:10px 0;overflow:hidden'>"
            f"<div style='background:{col};color:#fff;padding:8px 12px;font-weight:700'>"
            f"{label} · {r.get('kind', 'update')} · {str(r['status']).upper()}</div>"
            f"<div style='padding:8px 12px;font-size:13px;color:#334155'>"
            f"<div>snapshot: <code>{r.get('snapshot') or '—'}</code>{prune}</div>"
            f"{rb_html}"
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
        gtype = r.get("gtype")
        kind_label = ("VM" if gtype == "qemu" else "CT") if gtype else "CT"
        label = "PVE host" if r.get("kind") == "host-update" else f"{kind_label} {r.get('ctid')}"
        lines.append(f"{label} · {r.get('kind', 'update')} · {str(r['status']).upper()}")
        if r.get("snapshot"):
            lines.append(f"  snapshot: {r['snapshot']}")
        rb = r.get("ram_boost")
        if rb:
            lines.append(f"  RAM: {rb['from']}->{rb['to']} MB (tymczasowo / temporary)")
        for s in r.get("steps", []):
            lines.append(f"  - {s.get('action')}: {s.get('status')} (rc={s.get('rc')})")
            hint = rc_hint(s.get("rc")) if s.get("status") not in GOOD else None
            if hint:      # spell out the exit code, PL then EN
                lines.append(f"      -> {hint[0]}")
                lines.append(f"      -> {hint[1]}")
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
INVENTORY_TTL = 240    # refresh ~every tick; the slow pvesm part is cached hourly
                       # (cached_coverage), so config/schedule changes surface "on the fly"


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


_WD = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5, "sun": 6}


def _schedule_days(sched):
    """Parse the weekday spec of a systemd-calendar / vzdump schedule into a sorted
    list of weekdays (Mon=0..Sun=6). Returns None for an every-day schedule.
    Handles 'mon..fri 23:00', 'sat 00:30', 'mon,wed,fri 02:00', '*-*-* 01:00',
    'daily', and a bare 'HH:MM'."""
    s = (sched or "").lower()
    mt = re.search(r"\d{1,2}:\d{2}", s)
    head = (s[:mt.start()] if mt else s).replace("*", " ").strip()
    if not head or "daily" in s:
        return None                                   # every day
    days = set()
    for part in re.split(r"[,\s]+", head):
        mr = re.match(r"([a-z]{3})\.\.([a-z]{3})$", part)
        if mr and mr.group(1) in _WD and mr.group(2) in _WD:
            a, b = _WD[mr.group(1)], _WD[mr.group(2)]
            days.update(range(a, b + 1) if a <= b
                        else list(range(a, 7)) + list(range(0, b + 1)))
        elif part in _WD:
            days.add(_WD[part])
    return sorted(days) or None


def _ts_min(ts):
    m = re.search(r"\b(\d\d):(\d\d):\d\d\b", ts or "")
    return int(m.group(1)) * 60 + int(m.group(2)) if m else None


COVERAGE_CACHE = "/var/lib/proxmox-adminupdater/coverage.json"
COVERAGE_TTL = 3600   # pvesm list hits network storages (PBS/NFS) -> cache hourly


def backup_coverage(storages):
    """Latest backup per guest overall (cov, for freshness) AND per (storage,guest)
    (by_st, so a window's end is derived from ITS OWN storage's completions, not a
    faster daily job on a different storage)."""
    cov, by_st = {}, {}
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
            sm = by_st.setdefault(st, {})
            if vmid not in sm or ts > sm[vmid]:
                sm[vmid] = ts
            if vmid not in cov or ts > cov[vmid]["ts"]:
                cov[vmid] = {"storage": st, "ts": ts}
    return cov, by_st


def cached_coverage(storages):
    """pvesm over the network is the slow part of the scan; everything else (jobs.cfg,
    host-maintenance, pct/qm list) is local and re-read every tick. Cache ONLY coverage,
    hourly, so backup-config/schedule changes still surface 'on the fly' each tick."""
    try:
        if time.time() - os.path.getmtime(COVERAGE_CACHE) < COVERAGE_TTL:
            d = json.load(open(COVERAGE_CACHE))
            if d.get("cov"):
                return d["cov"], d.get("by_st", {})
    except (OSError, ValueError):
        pass
    cov, by_st = backup_coverage(storages)
    if cov:                                            # never cache an empty/failed scan
        try:
            os.makedirs(os.path.dirname(COVERAGE_CACHE), exist_ok=True)
            json.dump({"cov": cov, "by_st": by_st}, open(COVERAGE_CACHE, "w"))
        except OSError:
            pass
    return cov, by_st


# ---- host maintenance scan (read-only situational awareness) ------------------
# Other scheduled work on the host competes for disk IO with guest updates (ZFS
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
    # collapse duplicates of the SAME logical maintenance (e.g. e2scrub as both a
    # systemd timer AND /etc/cron.d entry, or mdcheck start+continue) to one row,
    # keeping the earliest occurrence — distinct types (scrub/trim/fstrim/…) stay.
    uniq, byname = [], set()
    for j in jobs:
        if j["name"] in byname:
            continue
        byname.add(j["name"])
        uniq.append(j)
    return {"jobs": uniq, "light_count": light}


# ---- learn each backup job's REAL duration from the PVE task history ----------
# The volid filename only carries a guest's START time (in UTC), so it cannot tell us
# when a job FINISHED — a job that starts 23:00 and runs 2 h past midnight looked like
# a 30-min window. Instead we read the last completed vzdump TASK (start+end epoch) and
# convert to local time, so the window reflects how long the backup actually took.
def _node_name():
    try:
        arr = json.loads(_sh(["pvesh", "get", "/nodes", "--output-format", "json"], 15) or "[]")
        if arr:
            return arr[0].get("node")
    except (ValueError, KeyError, IndexError):
        pass
    return (_sh(["hostname"], 5) or "").strip() or None


def _recent_vzdump_tasks(node, limit=100):
    if not node:
        return []
    raw = _sh(["pvesh", "get", f"/nodes/{node}/tasks", "--typefilter", "vzdump",
               "--limit", str(limit), "--output-format", "json"], 25)
    try:
        tasks = json.loads(raw) if raw.strip() else []
    except ValueError:
        return []
    ok = [t for t in tasks if t.get("starttime") and t.get("endtime")]
    ok.sort(key=lambda t: -int(t["starttime"]))
    return ok


def _circ_dist(a, b):
    d = abs(a - b) % 1440
    return min(d, 1440 - d)


def learn_windows(jobs):
    """{job_id: (start_min, end_min)} learned from the last completed vzdump task whose
    weekday + start-of-day match the job's schedule. end carries a small tail margin."""
    tasks = _recent_vzdump_tasks(_node_name())
    learned = {}
    for j in jobs:
        smin = _hhmm_min(j.get("schedule"))
        if smin is None:
            continue
        jdays = _schedule_days(j.get("schedule"))
        for t in tasks:
            st = time.localtime(int(t["starttime"]))
            if jdays is not None and st.tm_wday not in jdays:
                continue
            if _circ_dist(st.tm_hour * 60 + st.tm_min, smin) > 45:
                continue
            et = time.localtime(int(t["endtime"]))
            end = (et.tm_hour * 60 + et.tm_min + 5) % 1440     # +5 min tail margin
            if (end - smin) % 1440 > 480:                      # sanity guard: cap at 8h
                end = (smin + 180) % 1440
            learned[j["id"]] = (smin, end)
            break
    return learned


def build_inventory():
    """Read-only fleet scan. Backup windows are LEARNED from the PVE task history: the
    real [start, end] of the last matching vzdump run (crossing midnight is fine)."""
    jobs = detect_backup_jobs()
    storages = sorted({j.get("storage") for j in jobs if j.get("storage")})
    cov, by_st = cached_coverage(storages)
    learned = learn_windows(jobs)
    windows = []
    for j in jobs:
        smin = _hhmm_min(j.get("schedule"))
        if smin is None:            # monthly / non-daily -> no daily window
            continue
        if j["id"] in learned:
            start_min, end_min = learned[j["id"]]
        else:                       # no task history yet -> conservative 3h guess
            start_min, end_min = smin, (smin + 180) % 1440
        windows.append({"job": j["id"], "start_min": start_min, "end_min": end_min,
                        "storage": j.get("storage"), "days": _schedule_days(j.get("schedule")),
                        "learned": j["id"] in learned})
    guests = {}
    for line in _sh(["pct", "list"], 15).splitlines()[1:]:
        c = line.split()
        if not c:
            continue
        vmid, name = c[0], (c[-1] if len(c) > 2 else "")
        snaps = sum(1 for l in _sh(["pct", "listsnapshot", vmid], 15).splitlines()
                    if re.search(r"_\d{8}_\d{6}", l))
        b = cov.get(vmid)
        guests[vmid] = {"name": name, "snapshots": snaps, "type": "lxc",
                        "backup": {"storage": b["storage"], "ts": b["ts"]} if b else None}
    # QEMU VMs: same coverage/snapshot bookkeeping, plus a cheap agent-readiness ping
    # (running guests only -- pinging a stopped VM is a guaranteed, meaningless miss)
    # so the panel can warn "no guest agent" instead of jobs mysteriously failing later.
    for line in _sh(["qm", "list"], 15).splitlines()[1:]:
        c = line.split()
        if not c:
            continue
        vmid = c[0]
        name = c[1] if len(c) > 1 else ""
        status = c[2] if len(c) > 2 else ""
        snaps = sum(1 for l in _sh(["qm", "listsnapshot", vmid], 15).splitlines()
                    if re.search(r"_\d{8}_\d{6}", l))
        b = cov.get(vmid)
        agent_ok = run(["qm", "agent", vmid, "ping"], 10)[0] == 0 if status == "running" else None
        guests[vmid] = {"name": name, "snapshots": snaps, "type": "qemu", "agent_ok": agent_ok,
                        "backup": {"storage": b["storage"], "ts": b["ts"]} if b else None}
    return {"checked": datetime.now(timezone.utc).isoformat(),
            "jobs": [{"id": j["id"], "schedule": j.get("schedule"),
                      "storage": j.get("storage"), "vmids": j.get("vmids", [])} for j in jobs],
            "windows": windows, "guests": guests, "host_jobs": scan_host_jobs()}


def scan_ok(inv):
    """A scan is trustworthy only if it saw guests, and (when backup jobs exist)
    at least one real backup. Prevents a timed-out pvesm/pct/qm from clobbering good
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
        {"ctid": 108, "kind": "update", "gtype": "lxc", "status": "ok",
         "snapshot": "preupd_20260720_020000", "pruned": ["preupd_20260713_020000"],
         "ram_boost": {"from": 1024, "to": 4096},
         "steps": [{"action": "security-patch", "status": "ok", "rc": 0},
                   {"action": "ram-boost", "status": "ok", "rc": 0},
                   {"action": "app-update", "status": "ok", "rc": 0},
                   {"action": "health-check", "status": "ok", "rc": 0}]},
        {"ctid": 114, "kind": "update", "gtype": "lxc", "status": "failed",
         "snapshot": "preupd_20260720_021500",
         "steps": [{"action": "security-patch", "status": "ok", "rc": 0},
                   {"action": "app-update", "status": "failed", "rc": 137}]},
        {"ctid": 201, "kind": "update", "gtype": "qemu", "status": "ok",
         "snapshot": "preupd_20260731_020000",
         "steps": [{"action": "security-patch", "status": "ok", "rc": 0},
                   {"action": "reboot", "status": "ok", "rc": 0},
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
        # ad-hoc "check" probes are informational glances from the panel, not
        # something worth an email digest entry
        maybe_notify(cfg, [r for r in results if r.get("kind") != "check"])
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
