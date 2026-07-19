#!/usr/bin/env bash
# Remove proxmox-adminupdater: destroy the LXC, remove the host executor/timer,
# and the scoped API token/role/user. Guest pre-update snapshots are NOT touched.
#   bash uninstall.sh <CTID>
set -euo pipefail

CTID="${1:-}"
[ "$(id -u)" -eq 0 ] || { echo "uruchom jako root na hoście PVE"; exit 1; }
[ -n "$CTID" ] || { echo "użycie: bash uninstall.sh <CTID>"; exit 1; }

read -rp "Usunąć kontener $CTID, host-executor i token API adminupdater@pve? [y/N] " ans
[ "${ans,,}" = "y" ] || { echo "przerwano"; exit 0; }

# host-side executor
systemctl disable --now proxmox-adminupdater.timer 2>/dev/null || true
rm -f /etc/systemd/system/proxmox-adminupdater.service /etc/systemd/system/proxmox-adminupdater.timer
rm -f /usr/local/bin/proxmox-adminupdater-exec.py
systemctl daemon-reload 2>/dev/null || true
echo "✔ Host-executor usunięty (host.conf/recipes zostają w /etc/proxmox-adminupdater — usuń ręcznie)"

# container
if pct status "$CTID" >/dev/null 2>&1; then
  pct stop "$CTID" >/dev/null 2>&1 || true
  pct destroy "$CTID" >/dev/null 2>&1 || true
  echo "✔ Kontener $CTID usunięty"
fi

# token/role/user
pveum user token remove adminupdater@pve exec 2>/dev/null || true
pveum acl delete /vms --users adminupdater@pve --roles AdminUpdater 2>/dev/null || true
pveum user delete adminupdater@pve 2>/dev/null || true
pveum role delete AdminUpdater 2>/dev/null || true
echo "✔ Token/rola/user na hoście usunięte"
echo "ℹ Migawki preupd_* w guestach pozostały nietknięte — usuń je ręcznie, jeśli chcesz."
