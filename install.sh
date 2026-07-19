#!/usr/bin/env bash
# proxmox-adminupdater installer — run ON a Proxmox VE host.
#
# Creates an unprivileged Debian 13 LXC running the "brain" (web UI + plan/report
# API), provisions a scoped read-only API token, and installs the ONLY host-side
# component: a small executor + systemd timer that pulls the plan and runs
# `pct snapshot` + `pct exec` per opted-in guest.
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Kr1sCode/proxmox-adminupdater/main/install.sh)"
#
set -euo pipefail

REPO="${AU_REPO:-Kr1sCode/proxmox-adminupdater}"
BRANCH="${AU_BRANCH:-main}"

RD=$'\033[31m'; GN=$'\033[32m'; YW=$'\033[33m'; BL=$'\033[36m'; BD=$'\033[1m'; NC=$'\033[0m'
msg(){ echo -e " ${GN}✔${NC} $*"; }
info(){ echo -e " ${BL}➜${NC} $*"; }
warn(){ echo -e " ${YW}!${NC} $*"; }
die(){ echo -e " ${RD}✘${NC} $*" >&2; exit 1; }

echo -e "${BL}${BD}   ◆  proxmox-adminupdater  ·  agentless LXC updater${NC}\n"
[ "$(id -u)" -eq 0 ] || die "uruchom jako root na hoście Proxmox VE"
command -v pveversion >/dev/null 2>&1 || die "to nie wygląda na host Proxmox VE"
command -v pct >/dev/null 2>&1 || die "brak pct"
info "Proxmox: $(pveversion | head -1)"

# ---------- defaults (env-overridable) ----------
NEXTID=$(pvesh get /cluster/nextid 2>/dev/null || echo 210)
CTID="${AU_CTID:-$NEXTID}"; HOSTNAME="${AU_HOSTNAME:-adminupdater}"
DISK="${AU_DISK:-3}"; CORES="${AU_CORES:-1}"; RAM="${AU_RAM:-512}"
CTTYPE="${AU_UNPRIVILEGED:-1}"; NESTING="${AU_NESTING:-1}"
mapfile -t STORES < <(pvesm status -content rootdir 2>/dev/null | awk 'NR>1{print $1}')
STORE="${AU_STORE:-${STORES[0]:-local-lvm}}"
BRIDGE="${AU_BRIDGE:-vmbr0}"; DNS="${AU_NS:-}"
PASSWORD="${AU_PASSWORD:-$(openssl rand -base64 12 2>/dev/null || head -c 12 /dev/urandom | base64)}"
NET="name=eth0,bridge=${BRIDGE},ip=${AU_NET:-dhcp}"
NS_ARG=(); [ -n "$DNS" ] && NS_ARG=(--nameserver "$DNS")

[[ "$CTID" =~ ^[0-9]+$ ]] || die "CTID musi być liczbą: $CTID"
pct status "$CTID" >/dev/null 2>&1 && die "ID $CTID jest już zajęte"

# ---------- template ----------
info "Sprawdzam szablon Debian 13…"
TMPL=$(pveam list local 2>/dev/null | awk '/debian-13-standard/{print $1}' | head -1)
if [ -z "$TMPL" ]; then
  AV=$(pveam available --section system 2>/dev/null | awk '/debian-13-standard/{print $2}' | head -1)
  [ -n "$AV" ] || die "brak szablonu debian-13-standard"
  info "Pobieram $AV…"; pveam download local "$AV" >/dev/null; TMPL="local:vztmpl/$AV"
fi
msg "Szablon: $TMPL"

# ---------- create container ----------
info "Tworzę LXC ${CTID} (${HOSTNAME})…"
pct create "$CTID" "$TMPL" --hostname "$HOSTNAME" \
  --cores "$CORES" --memory "$RAM" --swap "$RAM" --rootfs "${STORE}:${DISK}" \
  --net0 "$NET" "${NS_ARG[@]}" --features "nesting=${NESTING}" \
  --password "$PASSWORD" --ostype debian --unprivileged "$CTTYPE" --onboot 1 \
  --description "proxmox-adminupdater — agentless LXC updater (brain)" >/dev/null
pct start "$CTID" >/dev/null
info "Czekam na sieć kontenera…"
for _ in $(seq 1 30); do
  CT_IP=$(pct exec "$CTID" -- bash -c "ip -4 -o addr show eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || true)
  [ -n "${CT_IP:-}" ] && break; sleep 2
done
[ -n "${CT_IP:-}" ] || die "kontener nie dostał IP"
msg "Kontener IP: ${CT_IP}"

PVE_HOST=$(ip -4 -o addr show "$BRIDGE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -n "${PVE_HOST:-}" ] || PVE_HOST=$(hostname -I | awk '{print $1}')

# ---------- API token (READ-ONLY: VM.Audit). Host does snapshots via pct. ----------
info "Provisioning roli/tokenu API (read-only, VM.Audit) na hoście…"
pveum role add AdminUpdater --privs "VM.Audit" 2>/dev/null || \
  pveum role modify AdminUpdater --privs "VM.Audit" 2>/dev/null || true
pveum user add adminupdater@pve --comment "proxmox-adminupdater" 2>/dev/null || true
pveum acl modify /vms --users adminupdater@pve --roles AdminUpdater 2>/dev/null || true
pveum user token remove adminupdater@pve exec 2>/dev/null || true
TOKVAL=$(pveum user token add adminupdater@pve exec --privsep 0 --output-format json \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['value'])")
[ -n "$TOKVAL" ] || die "nie udało się utworzyć tokenu"
msg "Token API: adminupdater@pve!exec"

# ---------- install brain inside container ----------
info "Instaluję aplikację w kontenerze…"
pct exec "$CTID" -- bash -s -- "$REPO" "$BRANCH" "$PVE_HOST" "adminupdater@pve!exec=${TOKVAL}" <<'INNER'
set -euo pipefail
REPO="$1"; BRANCH="$2"; PVE_HOST="$3"; TOKEN="$4"
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true -qq update >/dev/null
apt-get -o Acquire::ForceIPv4=true -qq install -y curl python3 python3-flask python3-requests python3-gunicorn >/dev/null
mkdir -p /opt/adminupdater /etc/adminupdater /var/lib/adminupdater /var/log/adminupdater
tmp=$(mktemp -d)
curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz -C "$tmp"
cp -r "$tmp"/*/app/. /opt/adminupdater/
cp "$tmp"/*/systemd/*.service /etc/systemd/system/
cat > /etc/adminupdater/config.json <<JSON
{"settings":{"pve_host":"${PVE_HOST}","pve_port":8006,"verify_tls":false,"paused":false,"snapshot_prefix":"preupd","rollback_on_fail":false},"auth":{"allowlist":["root@pam"]},"guests":{}}
JSON
printf '%s' "$TOKEN" > /etc/adminupdater/token; chmod 600 /etc/adminupdater/token
python3 -c "import secrets;open('/etc/adminupdater/secret','w').write(secrets.token_hex(32))"; chmod 600 /etc/adminupdater/secret
python3 -c "import secrets;open('/etc/adminupdater/exec_token','w').write(secrets.token_hex(32))"; chmod 600 /etc/adminupdater/exec_token
rm -rf "$tmp"
systemctl daemon-reload
systemctl enable --now adminupdater-web.service >/dev/null 2>&1
INNER
msg "Aplikacja zainstalowana w kontenerze"

# ---------- install THE host-side executor (the only host footprint) ----------
info "Instaluję host-executor na Proxmoksie…"
EXECTOK=$(pct exec "$CTID" -- cat /etc/adminupdater/exec_token)
htmp=$(mktemp -d)
curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz -C "$htmp"
install -Dm755 "$htmp"/*/host/proxmox-adminupdater-exec.py /usr/local/bin/proxmox-adminupdater-exec.py
install -d /etc/proxmox-adminupdater/recipes
cp "$htmp"/*/host/recipes/*.sh /etc/proxmox-adminupdater/recipes/ 2>/dev/null || true
cp "$htmp"/*/host/proxmox-adminupdater.service /etc/systemd/system/
cp "$htmp"/*/host/proxmox-adminupdater.timer   /etc/systemd/system/
if [ ! -f /etc/proxmox-adminupdater/host.conf ]; then
  cat > /etc/proxmox-adminupdater/host.conf <<EOF
[main]
updater_url    = http://${CT_IP}
token          = ${EXECTOK}
allowed_ctids  =
recipes_dir    = /etc/proxmox-adminupdater/recipes
exec_timeout   = 1800
tls_insecure   = false
EOF
  chmod 600 /etc/proxmox-adminupdater/host.conf
fi
rm -rf "$htmp"
systemctl daemon-reload
systemctl enable --now proxmox-adminupdater.timer >/dev/null 2>&1
msg "Host-executor zainstalowany (timer aktywny)"

echo
echo -e "${GN}${BD} ✔ Gotowe!${NC}"
echo -e "   Panel:     ${BD}http://${CT_IP}/${NC}   (login: poświadczenia Proxmoksa)"
echo -e "   Kontener:  CT ${BD}${CTID}${NC} (${HOSTNAME}) · hasło root ${BD}${PASSWORD}${NC}"
echo -e "   Host conf: ${BD}/etc/proxmox-adminupdater/host.conf${NC}"
echo
echo -e "   ${YW}WAŻNE:${NC} nic się nie zaktualizuje, dopóki NIE dopiszesz CT do"
echo -e "          ${BD}allowed_ctids${NC} w host.conf (twarda whitelista po stronie hosta),"
echo -e "          a potem: ${BD}systemctl restart proxmox-adminupdater.timer${NC}"
echo
