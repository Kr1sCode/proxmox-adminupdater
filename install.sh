#!/usr/bin/env bash
# proxmox-adminupdater installer — run ON a Proxmox VE host.
# Creates an unprivileged Debian 13 LXC running the "brain" (web UI + plan/report
# API), provisions a scoped read-only API token (VM.Audit), and installs the ONLY
# host-side component: a small executor + systemd timer that pulls the plan and
# runs `pct snapshot` + `pct exec` per opted-in guest.
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Kr1sCode/proxmox-adminupdater/main/install.sh)"
#
set -euo pipefail

REPO="${AU_REPO:-Kr1sCode/proxmox-adminupdater}"
BRANCH="${AU_BRANCH:-main}"
TARBALL="https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz"

# ---------- pretty output ----------
RD=$'\033[31m'; GN=$'\033[32m'; YW=$'\033[33m'; BL=$'\033[36m'; BD=$'\033[1m'; NC=$'\033[0m'
msg()  { echo -e " ${GN}✔${NC} $*"; }
info() { echo -e " ${BL}➜${NC} $*"; }
warn() { echo -e " ${YW}!${NC} $*"; }
die()  { echo -e " ${RD}✘${NC} $*" >&2; exit 1; }
banner() {
  echo -e "${BL}${BD}"
  echo '   ┌────────────────────────────────────────────────────┐'
  echo '   │   ◆  proxmox-adminupdater  ·  agentless LXC updater │'
  echo '   └────────────────────────────────────────────────────┘'
  echo -e "${NC}"
}

# ---------- preflight ----------
banner
[ "$(id -u)" -eq 0 ] || die "uruchom jako root na hoście Proxmox VE"
command -v pveversion >/dev/null 2>&1 || die "to nie wygląda na host Proxmox VE (brak pveversion)"
command -v pct >/dev/null 2>&1 || die "brak pct"
info "Proxmox: $(pveversion | head -1)"

WT=(whiptail --backtitle "proxmox-adminupdater" --title "proxmox-adminupdater")
wt_input()  { "${WT[@]}" --inputbox    "$1" 9  68 "$2" 3>&1 1>&2 2>&3; }
wt_pass()   { "${WT[@]}" --passwordbox  "$1" 9  68 ""  3>&1 1>&2 2>&3; }
tx()        { local v=""; read -rp "   $1 [$2]: " v </dev/tty 2>/dev/null || true; echo "${v:-$2}"; }
ask()       { local v=""; read -rp "   $1 " v </dev/tty 2>/dev/null || true; echo "$v"; }

# Which wizard to use. Unless AU_NONINTERACTIVE=1 is set explicitly, the user
# ALWAYS gets a menu: whiptail if present (or installable), otherwise a plain
# text wizard. It must never silently auto-create a container.
WIZARD="text"
if [ "${AU_NONINTERACTIVE:-0}" = 1 ]; then
  WIZARD="none"; info "AU_NONINTERACTIVE=1 — pomijam kreator, używam defaultów/env"
elif command -v whiptail >/dev/null 2>&1; then
  WIZARD="whiptail"
else
  warn "brak whiptail — próbuję doinstalować (potrzebny do menu)…"
  if apt-get -qq update >/dev/null 2>&1 && apt-get -qq install -y whiptail >/dev/null 2>&1 \
     && command -v whiptail >/dev/null 2>&1; then
    WIZARD="whiptail"; msg "whiptail zainstalowany"
  else
    warn "whiptail niedostępny — używam kreatora tekstowego"
  fi
fi
[ "$WIZARD" != none ] && info "Kreator: ${WIZARD}"

# ---------- defaults ----------
NEXTID=$(pvesh get /cluster/nextid 2>/dev/null || echo 210)
DEF_CTID="$NEXTID"; DEF_HOST="adminupdater"; DEF_DISK="3"; DEF_CORES="1"; DEF_RAM="512"

# detect bridges + container-capable storages
mapfile -t BRIDGES < <(ip -o link show type bridge 2>/dev/null | awk -F': ' '{print $2}' | sed 's/@.*//' | sort)
[ "${#BRIDGES[@]}" -gt 0 ] || BRIDGES=(vmbr0)
DEF_BRIDGE="vmbr0"; printf '%s\n' "${BRIDGES[@]}" | grep -qx vmbr0 || DEF_BRIDGE="${BRIDGES[0]}"
mapfile -t STORES < <(pvesm status -content rootdir 2>/dev/null | awk 'NR>1{print $1}')
DEF_STORE="${STORES[0]:-local-lvm}"

# ---------- base values (env overridable, also prefill the wizard) ----------
CTTYPE="${AU_UNPRIVILEGED:-1}"           # 1=unprivileged 0=privileged
PASSWORD="${AU_PASSWORD:-}"
CTID="${AU_CTID:-$DEF_CTID}";      HOSTNAME="${AU_HOSTNAME:-$DEF_HOST}"
DISK="${AU_DISK:-$DEF_DISK}";      CORES="${AU_CORES:-$DEF_CORES}"
RAM="${AU_RAM:-$DEF_RAM}";         STORE="${AU_STORE:-$DEF_STORE}"
BRIDGE="${AU_BRIDGE:-$DEF_BRIDGE}"; DNS="${AU_NS:-}"; NESTING="${AU_NESTING:-1}"
# IPv4: parse AU_NET ("dhcp" | "CIDR,gw=GW")
IP4MODE="dhcp"; IP4=""; GW=""
if [ -n "${AU_NET:-}" ] && [ "${AU_NET}" != "dhcp" ]; then
  IP4MODE="static"; IP4="${AU_NET%%,*}"; GW="$(sed -n 's/.*gw=\([^,]*\).*/\1/p' <<<"$AU_NET")"
fi

# ---------- wizard ----------
if [ "$WIZARD" = "whiptail" ]; then
  MODE=$("${WT[@]}" --menu "Tryb instalacji" 12 68 2 \
    "1" "Default  — automatyczne ustawienia (DHCP, vmbr0)" \
    "2" "Advanced — CT ID, hostname, sieć, DNS, zasoby" 3>&1 1>&2 2>&3) || die "anulowano"
  if [ "$MODE" = "2" ]; then
    CTTYPE=$("${WT[@]}" --radiolist "Typ kontenera" 11 68 2 \
      "1" "Unprivileged (zalecane)" ON  "0" "Privileged" OFF 3>&1 1>&2 2>&3) || die "anulowano"
    PASSWORD=$(wt_pass "Hasło root (puste = wygeneruj losowe)") || die "anulowano"
    CTID=$(wt_input "Container ID" "$DEF_CTID") || die "anulowano"
    HOSTNAME=$(wt_input "Hostname" "$DEF_HOST") || die "anulowano"
    DISK=$(wt_input "Dysk (GB)" "$DEF_DISK") || die "anulowano"
    CORES=$(wt_input "Rdzenie CPU" "$DEF_CORES") || die "anulowano"
    RAM=$(wt_input "RAM (MiB)" "$DEF_RAM") || die "anulowano"
    smenu=(); for s in "${STORES[@]}"; do smenu+=("$s" ""); done
    [ "${#smenu[@]}" -gt 0 ] && STORE=$("${WT[@]}" --menu "Storage (rootfs)" 14 68 6 "${smenu[@]}" 3>&1 1>&2 2>&3)
    bmenu=(); for b in "${BRIDGES[@]}"; do bmenu+=("$b" ""); done
    BRIDGE=$("${WT[@]}" --menu "Network bridge" 14 68 6 "${bmenu[@]}" 3>&1 1>&2 2>&3) || die "anulowano"
    IP4MODE=$("${WT[@]}" --menu "Konfiguracja IPv4" 11 68 2 \
      "dhcp" "Automatycznie (DHCP)" "static" "Statyczny adres" 3>&1 1>&2 2>&3) || die "anulowano"
    if [ "$IP4MODE" = "static" ]; then
      IP4=$(wt_input "Adres IPv4 w formacie CIDR (np. 192.168.1.50/24)" "$IP4") || die "anulowano"
      GW=$(wt_input "Brama (gateway), np. 192.168.1.1" "$GW") || die "anulowano"
    fi
    DNS=$(wt_input "Serwer DNS (puste = dziedzicz z hosta)" "$DNS") || die "anulowano"
    if "${WT[@]}" --yesno "Włączyć nesting? (wymagane przez systemd w kontenerze)" 8 68; then
      NESTING=1
    else
      NESTING=0
    fi
    "${WT[@]}" --yesno "Podsumowanie:

  CT ID:     $CTID   ($([ "$CTTYPE" = 1 ] && echo unprivileged || echo privileged))
  Hostname:  $HOSTNAME
  Zasoby:    ${CORES} vCPU · ${RAM} MiB · ${DISK} GB · $STORE
  Sieć:      $BRIDGE · $([ "$IP4MODE" = static ] && echo "$IP4 gw=$GW" || echo DHCP)
  DNS:       ${DNS:-<host>}

Utworzyć kontener?" 16 68 || die "anulowano przez użytkownika"
  fi
elif [ "$WIZARD" = "text" ]; then
  echo
  echo "   Tryb instalacji:"
  echo "     1) Default  — automatyczne (DHCP, ${DEF_BRIDGE}, CTID ${DEF_CTID})"
  echo "     2) Advanced — wybierz CTID, sieć, zasoby"
  MODE="$(tx 'Wybór (1/2)' '1')"
  if [ "$MODE" = "2" ]; then
    a="$(ask 'Unprivileged? [T/n]:')"; [ "${a,,}" = n ] && CTTYPE=0 || CTTYPE=1
    read -rsp "   Hasło root (puste = losowe): " PASSWORD </dev/tty 2>/dev/null || true; echo
    CTID="$(tx 'Container ID' "$DEF_CTID")"
    HOSTNAME="$(tx 'Hostname' "$DEF_HOST")"
    DISK="$(tx 'Dysk (GB)' "$DEF_DISK")"
    CORES="$(tx 'Rdzenie CPU' "$DEF_CORES")"
    RAM="$(tx 'RAM (MiB)' "$DEF_RAM")"
    STORE="$(tx "Storage [${STORES[*]:-local-lvm}]" "$DEF_STORE")"
    BRIDGE="$(tx "Bridge [${BRIDGES[*]}]" "$DEF_BRIDGE")"
    IP4="$(tx 'IPv4 CIDR, np. 192.168.1.50/24 (puste = DHCP)' '')"
    if [ -n "$IP4" ]; then IP4MODE=static; GW="$(tx 'Brama (gateway)' '')"; fi
    DNS="$(tx 'DNS (puste = dziedzicz z hosta)' '')"
    a="$(ask 'Nesting? [T/n]:')"; [ "${a,,}" = n ] && NESTING=0 || NESTING=1
  fi
  echo
  echo "   Podsumowanie: CT ${CTID} ($([ "$CTTYPE" = 1 ] && echo unpriv || echo priv)) · ${CORES}vCPU/${RAM}MiB/${DISK}GB · ${STORE} · ${BRIDGE} · $([ "$IP4MODE" = static ] && echo "$IP4 gw=${GW}" || echo DHCP)"
  a="$(ask 'Utworzyć kontener? [T/n]:')"; [ "${a,,}" = n ] && die "anulowano przez użytkownika"
fi

# ---------- validate ----------
[[ "$CTID" =~ ^[0-9]+$ ]] || die "CTID musi być liczbą: $CTID"
if pct status "$CTID" >/dev/null 2>&1 || qm status "$CTID" >/dev/null 2>&1; then
  die "ID $CTID jest już zajęte"
fi
[ "$IP4MODE" = "static" ] && { [ -n "$IP4" ] || die "statyczny IPv4 wybrany, ale adres pusty"; }

# ---------- template ----------
info "Sprawdzam szablon Debian 13…"
TMPL=$(pveam list local 2>/dev/null | awk '/debian-13-standard/{print $1}' | head -1)
if [ -z "$TMPL" ]; then
  AV=$(pveam available --section system 2>/dev/null | awk '/debian-13-standard/{print $2}' | head -1)
  [ -n "$AV" ] || die "brak szablonu debian-13-standard w pveam"
  info "Pobieram $AV…"; pveam download local "$AV" >/dev/null
  TMPL="local:vztmpl/$AV"
fi
msg "Szablon: $TMPL"

# ---------- network arg ----------
if [ "$IP4MODE" = "static" ]; then
  NET="name=eth0,bridge=${BRIDGE},ip=${IP4}"
  [ -n "$GW" ] && NET="${NET},gw=${GW}"
else
  NET="name=eth0,bridge=${BRIDGE},ip=dhcp"
fi
NS_ARG=(); [ -n "$DNS" ] && NS_ARG=(--nameserver "$DNS")
[ -n "$PASSWORD" ] || PASSWORD="$(openssl rand -base64 12 2>/dev/null || head -c 12 /dev/urandom | base64)"

# ---------- create ----------
info "Tworzę LXC ${CTID} (${HOSTNAME})…"
pct create "$CTID" "$TMPL" \
  --hostname "$HOSTNAME" \
  --cores "$CORES" --memory "$RAM" --swap "$RAM" \
  --rootfs "${STORE}:${DISK}" \
  --net0 "$NET" "${NS_ARG[@]}" \
  --features "nesting=${NESTING}" \
  --password "$PASSWORD" \
  --ostype debian --unprivileged "$CTTYPE" --onboot 1 \
  --description "proxmox-adminupdater — agentless LXC updater (brain)" >/dev/null
msg "Kontener utworzony"
pct start "$CTID" >/dev/null
info "Czekam na sieć kontenera…"
for _ in $(seq 1 30); do
  CT_IP=$(pct exec "$CTID" -- bash -c "ip -4 -o addr show eth0 2>/dev/null | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || true)
  [ -n "${CT_IP:-}" ] && break; sleep 2
done
[ -n "${CT_IP:-}" ] || die "kontener nie dostał IP"
msg "Kontener IP: ${CT_IP}"

# host IP on that bridge — what the container uses to reach the PVE API
PVE_HOST=$(ip -4 -o addr show "$BRIDGE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
[ -n "${PVE_HOST:-}" ] || PVE_HOST=$(hostname -I | awk '{print $1}')

# ---------- API token + role on host (READ-ONLY: VM.Audit) ----------
# The container only READS the guest list/status. Snapshots + exec are done by
# the host executor with native pct, so no VM.Snapshot on the token.
info "Provisioning roli/tokenu API (read-only VM.Audit, endpoint: ${PVE_HOST}:8006)…"
pveum role add AdminUpdater --privs "VM.Audit" 2>/dev/null || \
  pveum role modify AdminUpdater --privs "VM.Audit" 2>/dev/null || true
pveum user add adminupdater@pve --comment "proxmox-adminupdater" 2>/dev/null || true
pveum acl modify /vms --users adminupdater@pve --roles AdminUpdater 2>/dev/null || true
if pveum user token list adminupdater@pve --output-format json 2>/dev/null | grep -q '"exec"'; then
  warn "Token adminupdater@pve!exec już istniał — rotuję na nowy"
fi
pveum user token remove adminupdater@pve exec 2>/dev/null || true
TOKVAL=$(pveum user token add adminupdater@pve exec --privsep 0 --output-format json | \
  python3 -c "import sys,json;print(json.load(sys.stdin)['value'])")
[ -n "$TOKVAL" ] || die "nie udało się utworzyć tokenu"
if curl -fsSk -H "Authorization: PVEAPIToken=adminupdater@pve!exec=${TOKVAL}" \
     "https://${PVE_HOST}:8006/api2/json/version" >/dev/null 2>&1; then
  msg "Token API zweryfikowany (adminupdater@pve!exec)"
else
  warn "Token utworzony, ale nie zweryfikowałem połączenia z ${PVE_HOST}:8006 — sprawdź sieć kontenera"
fi

# ---------- install brain inside container ----------
info "Instaluję aplikację w kontenerze…"
pct exec "$CTID" -- bash -s -- "$REPO" "$BRANCH" "$PVE_HOST" "adminupdater@pve!exec=${TOKVAL}" <<'INNER'
set -euo pipefail
REPO="$1"; BRANCH="$2"; PVE_HOST="$3"; TOKEN="$4"
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true -qq update >/dev/null
apt-get -o Acquire::ForceIPv4=true -qq install -y curl python3 python3-flask python3-requests python3-gunicorn >/dev/null
ln -sf /usr/share/zoneinfo/$(cat /etc/timezone 2>/dev/null || echo UTC) /etc/localtime 2>/dev/null || true

mkdir -p /opt/adminupdater /etc/adminupdater /var/lib/adminupdater /var/log/adminupdater
tmp=$(mktemp -d)
curl -fsSL "https://github.com/${REPO}/archive/refs/heads/${BRANCH}.tar.gz" | tar -xz -C "$tmp"
src="$tmp"/*/
cp -r $src/app/. /opt/adminupdater/
cp $src/systemd/*.service /etc/systemd/system/

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
curl -fsSL "$TARBALL" | tar -xz -C "$htmp"
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

# ---------- verify ----------
sleep 2
if pct exec "$CTID" -- curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1/login 2>/dev/null | grep -q 200; then
  msg "Web UI odpowiada"
else
  warn "Web UI jeszcze nie odpowiada — sprawdź: pct exec $CTID -- journalctl -u adminupdater-web"
fi

echo
echo -e "${GN}${BD} ✔ Gotowe!${NC}"
echo -e "   Panel:     ${BD}http://${CT_IP}/${NC}   (login: poświadczenia Proxmoksa, domyślnie root@pam)"
echo -e "   Kontener:  CT ${BD}${CTID}${NC} (${HOSTNAME}) · IP ${BD}${CT_IP}${NC} · hasło root ${BD}${PASSWORD}${NC}"
echo -e "   Host conf: ${BD}/etc/proxmox-adminupdater/host.conf${NC}"
echo
echo -e "   ${YW}WAŻNE:${NC} nic się nie zaktualizuje, dopóki NIE dopiszesz CT do ${BD}allowed_ctids${NC}"
echo -e "          w host.conf (twarda whitelista po stronie hosta), a potem:"
echo -e "          ${BD}systemctl restart proxmox-adminupdater.timer${NC}"
echo -e "   ${YW}HTTPS:${NC} wystaw panel przez reverse proxy (np. NPM) → http://${CT_IP}:80"
echo
