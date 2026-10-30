#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager  -  Multi-Protocol Tunnel (Proto 50 / 47 GRE / 41 SIT / UDP)
#
#    Iran server   : 10.10.10.2   (menu option 1)
#    Kharej client : 10.10.10.1   (menu option 2)
#
#  Features:
#   * Default shared secret "123" (no manual token copy/paste needed).
#   * Selectable transports:
#       1) Raw ESP (IP Protocol 50)
#       2) GRE Carrier + ESP (IP Protocol 47 - Anti-DPI / Firewall bypass)
#       3) SIT 6in4 Carrier + ESP (IP Protocol 41 - Anti-DPI / Firewall bypass)
#       4) ESP-in-UDP (NAT / fallback transport)
#   * Client-side Protocol Benchmark (Ping, Jitter, Packet Loss, Speed/Bandwidth).
#   * Built-in Kernel & Queue TUNER profiles: GAMING, FULL SPEED, BALANCED, LATENCY.
#   * Automatic UTC Clock Sync (NTP + HTTPS Date fallback) on both ends.
#   * Configurable Auto-Restart Timer (TUNNEL RESTART).
#   * Smart Packet-Loss & Disconnection Watchdog with auto-healing.
# ==============================================================================

APP="esp-tunnel"
VERSION="2.0"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"
DIAG_UDP_PID_FILE="${RUN_DIR}/diag_udp.pid"

DEFAULT_SECRET="123"

IF_NAME="espt0"
GRE_IF="espgre0"
SIT_IF="espsit0"
IF_ID=42

# Diagnostic carrier interfaces (for Protocol Test)
DIAG_GRE_IF="espdgre0"
DIAG_SIT_IF="espdsit0"
DIAG_ESP_IF="espdesp0"
DIAG_IF_ID=99

IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30

# Internal carrier endpoints for Protocol 47 (GRE) and Protocol 41 (SIT)
GRE_IRAN="10.10.11.2"
GRE_KHAREJ="10.10.11.1"
SIT_IRAN="fd00:e570:11::2"
SIT_KHAREJ="fd00:e570:11::1"

# Diagnostic subnets
DIAG_GRE_IRAN="10.10.97.2"
DIAG_GRE_KHAREJ="10.10.97.1"
DIAG_SIT_IRAN="10.10.98.2"
DIAG_SIT_KHAREJ="10.10.98.1"
DIAG_ESP_IRAN="10.10.99.2"
DIAG_ESP_KHAREJ="10.10.99.1"

EPOCH_LEN=3600          # key rotation period (seconds)
SEQ_STEP=1000000        # initial ESP sequence seed per second inside an epoch
MTU_ESP=1400
MTU_UDP=1380
MTU_GRE=1376
MTU_SIT=1360
DEFAULT_UDP_PORT=4500

# ---- runtime state (filled by load_config) -----------------------------------
ROLE=""; MASTER=""; IRAN_IP=""; KHAREJ_IP=""; MODE="esp"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"; TUNER="balanced"; RESTART_MINS=0
WatchdogLossThreshold=25
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_ESP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0
XFRM_LOCAL=""; XFRM_PEER=""; XFRM_DEV=""; SIT_FALLBACK=0

PY_UDP='
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP = UDP_ENCAP_ESPINUDP
while True:
    try:
        data, addr = s.recvfrom(65535)
        if data.startswith(b"ESPT_PROBE:"):
            s.sendto(data, addr)
    except Exception:
        pass
'

# ------------------------------------------------------------------------------
#  Small helpers
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_B=$'\e[1;36m'; C_M=$'\e[1;35m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_M=""; C_0=""
fi
info() { echo "${C_B}[*]${C_0} $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; }
warn() { echo "${C_Y}[!]${C_0} $*" >&2; }
err()  { echo "${C_R}[x]${C_0} $*" >&2; }
log()  { echo "[${APP}] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Please run as root (sudo -i)."
    exit 1
  fi
}

confirm() {
  local def=${2:-n} a p="[y/N]"
  [[ $def == y ]] && p="[Y/n]"
  read -r -p "$1 $p " a
  a=${a:-$def}
  [[ $a =~ ^[Yy] ]]
}

pause() { read -r -p "Press Enter to continue..." _; }

valid_ip() {
  local o
  [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do
    (( 10#$o <= 255 )) || return 1
  done
  return 0
}

is_private_ip() {
  [[ $1 =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.) ]]
}

valid_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }

norm_ports() {
  local raw=${1//[[:space:]]/} spec a b
  local -a out=() specs=()
  raw=${raw//،/,}
  [[ -n $raw ]] || return 1
  IFS=',' read -ra specs <<< "$raw"
  for spec in "${specs[@]}"; do
    [[ -z $spec ]] && continue
    if [[ $spec =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}; b=${BASH_REMATCH[2]}
      valid_port "$a" && valid_port "$b" && (( 10#$a <= 10#$b )) || return 1
      out+=("$((10#$a))-$((10#$b))")
    else
      valid_port "$spec" || return 1
      out+=("$((10#$spec))")
    fi
  done
  (( ${#out[@]} > 0 )) || return 1
  local IFS=,
  echo "${out[*]}"
}

ports_include() {
  local spec a b
  local -a specs=()
  IFS=',' read -ra specs <<< "$1"
  for spec in "${specs[@]}"; do
    if [[ $spec == *-* ]]; then a=${spec%-*}; b=${spec#*-}; else a=$spec; b=$spec; fi
    (( $2 >= a && $2 <= b )) && return 0
  done
  return 1
}

ssh_ports() {
  local p
  p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  [[ -n $p ]] || p=$(ss -Hltnp 2>/dev/null | awk '/sshd/{n=split($4,a,":"); print a[n]}')
  [[ -n $p ]] || p=22
  echo "$p ${SSH_CONNECTION##* }"
}

kdf() { printf '%s' "$1" | sha512sum | awk '{print $1}'; }

default_master_key() {
  kdf "esp-tunnel-static-key-${DEFAULT_SECRET}" | cut -c1-64
}

route_info() {
  local out
  out=$(ip -4 route get "$1" 2>/dev/null | head -n1)
  LOCAL_ADDR=$(awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$out")
  WAN_DEV=$(awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$out")
  [[ -n $LOCAL_ADDR && -n $WAN_DEV ]]
}

detect_public_ip() {
  local addr pub
  addr=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')
  if [[ -z $addr ]] || is_private_ip "$addr"; then
    if have curl; then
      pub=$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null)
      valid_ip "$pub" && addr=$pub
    fi
  fi
  echo "$addr"
}

# ------------------------------------------------------------------------------
#  Clock / Time Synchronization (UTC)
# ------------------------------------------------------------------------------
sync_clock() {
  info "Synchronizing server clock (UTC) to prevent key rotation mismatch..."
  timedatectl set-timezone UTC >/dev/null 2>&1 || ln -sf /usr/share/zoneinfo/UTC /etc/localtime 2>/dev/null
  timedatectl set-ntp true >/dev/null 2>&1 || true

  if have chronyc; then
    chronyc -a makestep >/dev/null 2>&1 || true
  elif have systemctl; then
    systemctl restart systemd-timesyncd >/dev/null 2>&1 || true
  fi

  # HTTPS Date header fallback (works even if UDP 123 NTP is filtered)
  if have curl; then
    local http_date url
    for url in "https://www.google.com" "https://1.1.1.1" "https://icanhazip.com"; do
      http_date=$(curl -fsSI --max-time 4 "$url" 2>/dev/null | awk 'BEGIN{IGNORECASE=1} /^date:/ {sub(/^[Dd]ate:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit}')
      if [[ -n $http_date ]]; then
        local remote_ts local_ts diff
        remote_ts=$(date -u -d "$http_date" +%s 2>/dev/null || echo 0)
        local_ts=$(date -u +%s)
        if (( remote_ts > 1700000000 )); then
          diff=$(( remote_ts - local_ts ))
          (( diff < 0 )) && diff=$(( -diff ))
          if (( diff > 2 )); then
            date -u -s "$http_date" >/dev/null 2>&1 && log "Clock stepped via HTTPS header (drift was ${diff}s)"
          fi
          break
        fi
      fi
    done
  fi
  hwclock -w >/dev/null 2>&1 || true
  ok "System UTC time synchronized: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
}

# ------------------------------------------------------------------------------
#  Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF"
  MASTER=${MASTER:-$(default_master_key)}
  MODE=${MODE:-esp}
  UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}
  FWD_PROTO=${FWD_PROTO:-both}
  TUNER=${TUNER:-balanced}
  RESTART_MINS=${RESTART_MINS:-0}

  case $ROLE in
    iran)
      LOCAL_INNER=$IP_IRAN; PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP
      OUT_LABEL=i2k; IN_LABEL=k2i
      ;;
    kharej)
      LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN; PEER_PUB=$IRAN_IP
      OUT_LABEL=k2i; IN_LABEL=i2k
      ;;
    *) return 1 ;;
  esac
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1

  case $MODE in
    udp) MTU=$MTU_UDP ;;
    gre) MTU=$MTU_GRE ;;
    sit) MTU=$MTU_SIT ;;
    *)   MTU=$MTU_ESP ;;
  esac
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  MASTER=${MASTER:-$(default_master_key)}
  (
    umask 077
    {
      echo "# ${APP} config - shared key derived from default token (${DEFAULT_SECRET})"
      printf 'ROLE=%q\n'         "$ROLE"
      printf 'MASTER=%q\n'       "$MASTER"
      printf 'IRAN_IP=%q\n'      "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n'    "$KHAREJ_IP"
      printf 'MODE=%q\n'         "$MODE"
      printf 'UDP_PORT=%q\n'     "$UDP_PORT"
      printf 'PORTS=%q\n'        "$PORTS"
      printf 'FWD_PROTO=%q\n'    "$FWD_PROTO"
      printf 'TUNER=%q\n'        "$TUNER"
      printf 'RESTART_MINS=%q\n' "$RESTART_MINS"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

# ------------------------------------------------------------------------------
#  Pre-flight: dependencies + kernel support
# ------------------------------------------------------------------------------
ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required (systemctl not found)."; return 1; }
  for c in ip iptables ping ss sha256sum sha512sum base64 awk od head tc curl python3; do
    have "$c" || missing+=("$c")
  done
  (( ${#missing[@]} == 0 )) && return 0

  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || { err "Missing commands: ${missing[*]} (no supported package manager found)."; return 1; }

  for c in "${missing[@]}"; do
    case $c in
      ip|ss|tc) [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)     [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      iptables|python3|curl) pkgs+=("$c") ;;
      *)        pkgs+=(coreutils) ;;
    esac
  done
  info "Installing missing packages: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
  for c in "${missing[@]}"; do
    have "$c" || { err "Could not install '$c'. Install it manually and run again."; return 1; }
  done
  return 0
}

load_modules() {
  local m
  for m in xfrm_interface xfrm_user esp4 esp6 gcm aesni_intel nf_conntrack xt_TCPMSS iptable_nat ip_gre sit ip6_tunnel xfrm6_tunnel tcp_bbr sch_fq sch_fq_codel; do
    modprobe -q "$m" 2>/dev/null
  done
  return 0
}

check_kernel() {
  local t="espchk0" out virt k
  virt=$(systemd-detect-virt 2>/dev/null)
  case $virt in
    openvz|lxc|lxc-libvirt) warn "Virtualization '$virt' detected - XFRM/IPsec normally does NOT work inside containers." ;;
  esac
  load_modules
  ip link del "$t" 2>/dev/null
  if ! out=$(ip link add "$t" type xfrm dev lo if_id 4242 2>&1); then
    err "This kernel has no XFRM-interface support: $out"
    err "Needs Linux >= 4.19 (uname -r) on a real/KVM server (not OpenVZ/LXC)."
    return 1
  fi
  ip link del "$t" 2>/dev/null
  k=$(printf '%072d' 0)
  if ! out=$(ip xfrm state add src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 mode tunnel \
             aead 'rfc4106(gcm(aes))' "0x$k" 128 2>&1); then
    err "Kernel lacks AES-GCM ESP support: $out"
    return 1
  fi
  ip xfrm state delete src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 2>/dev/null
  return 0
}

# ------------------------------------------------------------------------------
#  TUNER Profiles (Kernel sysctl + Interface qdisc/txqueuelen)
# ------------------------------------------------------------------------------
apply_tuner_profile() {
  local profile=${1:-$TUNER}
  local rmem wmem tcp_rmem tcp_wmem backlog qlen qdisc somaxconn tw_reuse low_lat fastopen slow_idle busy_poll busy_read conntrack_max

  case $profile in
    gaming)
      rmem=16777216
      wmem=16777216
      tcp_rmem="4096 65536 16777216"
      tcp_wmem="4096 65536 16777216"
      backlog=8192
      qlen=1000
      qdisc="fq_codel"
      somaxconn=8192
      tw_reuse=1
      low_lat=1
      fastopen=3
      slow_idle=0
      busy_poll=25
      busy_read=25
      conntrack_max=262144
      ;;
    full_speed)
      rmem=67108864
      wmem=67108864
      tcp_rmem="4096 131072 67108864"
      tcp_wmem="4096 131072 67108864"
      backlog=65536
      qlen=10000
      qdisc="fq"
      somaxconn=32768
      tw_reuse=1
      low_lat=0
      fastopen=3
      slow_idle=0
      busy_poll=0
      busy_read=0
      conntrack_max=1048576
      ;;
    latency)
      rmem=8388608
      wmem=8388608
      tcp_rmem="4096 32768 8388608"
      tcp_wmem="4096 32768 8388608"
      backlog=4096
      qlen=500
      qdisc="fq_codel"
      somaxconn=8192
      tw_reuse=1
      low_lat=1
      fastopen=3
      slow_idle=0
      busy_poll=50
      busy_read=50
      conntrack_max=262144
      ;;
    balanced|*)
      rmem=16777216
      wmem=16777216
      tcp_rmem="4096 87380 16777216"
      tcp_wmem="4096 65536 16777216"
      backlog=16384
      qlen=4000
      qdisc="fq"
      somaxconn=16384
      tw_reuse=1
      low_lat=0
      fastopen=3
      slow_idle=0
      busy_poll=0
      busy_read=0
      conntrack_max=524288
      ;;
  esac

  cat > "$SYSCTL_FILE" <<EOF
# ${APP} TUNER Profile: ${profile^^}
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.core.default_qdisc = ${qdisc}
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = ${rmem}
net.core.wmem_max = ${wmem}
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = ${tcp_rmem}
net.ipv4.tcp_wmem = ${tcp_wmem}
net.core.netdev_max_backlog = ${backlog}
net.core.somaxconn = ${somaxconn}
net.ipv4.tcp_tw_reuse = ${tw_reuse}
net.ipv4.tcp_low_latency = ${low_lat}
net.ipv4.tcp_fastopen = ${fastopen}
net.ipv4.tcp_slow_start_after_idle = ${slow_idle}
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.core.busy_poll = ${busy_poll}
net.core.busy_read = ${busy_read}
net.netfilter.nf_conntrack_max = ${conntrack_max}
EOF

  sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.all.rp_filter=0" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.default.rp_filter=0" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    ip link set dev "$IF_NAME" txqueuelen "$qlen" 2>/dev/null
    tc qdisc replace dev "$IF_NAME" root "$qdisc" 2>/dev/null || true
  fi
  if [[ -n $WAN_DEV ]] && ip link show "$WAN_DEV" >/dev/null 2>&1; then
    tc qdisc replace dev "$WAN_DEV" root "$qdisc" 2>/dev/null || true
  fi
}

# ------------------------------------------------------------------------------
#  Firewall (iptables, dedicated chains so cleanup is exact)
# ------------------------------------------------------------------------------
ipt() { iptables -w 5 "$@"; }

fw_chain_reset() {
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -N "$c" 2>/dev/null || ipt -t "$t" -F "$c"
  ipt -t "$t" -I "$h" 1 -j "$c"
}

fw_chain_remove() {
  local t=$1 c=$2 h=$3
  while ipt -t "$t" -D "$h" -j "$c" 2>/dev/null; do :; done
  ipt -t "$t" -F "$c" 2>/dev/null
  ipt -t "$t" -X "$c" 2>/dev/null
}

fw_remove() {
  have iptables || return 0
  fw_chain_remove filter ESPT_IN   INPUT
  fw_chain_remove filter ESPT_FWD  FORWARD
  fw_chain_remove mangle ESPT_MSS  POSTROUTING
  fw_chain_remove nat    ESPT_PRE  PREROUTING
  fw_chain_remove nat    ESPT_POST POSTROUTING
}

fw_apply() {
  local spec d pr
  local -a specs=() protos=()

  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_IN -i "$GRE_IF" -j ACCEPT
  ipt -A ESPT_IN -i "$SIT_IF" -j ACCEPT
  ipt -A ESPT_IN -i "$DIAG_GRE_IF" -j ACCEPT
  ipt -A ESPT_IN -i "$DIAG_SIT_IF" -j ACCEPT
  ipt -A ESPT_IN -i "$DIAG_ESP_IF" -j ACCEPT

  # Accept all 4 tunnel transports from peer (and diagnostic probes)
  if [[ -n $PEER_PUB ]]; then
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
    ipt -A ESPT_IN -p 47 -s "$PEER_PUB" -j ACCEPT
    ipt -A ESPT_IN -p 41 -s "$PEER_PUB" -j ACCEPT
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$UDP_PORT" -j ACCEPT
  fi
  if [[ $ROLE == iran ]]; then
    # Allow Protocol Test probes from Kharej even before peer IP is locked
    ipt -A ESPT_IN -p 50 -j ACCEPT
    ipt -A ESPT_IN -p 47 -j ACCEPT
    ipt -A ESPT_IN -p 41 -j ACCEPT
    ipt -A ESPT_IN -p udp --dport "$UDP_PORT" -j ACCEPT
  fi

  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  if [[ $TUNER == gaming || $TUNER == latency ]]; then
    ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -j DSCP --set-dscp-class EF 2>/dev/null || true
  fi

  if [[ $ROLE == iran && -n $PORTS ]]; then
    fw_chain_reset nat ESPT_PRE  PREROUTING
    fw_chain_reset nat ESPT_POST POSTROUTING
    case $FWD_PROTO in
      tcp) protos=(tcp) ;;
      udp) protos=(udp) ;;
      *)   protos=(tcp udp) ;;
    esac
    IFS=',' read -ra specs <<< "$PORTS"
    for spec in "${specs[@]}"; do
      [[ -z $spec ]] && continue
      d=${spec/-/:}
      for pr in "${protos[@]}"; do
        ipt -t nat -A ESPT_PRE ! -i "$IF_NAME" -p "$pr" --dport "$d" -j DNAT --to-destination "$IP_KHAREJ"
      done
    done
    ipt -t nat -A ESPT_POST -o "$IF_NAME" -d "$IP_KHAREJ" -j SNAT --to-source "$IP_IRAN"
  fi
  return 0
}

# ------------------------------------------------------------------------------
#  Carrier & XFRM Interface / Policies / Security Associations
# ------------------------------------------------------------------------------
carrier_teardown() {
  ip link del "$GRE_IF" 2>/dev/null
  ip link del "$SIT_IF" 2>/dev/null
}

carrier_setup() {
  carrier_teardown
  SIT_FALLBACK=0
  case $MODE in
    gre)
      local gre_local gre_peer
      if [[ $ROLE == iran ]]; then
        gre_local=$GRE_IRAN; gre_peer=$GRE_KHAREJ
      else
        gre_local=$GRE_KHAREJ; gre_peer=$GRE_IRAN
      fi
      ip tunnel add "$GRE_IF" mode gre local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 dev "$WAN_DEV" || {
        log "ERROR: failed to create GRE carrier ($GRE_IF)"; return 1
      }
      ip addr add "${gre_local}/30" dev "$GRE_IF" || return 1
      ip link set "$GRE_IF" mtu 1440 up || return 1
      sysctl -qw "net.ipv4.conf.${GRE_IF}.rp_filter=0" >/dev/null 2>&1
      XFRM_LOCAL=$gre_local
      XFRM_PEER=$gre_peer
      XFRM_DEV=$GRE_IF
      ;;
    sit)
      local sit_local sit_peer
      if [[ $ROLE == iran ]]; then
        sit_local=$SIT_IRAN; sit_peer=$SIT_KHAREJ
      else
        sit_local=$SIT_KHAREJ; sit_peer=$SIT_IRAN
      fi
      ip tunnel add "$SIT_IF" mode sit local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 dev "$WAN_DEV" || {
        log "ERROR: failed to create SIT proto-41 carrier ($SIT_IF)"; return 1
      }
      sysctl -qw "net.ipv6.conf.${SIT_IF}.disable_ipv6=0" >/dev/null 2>&1
      ip link set "$SIT_IF" mtu 1420 up || return 1
      ip -6 addr add "${sit_local}/64" dev "$SIT_IF" || return 1
      XFRM_LOCAL=$sit_local
      XFRM_PEER=$sit_peer
      XFRM_DEV=$SIT_IF
      ;;
    *)
      XFRM_LOCAL=$LOCAL_ADDR
      XFRM_PEER=$PEER_PUB
      XFRM_DEV=$WAN_DEV
      ;;
  esac
  return 0
}

iface_setup() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$XFRM_DEV" if_id "$IF_ID" 2>&1); then
    log "ERROR: cannot create interface $IF_NAME: $out"; return 1
  fi
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || { log "ERROR: cannot set $LOCAL_INNER on $IF_NAME"; return 1; }
  ip link set "$IF_NAME" mtu "$MTU" up            || { log "ERROR: cannot bring $IF_NAME up"; return 1; }
  return 0
}

policies_remove() {
  local a b
  for a in "$IP_IRAN" "$IP_KHAREJ"; do
    if [[ $a == "$IP_IRAN" ]]; then b=$IP_KHAREJ; else b=$IP_IRAN; fi
    ip xfrm policy delete src "$a/32" dst "$b/32" dir out if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst "$b/32" dir in  if_id "$IF_ID" 2>/dev/null
    ip xfrm policy delete src "$a/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null
  done
}

policies_setup() {
  (( SIT_FALLBACK == 1 )) && return 0
  local out
  policies_remove
  out=$(ip xfrm policy add src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
        tmpl src "$XFRM_LOCAL" dst "$XFRM_PEER" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy out: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
        tmpl src "$XFRM_PEER" dst "$XFRM_LOCAL" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy in: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
        tmpl src "$XFRM_PEER" dst "$XFRM_LOCAL" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy fwd: $out"; return 1; }
  return 0
}

sa_add() {
  (( SIT_FALLBACK == 1 )) && return 0
  local dir=$1 e=$2 src dst label spi key seq out
  local -a args=()
  if [[ $dir == out ]]; then src=$XFRM_LOCAL; dst=$XFRM_PEER;  label=$OUT_LABEL
  else                       src=$XFRM_PEER;  dst=$XFRM_LOCAL; label=$IN_LABEL
  fi
  grep -q "^$dir $e " "$REG" 2>/dev/null && return 0

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)
  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  args+=(if_id "$IF_ID")

  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
  if [[ $dir == out ]]; then
    seq=$(( ($(date +%s) % EPOCH_LEN) * SEQ_STEP ))
    if ! out=$(ip xfrm state add "${args[@]}" replay-oseq "$seq" 2>&1); then
      out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
    fi
  else
    out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
  fi
  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

# Fallback for kernels where cross-family IPv4-in-IPv6 XFRM over SIT isn't enabled
setup_sit_direct_fallback() {
  SIT_FALLBACK=1
  policies_remove
  sa_flush
  ip link del "$IF_NAME" 2>/dev/null
  ip link del "$SIT_IF" 2>/dev/null
  ip tunnel add "$IF_NAME" mode sit local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 dev "$WAN_DEV" || return 1
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || return 1
  ip link set "$IF_NAME" mtu "$MTU_SIT" up || return 1
  echo "out $CUR_EPOCH 0x41 $LOCAL_ADDR $PEER_PUB" > "$REG"
  log "SIT Protocol 41 active on $IF_NAME"
  return 0
}

prune_sa() {
  (( SIT_FALLBACK == 1 )) && return 0
  local e=$1 dir ep spi src dst keep tmp
  [[ -f $REG ]] || return 0
  tmp=$(mktemp)
  while read -r dir ep spi src dst; do
    [[ -n $spi ]] || continue
    keep=1
    if [[ $dir == out ]]; then
      (( ep != e )) && keep=0
    else
      (( ep < e - 1 || ep > e + 1 )) && keep=0
    fi
    if (( keep )); then
      echo "$dir $ep $spi $src $dst" >> "$tmp"
    else
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
      log "removed expired SA ($dir, epoch $ep)"
    fi
  done < "$REG"
  cat "$tmp" > "$REG"
  rm -f "$tmp"
}

install_epoch() {
  (( SIT_FALLBACK == 1 )) && return 0
  local e=$1 x
  sa_add out "$e" || return 1
  for x in $((e - 1)) "$e" $((e + 1)); do
    sa_add in "$x" || return 1
  done
  prune_sa "$e"
  return 0
}

sa_flush() {
  local dir ep spi src dst
  if [[ -f $REG ]]; then
    while read -r dir ep spi src dst; do
      [[ -n $spi && $spi != "0x41" ]] && ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    done < "$REG"
  fi
  rm -f "$REG"
}

udp_helper_stop() {
  local f
  for f in "$UDP_PID_FILE" "$DIAG_UDP_PID_FILE"; do
    if [[ -f $f ]]; then
      kill "$(cat "$f")" 2>/dev/null
      rm -f "$f"
    fi
  done
}

udp_helper_start() {
  udp_helper_stop
  python3 -c "$PY_UDP" "$UDP_PORT" >/dev/null 2>&1 &
  echo $! > "$UDP_PID_FILE"
  sleep 0.5
  if ! kill -0 "$(cat "$UDP_PID_FILE")" 2>/dev/null; then
    log "ERROR: cannot open UDP port $UDP_PORT for ESP-in-UDP"
    return 1
  fi
  return 0
}

# ------------------------------------------------------------------------------
#  Diagnostic Responders on Iran (so Client can test Proto 50, 47, 41, UDP)
# ------------------------------------------------------------------------------
diag_teardown() {
  ip link del "$DIAG_GRE_IF" 2>/dev/null
  ip link del "$DIAG_SIT_IF" 2>/dev/null
  ip link del "$DIAG_ESP_IF" 2>/dev/null
  ip xfrm policy delete src "$DIAG_ESP_IRAN/32" dst "$DIAG_ESP_KHAREJ/32" dir out if_id "$DIAG_IF_ID" 2>/dev/null
  ip xfrm policy delete src "$DIAG_ESP_KHAREJ/32" dst "$DIAG_ESP_IRAN/32" dir in if_id "$DIAG_IF_ID" 2>/dev/null
  ip xfrm state delete src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp spi 0x19999991 2>/dev/null
  ip xfrm state delete src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp spi 0x19999992 2>/dev/null
}

diag_setup_iran() {
  [[ $ROLE == iran && -n $PEER_PUB && -n $LOCAL_ADDR ]] || return 0
  diag_teardown

  # 1) GRE Proto 47 test responder (if main mode is not already GRE)
  if [[ $MODE != gre ]]; then
    if ip tunnel add "$DIAG_GRE_IF" mode gre local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 dev "$WAN_DEV" 2>/dev/null; then
      ip addr add "${DIAG_GRE_IRAN}/30" dev "$DIAG_GRE_IF" 2>/dev/null
      ip link set "$DIAG_GRE_IF" mtu 1400 up 2>/dev/null
      sysctl -qw "net.ipv4.conf.${DIAG_GRE_IF}.rp_filter=0" >/dev/null 2>&1
    fi
  fi

  # 2) SIT Proto 41 test responder (if main mode is not already SIT)
  if [[ $MODE != sit ]]; then
    if ip tunnel add "$DIAG_SIT_IF" mode sit local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 dev "$WAN_DEV" 2>/dev/null; then
      ip addr add "${DIAG_SIT_IRAN}/30" dev "$DIAG_SIT_IF" 2>/dev/null
      ip link set "$DIAG_SIT_IF" mtu 1380 up 2>/dev/null
      sysctl -qw "net.ipv4.conf.${DIAG_SIT_IF}.rp_filter=0" >/dev/null 2>&1
    fi
  fi

  # 3) Raw ESP Proto 50 test responder (if main mode is not already Raw ESP)
  if [[ $MODE != esp ]]; then
    local dkey
    dkey=$(kdf "${MASTER}|diag50" | cut -c1-72)
    if ip link add "$DIAG_ESP_IF" type xfrm dev "$WAN_DEV" if_id "$DIAG_IF_ID" 2>/dev/null; then
      ip addr add "${DIAG_ESP_IRAN}/30" dev "$DIAG_ESP_IF" 2>/dev/null
      ip link set "$DIAG_ESP_IF" mtu 1400 up 2>/dev/null
      ip xfrm policy add src "$DIAG_ESP_IRAN/32" dst "$DIAG_ESP_KHAREJ/32" dir out if_id "$DIAG_IF_ID" \
        tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$DIAG_IF_ID" mode tunnel 2>/dev/null
      ip xfrm policy add src "$DIAG_ESP_KHAREJ/32" dst "$DIAG_ESP_IRAN/32" dir in if_id "$DIAG_IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$DIAG_IF_ID" mode tunnel 2>/dev/null
      ip xfrm state add src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp spi 0x19999991 reqid "$DIAG_IF_ID" mode tunnel \
        aead 'rfc4106(gcm(aes))' "0x${dkey}" 128 if_id "$DIAG_IF_ID" 2>/dev/null
      ip xfrm state add src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp spi 0x19999992 reqid "$DIAG_IF_ID" mode tunnel \
        aead 'rfc4106(gcm(aes))' "0x${dkey}" 128 if_id "$DIAG_IF_ID" 2>/dev/null
    fi
  fi

  # 4) UDP probe socket (always running on Iran so ESP-in-UDP test works anytime)
  if [[ $MODE != udp ]]; then
    python3 -c "$PY_UDP" "$UDP_PORT" >/dev/null 2>&1 &
    echo $! > "$DIAG_UDP_PID_FILE"
  fi
}

teardown_all() {
  fw_remove
  udp_helper_stop
  diag_teardown
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null
  carrier_teardown
  return 0
}

setup_all() {
  teardown_all
  mkdir -p "$RUN_DIR"; : > "$REG"
  load_modules
  route_info "$PEER_PUB" || { log "ERROR: no route to peer $PEER_PUB"; return 1; }
  carrier_setup          || return 1
  iface_setup            || return 1

  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  if [[ $MODE == sit ]]; then
    if ! policies_setup || ! install_epoch "$CUR_EPOCH"; then
      setup_sit_direct_fallback || return 1
    fi
  else
    policies_setup             || return 1
    install_epoch "$CUR_EPOCH" || return 1
  fi

  if [[ $MODE == udp ]]; then udp_helper_start || return 1; fi
  apply_tuner_profile "$TUNER"
  fw_apply
  diag_setup_iran
  log "tunnel up: role=$ROLE ${LOCAL_INNER} <-> ${PEER_INNER} transport=$MODE tuner=$TUNER local=$LOCAL_ADDR($WAN_DEV) peer=$PEER_PUB mtu=$MTU epoch=$CUR_EPOCH"
  return 0
}

# ------------------------------------------------------------------------------
#  Protocol Test Benchmark (Run on Kharej Client)
# ------------------------------------------------------------------------------
bench_interface_ping_and_bw() {
  local dev=$1 target_ip=$2 out loss avg jitter bw_mbps rtt_line
  out=$(ping -c 6 -i 0.2 -W 1 -I "$dev" "$target_ip" 2>&1)
  loss=$(awk -F',' '/packet loss/{gsub(/[^0-9]/,"",$3); print $3}' <<<"$out")
  [[ -z $loss ]] && loss=100
  if (( loss == 100 )); then
    echo "DOWN|-|100%|0.00 Mbps"
    return 1
  fi
  rtt_line=$(awk -F'=' '/rtt|round-trip/{print $2}' <<<"$out" | awk '{print $1}')
  avg=$(cut -d'/' -f2 <<<"$rtt_line")
  jitter=$(cut -d'/' -f4 <<<"$rtt_line")
  [[ -z $avg ]] && avg="0.0"
  [[ -z $jitter ]] && jitter="0.0"

  # Bandwidth / Speed test using high-rate 1300-byte payload burst
  local t_start t_end rx0 rx1 tx0 tx1 dt bytes
  rx0=$(<"/sys/class/net/$dev/statistics/rx_bytes")
  tx0=$(<"/sys/class/net/$dev/statistics/tx_bytes")
  t_start=$(date +%s%3N)
  ping -c 60 -i 0.01 -s 1300 -W 1 -q -I "$dev" "$target_ip" >/dev/null 2>&1 || true
  t_end=$(date +%s%3N)
  rx1=$(<"/sys/class/net/$dev/statistics/rx_bytes")
  tx1=$(<"/sys/class/net/$dev/statistics/tx_bytes")
  dt=$(( t_end - t_start ))
  (( dt <= 0 )) && dt=1000
  bytes=$(( (rx1 - rx0) + (tx1 - tx0) ))
  bw_mbps=$(awk -v b="$bytes" -v ms="$dt" 'BEGIN { printf "%.2f Mbps", (b * 8.0) / (ms * 1000.0) }')
  echo "UP|${avg} ms (jit ${jitter} ms)|${loss}%|${bw_mbps}"
  return 0
}

run_protocol_test() {
  local target_iran=$1 uport=${2:-$DEFAULT_UDP_PORT}
  local was_active=0
  if [[ -z $target_iran ]]; then
    read -r -p "Enter Iran Server Public IP to test protocols: " target_iran
    valid_ip "$target_iran" || { err "Invalid IPv4 address."; return 1; }
  fi
  if ! route_info "$target_iran"; then
    err "No route to Iran server $target_iran."
    return 1
  fi

  if systemctl is-active --quiet "$APP"; then
    was_active=1
    systemctl stop "$APP" >/dev/null 2>&1
  fi

  load_modules
  local mkey dkey
  mkey=$(default_master_key)
  dkey=$(kdf "${mkey}|diag50" | cut -c1-72)
  local cur_ep=$(( $(date +%s) / EPOCH_LEN ))

  echo
  info "Running Live Protocol Benchmark against Iran Server ($target_iran)..."
  info "Testing Reachability, Ping/Jitter, Packet Loss, and Bandwidth..."
  echo

  # Clean any leftover test interfaces
  ip link del "t_esp0" 2>/dev/null
  ip link del "t_gre0" 2>/dev/null
  ip link del "t_sit0" 2>/dev/null

  # --- 1) Test Protocol 50 (Raw ESP) ---
  local res_esp="DOWN|-|100%|0.00 Mbps"
  if ip link add "t_esp0" type xfrm dev "$WAN_DEV" if_id "$DIAG_IF_ID" 2>/dev/null; then
    ip addr add "${DIAG_ESP_KHAREJ}/30" dev "t_esp0" 2>/dev/null
    ip link set "t_esp0" mtu 1400 up 2>/dev/null
    ip xfrm policy add src "$DIAG_ESP_KHAREJ/32" dst "$DIAG_ESP_IRAN/32" dir out if_id "$DIAG_IF_ID" \
      tmpl src "$LOCAL_ADDR" dst "$target_iran" proto esp reqid "$DIAG_IF_ID" mode tunnel 2>/dev/null
    ip xfrm policy add src "$DIAG_ESP_IRAN/32" dst "$DIAG_ESP_KHAREJ/32" dir in if_id "$DIAG_IF_ID" \
      tmpl src "$target_iran" dst "$LOCAL_ADDR" proto esp reqid "$DIAG_IF_ID" mode tunnel 2>/dev/null
    ip xfrm state add src "$LOCAL_ADDR" dst "$target_iran" proto esp spi 0x19999992 reqid "$DIAG_IF_ID" mode tunnel \
      aead 'rfc4106(gcm(aes))' "0x${dkey}" 128 if_id "$DIAG_IF_ID" 2>/dev/null
    ip xfrm state add src "$target_iran" dst "$LOCAL_ADDR" proto esp spi 0x19999991 reqid "$DIAG_IF_ID" mode tunnel \
      aead 'rfc4106(gcm(aes))' "0x${dkey}" 128 if_id "$DIAG_IF_ID" 2>/dev/null
    res_esp=$(bench_interface_ping_and_bw "t_esp0" "$DIAG_ESP_IRAN")
    ip xfrm policy delete src "$DIAG_ESP_KHAREJ/32" dst "$DIAG_ESP_IRAN/32" dir out if_id "$DIAG_IF_ID" 2>/dev/null
    ip xfrm policy delete src "$DIAG_ESP_IRAN/32" dst "$DIAG_ESP_KHAREJ/32" dir in if_id "$DIAG_IF_ID" 2>/dev/null
    ip xfrm state delete src "$LOCAL_ADDR" dst "$target_iran" proto esp spi 0x19999992 2>/dev/null
    ip xfrm state delete src "$target_iran" dst "$LOCAL_ADDR" proto esp spi 0x19999991 2>/dev/null
    ip link del "t_esp0" 2>/dev/null
  fi
  # If main tunnel on Iran is currently set to Raw ESP, also test against 10.10.10.2
  if [[ ${res_esp%%|*} == "DOWN" ]]; then
    local spi_out spi_in key_out key_in
    spi_out="0x1$(kdf "${mkey}|spi|k2i|${cur_ep}" | cut -c1-7)"
    spi_in="0x1$(kdf "${mkey}|spi|i2k|${cur_ep}" | cut -c1-7)"
    key_out=$(kdf "${mkey}|key|k2i|${cur_ep}" | cut -c1-72)
    key_in=$(kdf "${mkey}|key|i2k|${cur_ep}" | cut -c1-72)
    if ip link add "t_esp0" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>/dev/null; then
      ip addr add "${IP_KHAREJ}/30" dev "t_esp0" 2>/dev/null
      ip link set "t_esp0" mtu 1400 up 2>/dev/null
      ip xfrm policy add src "$IP_KHAREJ/32" dst "$IP_IRAN/32" dir out if_id "$IF_ID" \
        tmpl src "$LOCAL_ADDR" dst "$target_iran" proto esp reqid "$IF_ID" mode tunnel 2>/dev/null
      ip xfrm policy add src "$IP_IRAN/32" dst "$IP_KHAREJ/32" dir in if_id "$IF_ID" \
        tmpl src "$target_iran" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>/dev/null
      ip xfrm state add src "$LOCAL_ADDR" dst "$target_iran" proto esp spi "$spi_out" reqid "$IF_ID" mode tunnel \
        aead 'rfc4106(gcm(aes))' "0x${key_out}" 128 if_id "$IF_ID" 2>/dev/null
      ip xfrm state add src "$target_iran" dst "$LOCAL_ADDR" proto esp spi "$spi_in" reqid "$IF_ID" mode tunnel \
        aead 'rfc4106(gcm(aes))' "0x${key_in}" 128 if_id "$IF_ID" 2>/dev/null
      res_esp=$(bench_interface_ping_and_bw "t_esp0" "$IP_IRAN")
      ip xfrm policy delete src "$IP_KHAREJ/32" dst "$IP_IRAN/32" dir out if_id "$IF_ID" 2>/dev/null
      ip xfrm policy delete src "$IP_IRAN/32" dst "$IP_KHAREJ/32" dir in if_id "$IF_ID" 2>/dev/null
      ip xfrm state delete src "$LOCAL_ADDR" dst "$target_iran" proto esp spi "$spi_out" 2>/dev/null
      ip xfrm state delete src "$target_iran" dst "$LOCAL_ADDR" proto esp spi "$spi_in" 2>/dev/null
      ip link del "t_esp0" 2>/dev/null
    fi
  fi

  # --- 2) Test Protocol 47 (GRE) ---
  local res_gre="DOWN|-|100%|0.00 Mbps"
  if ip tunnel add "t_gre0" mode gre local "$LOCAL_ADDR" remote "$target_iran" ttl 64 dev "$WAN_DEV" 2>/dev/null; then
    ip addr add "${DIAG_GRE_KHAREJ}/30" dev "t_gre0" 2>/dev/null
    ip addr add "${GRE_KHAREJ}/30" dev "t_gre0" 2>/dev/null
    ip link set "t_gre0" mtu 1400 up 2>/dev/null
    sysctl -qw "net.ipv4.conf.t_gre0.rp_filter=0" >/dev/null 2>&1
    res_gre=$(bench_interface_ping_and_bw "t_gre0" "$DIAG_GRE_IRAN")
    if [[ ${res_gre%%|*} == "DOWN" ]]; then
      res_gre=$(bench_interface_ping_and_bw "t_gre0" "$GRE_IRAN")
    fi
    ip link del "t_gre0" 2>/dev/null
  fi

  # --- 3) Test Protocol 41 (SIT / 6in4) ---
  local res_sit="DOWN|-|100%|0.00 Mbps"
  if ip tunnel add "t_sit0" mode sit local "$LOCAL_ADDR" remote "$target_iran" ttl 64 dev "$WAN_DEV" 2>/dev/null; then
    sysctl -qw "net.ipv6.conf.t_sit0.disable_ipv6=0" >/dev/null 2>&1
    ip addr add "${DIAG_SIT_KHAREJ}/30" dev "t_sit0" 2>/dev/null
    ip addr add "${IP_KHAREJ}/30" dev "t_sit0" 2>/dev/null
    ip -6 addr add "${SIT_KHAREJ}/64" dev "t_sit0" 2>/dev/null
    ip link set "t_sit0" mtu 1380 up 2>/dev/null
    sysctl -qw "net.ipv4.conf.t_sit0.rp_filter=0" >/dev/null 2>&1
    res_sit=$(bench_interface_ping_and_bw "t_sit0" "$DIAG_SIT_IRAN")
    if [[ ${res_sit%%|*} == "DOWN" ]]; then
      res_sit=$(bench_interface_ping_and_bw "t_sit0" "$SIT_IRAN")
    fi
    if [[ ${res_sit%%|*} == "DOWN" ]]; then
      res_sit=$(bench_interface_ping_and_bw "t_sit0" "$IP_IRAN")
    fi
    ip link del "t_sit0" 2>/dev/null
  fi

  # --- 4) Test ESP-in-UDP ---
  local res_udp="DOWN|-|100%|0.00 Mbps"
  res_udp=$(python3 - "$target_iran" "$uport" <<'PYEOF'
import socket, sys, time, statistics

host = sys.argv[1]
port = int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.8)
rtts = []
sent = 8
for i in range(sent):
    payload = b"ESPT_PROBE:" + str(i).encode() + b":" + (b"X" * 1200)
    t0 = time.perf_counter()
    try:
        s.sendto(payload, (host, port))
        data, _ = s.recvfrom(2048)
        if data.startswith(b"ESPT_PROBE:"):
            rtts.append((time.perf_counter() - t0) * 1000.0)
    except Exception:
        pass

if not rtts:
    print("DOWN|-|100%|0.00 Mbps")
    sys.exit(0)

loss = int(round((1.0 - len(rtts) / sent) * 100))
avg = statistics.mean(rtts)
jit = statistics.stdev(rtts) if len(rtts) > 1 else 0.0

# Burst speed test
s.settimeout(0.3)
burst = 50
b_ok = 0
pkt = b"ESPT_PROBE:BW:" + (b"Z" * 1300)
t_start = time.perf_counter()
for _ in range(burst):
    try:
        s.sendto(pkt, (host, port))
        data, _ = s.recvfrom(2048)
        if data:
            b_ok += 1
    except Exception:
        pass
dt = max(time.perf_counter() - t_start, 0.001)
mbps = ((b_ok * len(pkt) * 2 * 8) / dt) / 1e6
print(f"UP|{avg:.2f} ms (jit {jit:.2f} ms)|{loss}%|{mbps:.2f} Mbps")
PYEOF
  )

  if (( was_active )); then
    systemctl start "$APP" >/dev/null 2>&1
  fi

  echo "${C_B}========================================================================================${C_0}"
  printf "${C_Y}%-4s | %-24s | %-8s | %-24s | %-7s | %-12s${C_0}\n" "Opt" "Protocol / Transport" "Status" "Ping & Jitter" "Loss" "Est. Speed"
  echo "${C_B}----------------------------------------------------------------------------------------${C_0}"

  local idx=1 name row st pg ls bw
  for row in \
    "1|Raw ESP (Proto 50)|$res_esp" \
    "2|GRE + ESP (Proto 47)|$res_gre" \
    "3|SIT + ESP (Proto 41)|$res_sit" \
    "4|ESP-in-UDP (Port $uport)|$res_udp"; do
    IFS='|' read -r idx name st pg ls bw <<<"$row"
    if [[ $st == "UP" ]]; then
      printf " %-3s | %-24s | ${C_G}%-8s${C_0} | %-24s | %-7s | ${C_G}%-12s${C_0}\n" "$idx" "$name" "$st" "$pg" "$ls" "$bw"
    else
      printf " %-3s | %-24s | ${C_R}%-8s${C_0} | %-24s | %-7s | %-12s\n" "$idx" "$name" "$st" "$pg" "$ls" "$bw"
    fi
  done
  echo "${C_B}========================================================================================${C_0}"
  echo
}

# ------------------------------------------------------------------------------
#  Daemon (runs under systemd): setup, hourly key rotation, auto-restart & packet-loss watchdog
# ------------------------------------------------------------------------------
cmd_daemon() {
  local tries=0 fails=0 loss_strikes=0 last_fix=0 peer_state="unknown" e now start_ts
  local ping_out pkt_loss
  load_config || { log "ERROR: missing or invalid $CONF"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB after 60s"; exit 1; }
    sleep 2
  done
  sync_clock >/dev/null 2>&1 || true
  setup_all || { log "ERROR: setup failed"; exit 1; }
  start_ts=$(date +%s)

  while true; do
    sleep 5 &
    wait $!

    now=$(date +%s)

    # --- Scheduled Auto-Restart (TUNNEL RESTART timer) ---
    if (( RESTART_MINS > 0 && (now - start_ts) >= (RESTART_MINS * 60) )); then
      log "Scheduled TUNNEL RESTART triggered (interval: ${RESTART_MINS} min)"
      sync_clock >/dev/null 2>&1 || true
      route_info "$PEER_PUB" && setup_all
      start_ts=$(date +%s)
      fails=0; loss_strikes=0
      continue
    fi

    # --- Hourly key rotation (make-before-break, no packet loss) ---
    e=$(( now / EPOCH_LEN ))
    if (( e != CUR_EPOCH )); then
      log "key rotation: epoch $CUR_EPOCH -> $e"
      if install_epoch "$e"; then CUR_EPOCH=$e; else log "WARN: key rotation failed, will retry"; fi
    fi

    # --- Smart Watchdog (Interface + Disconnection + Packet Loss) ---
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      log "WARN: interface $IF_NAME vanished - rebuilding immediately"
      route_info "$PEER_PUB" && setup_all
      continue
    fi

    ping_out=$(ping -c 4 -i 0.25 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1)
    pkt_loss=$(awk -F',' '/packet loss/{gsub(/[^0-9]/,"",$3); print $3}' <<<"$ping_out")
    [[ -z $pkt_loss ]] && pkt_loss=100

    if (( pkt_loss == 0 )); then
      if [[ $peer_state != up ]]; then log "peer $PEER_INNER healthy (0% loss) - tunnel UP"; fi
      peer_state=up; fails=0; loss_strikes=0
    elif (( pkt_loss < 100 )); then
      # Partial packet loss detected
      fails=0
      if (( pkt_loss >= WatchdogLossThreshold )); then
        loss_strikes=$(( loss_strikes + 1 ))
        log "WARN: watchdog detected ${pkt_loss}% packet loss on $IF_NAME (strike ${loss_strikes}/3)"
        if (( loss_strikes >= 3 && (now - last_fix) >= 45 )); then
          log "WATCHDOG: healing tunnel due to persistent packet loss (${pkt_loss}%)"
          last_fix=$now
          loss_strikes=0
          sync_clock >/dev/null 2>&1 || true
          route_info "$PEER_PUB" && setup_all
        fi
      else
        loss_strikes=0
      fi
    else
      # 100% packet loss (complete disconnection)
      fails=$(( fails + 1 ))
      if (( fails == 2 )); then
        peer_state=down
        log "WARN: peer $PEER_INNER unreachable (100% packet loss) - refreshing SAs & firewall"
        install_epoch "$CUR_EPOCH" >/dev/null 2>&1 || true
        fw_apply >/dev/null 2>&1 || true
      fi
      if (( fails >= 5 )); then
        if (( now - last_fix >= 30 )); then
          log "WATCHDOG: peer unreachable - full tunnel rebuild triggered"
          last_fix=$now
          sync_clock >/dev/null 2>&1 || true
          route_info "$PEER_PUB" && setup_all
        fi
        fails=2
      fi
    fi
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }

cmd_fw() {
  load_config || exit 1
  route_info "$PEER_PUB" || exit 1
  fw_apply
  log "firewall / port-forward rules reloaded"
}

# ------------------------------------------------------------------------------
#  Installation & Interactive Prompts
# ------------------------------------------------------------------------------
install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  if [[ ! -f $src ]]; then
    err "Save this script to a file first (bash esp-tunnel.sh); it cannot install itself from a pipe."
    return 1
  fi
  if [[ $src != "$BIN" ]]; then
    install -m 755 "$src" "$BIN" || return 1
  fi
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP Multi-Protocol Tunnel (${APP})
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecStopPost=${BIN} teardown
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  write_unit
  systemctl daemon-reload
  systemctl enable "$APP" >/dev/null 2>&1
  systemctl restart "$APP"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    [[ -s $REG ]] && ip link show "$IF_NAME" >/dev/null 2>&1 && break
  done
  if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service is running (auto-starts on boot)."
    return 0
  fi
  err "Service failed to start. Last log lines:"
  journalctl -u "$APP" -n 25 --no-pager
  return 1
}

confirm_reinstall() {
  if load_config 2>/dev/null; then
    warn "A tunnel is already configured on this server (role: $ROLE)."
    confirm "Re-install and overwrite it?" y || return 1
  fi
  return 0
}

ask_ports() {
  local raw norm p spec
  local -a sp=()
  while true; do
    read -r -p "Ports to forward through the tunnel (comma separated, e.g. 1080,443,8000-8100): " raw
    if ! norm=$(norm_ports "$raw"); then
      err "Invalid list. Use numbers 1-65535 separated by commas (ranges like 8000-8100 are allowed)."
      continue
    fi
    for p in $(ssh_ports); do
      [[ $p =~ ^[0-9]+$ ]] || continue
      if ports_include "$norm" "$p"; then
        err "Port $p is the SSH port of this server - forwarding it would lock you out. Remove it."
        continue 2
      fi
    done
    PORTS=$norm
    break
  done
  IFS=',' read -ra sp <<< "$PORTS"
  for spec in "${sp[@]}"; do
    [[ $spec == *-* ]] && continue
    if [[ -n $(ss -Hltun "sport = :$spec" 2>/dev/null) ]]; then
      warn "Port $spec is already used by a local service here; after forwarding, connections to it will go to Kharej instead."
    fi
  done
}

ask_transport() {
  local allow_test=${1:-0} target_ip=${2:-} c
  while true; do
    echo
    echo "Select Tunnel Transport Protocol:"
    echo "  1) Raw ESP - IP Protocol 50       (Fastest, lowest overhead)"
    echo "  2) GRE + ESP - IP Protocol 47     (Bypass firewall/DPI on Proto 50 via GRE)"
    echo "  3) SIT + ESP - IP Protocol 41     (Bypass firewall/DPI via IPv6-in-IPv4 Proto 41)"
    echo "  4) ESP-in-UDP                     (NAT / UDP fallback transport)"
    if (( allow_test )); then
      echo "  5) PROTOCOL TEST (Benchmark Ping, Loss & Speed of all protocols from Iran)"
    fi
    read -r -p "Select [1]: " c
    c=${c:-1}
    case $c in
      1) MODE=esp; UDP_PORT=$DEFAULT_UDP_PORT; break ;;
      2) MODE=gre; UDP_PORT=$DEFAULT_UDP_PORT; break ;;
      3) MODE=sit; UDP_PORT=$DEFAULT_UDP_PORT; break ;;
      4)
        MODE=udp
        while true; do
          read -r -p "UDP port for ESP-in-UDP [${DEFAULT_UDP_PORT}]: " UDP_PORT
          UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}
          valid_port "$UDP_PORT" && break
          err "Invalid port."
        done
        break
        ;;
      5)
        if (( allow_test )); then
          run_protocol_test "$target_ip" "$DEFAULT_UDP_PORT"
          continue
        fi
        err "Invalid selection."
        ;;
      *) err "Invalid selection." ;;
    esac
  done
}

ask_tuner() {
  local c
  echo
  echo "Select Network TUNER Profile:"
  echo "  1) GAMING      (fq_codel, tcp_low_latency=1, DSCP EF, txqueuelen=1000, rmem/wmem=16MB)"
  echo "  2) FULL SPEED  (BBR + fq, rmem/wmem=64MB, txqueuelen=10000, backlog=65536)"
  echo "  3) BALANCED    (BBR + fq, rmem/wmem=16MB, txqueuelen=4000, backlog=16384) [Default]"
  echo "  4) LATENCY     (LETENCY: busy_poll=50, busy_read=50, fastopen=3, txqueuelen=500, rmem=8MB)"
  read -r -p "Select TUNER [3]: " c
  case ${c:-3} in
    1) TUNER="gaming" ;;
    2) TUNER="full_speed" ;;
    4) TUNER="latency" ;;
    *) TUNER="balanced" ;;
  esac
  ok "Selected TUNER profile: ${TUNER^^}"
}

ask_restart_timer() {
  local raw
  echo
  echo "Auto-Restart Timer (TUNNEL RESTART):"
  echo "  Enter interval in minutes (e.g. 60 = every 1h, 180 = every 3h, or 0 to disable)"
  while true; do
    read -r -p "Auto-restart interval in minutes [0]: " raw
    raw=${raw:-0}
    if [[ $raw =~ ^[0-9]+$ ]]; then
      RESTART_MINS=$((10#$raw))
      break
    fi
    err "Please enter a valid number of minutes (0 or higher)."
  done
  if (( RESTART_MINS > 0 )); then
    ok "Tunnel will automatically restart every ${RESTART_MINS} minutes."
  else
    info "Scheduled auto-restart disabled (Watchdog auto-heal remains active 24/7)."
  fi
}

ask_fwd_proto() {
  local c
  echo
  echo "Forward which protocol on those ports?"
  echo "  1) TCP + UDP (default)   2) TCP only   3) UDP only"
  read -r -p "Select [1]: " c
  case $c in 2) FWD_PROTO=tcp ;; 3) FWD_PROTO=udp ;; *) FWD_PROTO=both ;; esac
}

# ------------------------------------------------------------------------------
#  Menu actions
# ------------------------------------------------------------------------------
setup_iran() {
  local det
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the IRAN server side (tunnel IP ${IP_IRAN} | Default Token: ${DEFAULT_SECRET})"
  ensure_deps  || { pause; return; }
  check_kernel || { pause; return; }
  sync_clock

  det=$(detect_public_ip)
  while true; do
    read -r -p "Iran server public IP [${det}]: " IRAN_IP
    IRAN_IP=${IRAN_IP:-$det}
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done
  while true; do
    read -r -p "Kharej (foreign) server public IP: " KHAREJ_IP
    valid_ip "$KHAREJ_IP" && break
    err "Invalid IPv4 address."
  done
  if ! route_info "$KHAREJ_IP"; then err "No route to $KHAREJ_IP from this server."; pause; return; fi

  ask_transport 0 "$KHAREJ_IP"
  ask_tuner
  ask_restart_timer
  echo
  ask_ports
  ask_fwd_proto

  ROLE=iran
  MASTER=$(default_master_key)
  write_config
  load_config
  start_service || { pause; return; }

  echo
  ok "Iran Server configured with Default Shared Key (${DEFAULT_SECRET}) - no token needed on Kharej!"
  echo "Forwarding: [${PORTS}] (${FWD_PROTO}) on this server  ->  ${IP_KHAREJ} through the tunnel."
  echo "Transport : ${MODE^^}  |  TUNER: ${TUNER^^}  |  Auto-Restart: ${RESTART_MINS} min"
  echo
  pause
}

setup_kharej() {
  local det
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the KHAREJ client side (tunnel IP ${IP_KHAREJ} | Default Token: ${DEFAULT_SECRET})"
  ensure_deps  || { pause; return; }
  check_kernel || { pause; return; }
  sync_clock

  while true; do
    read -r -p "Iran server public IP: " IRAN_IP
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done
  if ! route_info "$IRAN_IP"; then err "No route to Iran server $IRAN_IP."; pause; return; fi

  det=$(detect_public_ip)
  while true; do
    read -r -p "Kharej (this server) public IP [${det}]: " KHAREJ_IP
    KHAREJ_IP=${KHAREJ_IP:-$det}
    valid_ip "$KHAREJ_IP" && break
    err "Invalid IPv4 address."
  done

  ask_transport 1 "$IRAN_IP"
  ask_tuner
  ask_restart_timer

  ROLE=kharej
  MASTER=$(default_master_key)
  PORTS="443"
  FWD_PROTO="both"

  write_config
  load_config
  start_service || { pause; return; }

  echo
  info "Testing the tunnel (5 pings to ${PEER_INNER})..."
  ping -c 5 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 3
  echo
  ok "Kharej Client connected using Default Shared Key (${DEFAULT_SECRET})."
  echo "Transport : ${MODE^^}  |  TUNER: ${TUNER^^}  |  Auto-Restart: ${RESTART_MINS} min"
  echo
  pause
}

cmd_status() {
  local st epoch left line proto_desc
  if ! load_config 2>/dev/null; then
    warn "Tunnel is not installed. Use menu option 1 (Iran) or 2 (Kharej)."
    return
  fi
  st=$(systemctl is-active "$APP" 2>/dev/null)
  epoch=$(( $(date +%s) / EPOCH_LEN ))
  left=$(( EPOCH_LEN - $(date +%s) % EPOCH_LEN ))

  case $MODE in
    udp) proto_desc="ESP-in-UDP (UDP port $UDP_PORT)" ;;
    gre) proto_desc="GRE + ESP (IP Protocol 47)" ;;
    sit) proto_desc="SIT 6in4 + ESP (IP Protocol 41)" ;;
    *)   proto_desc="Raw ESP (IP Protocol 50)" ;;
  esac

  echo "${C_B}===================== ESP Tunnel Status =====================${C_0}"
  echo "Role          : $ROLE   (${LOCAL_INNER}  <->  ${PEER_INNER})"
  echo "Peer public IP: $PEER_PUB"
  echo "Shared Secret : Default (${DEFAULT_SECRET})"
  echo "Transport     : $proto_desc"
  echo "TUNER Profile : ${TUNER^^}"
  echo "Auto-Restart  : $( (( RESTART_MINS > 0 )) && echo "Every ${RESTART_MINS} min" || echo "Disabled (Watchdog active)" )"
  echo "UTC Clock     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "Cipher        : AES-256-GCM, MTU $MTU, next key rotation in $((left / 60)) min (epoch $epoch)"
  if [[ $st == active ]]; then echo "Service       : ${C_G}active${C_0}"; else echo "Service       : ${C_R}${st}${C_0}"; fi

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    echo "Interface     : $(ip -br addr show "$IF_NAME" | awk '{print $1, $2, $3}')"
  else
    echo "Interface     : ${C_R}$IF_NAME missing${C_0}"
  fi
  echo "Loaded SAs    : $(wc -l < "$REG" 2>/dev/null || echo 0)"
  echo
  echo "--- Ping through the tunnel (10 packets) ---"
  ping -c 10 -i 0.2 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
  echo
  echo "--- Interface counters ---"
  ip -s link show "$IF_NAME" 2>/dev/null | sed -n '3,6p'
  echo
  line=$(awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null)
  if [[ -n $line ]]; then
    echo "XFRM counters (non-zero = drops/errors): $line"
  else
    echo "XFRM counters : clean (no errors)"
  fi
  if [[ $ROLE == iran ]]; then
    echo
    echo "--- Forwarded ports (${FWD_PROTO}) : [${PORTS}] -> ${IP_KHAREJ} ---"
    iptables -t nat -vnL ESPT_PRE 2>/dev/null | sed -n '2,$p'
  fi
}

live_counters() {
  local stop=0 rx0 tx0 rp0 tp0 rx tx rp tp x0 x
  trap 'stop=1' INT
  rx0=$(<"/sys/class/net/$IF_NAME/statistics/rx_bytes");   tx0=$(<"/sys/class/net/$IF_NAME/statistics/tx_bytes")
  rp0=$(<"/sys/class/net/$IF_NAME/statistics/rx_packets"); tp0=$(<"/sys/class/net/$IF_NAME/statistics/tx_packets")
  x0=$(awk '{s+=$2} END{print s+0}' /proc/net/xfrm_stat 2>/dev/null)
  echo "Live traffic on $IF_NAME (Ctrl+C to stop)"
  while (( ! stop )); do
    sleep 1
    rx=$(<"/sys/class/net/$IF_NAME/statistics/rx_bytes");   tx=$(<"/sys/class/net/$IF_NAME/statistics/tx_bytes")
    rp=$(<"/sys/class/net/$IF_NAME/statistics/rx_packets"); tp=$(<"/sys/class/net/$IF_NAME/statistics/tx_packets")
    x=$(awk '{s+=$2} END{print s+0}' /proc/net/xfrm_stat 2>/dev/null)
    printf '%s  RX %7d kbit/s %6d pps | TX %7d kbit/s %6d pps | xfrm errors +%d\n' \
      "$(date +%T)" $(( (rx - rx0) * 8 / 1000 )) $(( rp - rp0 )) $(( (tx - tx0) * 8 / 1000 )) $(( tp - tp0 )) $(( x - x0 ))
    rx0=$rx; tx0=$tx; rp0=$rp; tp0=$tp; x0=$x
  done
  trap - INT
}

live_log() {
  local c
  if ! load_config 2>/dev/null; then warn "Tunnel is not installed."; return; fi
  echo
  echo "Live Log:"
  echo "  1) Service & Watchdog log (events, key rotations, packet-loss heal)"
  echo "  2) Live ping monitor (packet loss + latency/jitter through the tunnel)"
  echo "  3) Live traffic counters (kbit/s, pps, errors)"
  read -r -p "Select [1]: " c
  case ${c:-1} in
    1) echo "(Ctrl+C to return)"; trap ':' INT; journalctl -u "$APP" -f -n 40 --no-pager; trap - INT ;;
    2) echo "(Ctrl+C to stop and see the summary)"; trap ':' INT; ping -O -i 0.5 -I "$IF_NAME" "$PEER_INNER"; trap - INT ;;
    3) live_counters ;;
    *) warn "Invalid choice." ;;
  esac
}

uninstall_all() {
  confirm "Remove the tunnel completely (service, interface, keys, firewall rules)?" n || return
  systemctl disable --now "$APP" >/dev/null 2>&1
  teardown_all
  rm -f "$UNIT_FILE" "$SYSCTL_FILE"
  rm -rf "$CONF_DIR" "$RUN_DIR"
  systemctl daemon-reload
  systemctl reset-failed "$APP" 2>/dev/null
  rm -f "$BIN"
  ok "Tunnel fully removed."
}

change_ports() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  if [[ $ROLE != iran ]]; then warn "Ports are configured on the Iran server only."; return; fi
  info "Current ports: [${PORTS}] (${FWD_PROTO})"
  ask_ports
  ask_fwd_proto
  write_config
  if systemctl is-active --quiet "$APP"; then
    "$BIN" fw && ok "New ports are active."
  fi
}

change_tuner() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  info "Current TUNER profile: ${TUNER^^}"
  ask_tuner
  write_config
  apply_tuner_profile "$TUNER"
  ok "TUNER profile '${TUNER^^}' applied immediately."
}

configure_tunnel_restart() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  info "Current Auto-Restart interval: ${RESTART_MINS} minutes"
  ask_restart_timer
  write_config
  systemctl restart "$APP" && ok "Tunnel restarted and new timer (${RESTART_MINS} min) is active."
}

banner() {
  [[ -t 1 ]] && clear
  echo "${C_B}====================================================================${C_0}"
  echo "${C_B}   ESP Tunnel Manager v${VERSION}  -  Proto 50 / 47 (GRE) / 41 (SIT) / UDP${C_0}"
  echo "${C_B}   Iran ${IP_IRAN}  <=======  ESP (Key: ${DEFAULT_SECRET})  =======>  Kharej ${IP_KHAREJ}${C_0}"
  echo "${C_B}====================================================================${C_0}"
  if load_config 2>/dev/null; then
    echo " Role: $ROLE | Mode: ${MODE^^} | TUNER: ${TUNER^^} | Restart: ${RESTART_MINS}m | State: $(systemctl is-active "$APP" 2>/dev/null)"
  else
    echo " Not installed yet."
  fi
  echo
}

menu() {
  local ch
  while true; do
    banner
    echo "  1) Tunnel Set Iran Server"
    echo "  2) Tunnel Set Client (Kharej)"
    echo "  3) Status Tunnel"
    echo "  4) Live Log & Watchdog Monitor"
    echo "  5) Uninstall Full Tunnel"
    echo "  ------------------------------------"
    echo "  6) Change Forwarded Ports (Iran)"
    echo "  7) PROTOCOL TEST (Ping / Loss / Bandwidth Benchmark)"
    echo "  8) Change TUNER Profile (GAMING / FULL SPEED / BALANCED / LATENCY)"
    echo "  9) TUNNEL RESTART (Set Auto-Restart Timer / Restart Now)"
    echo " 10) Sync Server Clock (UTC)"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch || exit 0
    echo
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; echo; pause ;;
      4) live_log ;;
      5) uninstall_all; echo; pause ;;
      6) change_ports; echo; pause ;;
      7)
        load_config 2>/dev/null || true
        run_protocol_test "$IRAN_IP" "${UDP_PORT:-$DEFAULT_UDP_PORT}"
        pause
        ;;
      8) change_tuner; echo; pause ;;
      9) configure_tunnel_restart; echo; pause ;;
      10) sync_clock; echo; pause ;;
      0|q|Q) exit 0 ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

usage() {
  echo "Usage: $0 [menu|status|daemon|teardown|fw|test]"
}

main() {
  case "${1:-menu}" in
    menu)     need_root; menu ;;
    status)   need_root; cmd_status ;;
    daemon)   need_root; cmd_daemon ;;
    teardown) need_root; cmd_teardown ;;
    fw)       need_root; cmd_fw ;;
    test)     need_root; load_config 2>/dev/null || true; run_protocol_test "$2" ;;
    *)        usage; exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
