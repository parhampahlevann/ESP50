#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v2.0
#  Resilient XFRM/ESP-in-UDP tunnel with:
#    - non-destructive watchdog / self-healing
#    - deterministic epoch key rotation
#    - deterministic UDP port rotation with receive window
#    - XFRM SA sequence persistence across rebuilds
#    - XFRM / firewall / route diagnostics
#    - automatic failover to the next epoch before hard rebuild
#
#  Roles:
#    Iran  = forwarding/server side
#    Kharej = peer/client side
#
#  Compatibility:
#    Existing /etc/esp-tunnel/config is reused when present.
# ==============================================================================

set -o pipefail

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
UDP_LOG="${RUN_DIR}/udp-helper.log"

STATE_DIR="/var/lib/${APP}"
SEQ_FILE="${STATE_DIR}/out-oseq"

# ---- Shared configuration ----
# Existing installations keep their existing MASTER from /etc/esp-tunnel/config.
# For fresh installs, replace this constant with your own shared secret and use
# the same value on BOTH servers.
STATIC_MASTER="e7d8f3c1a4b92850d6e1749c3b8a1052f9c4e7b8a1d2e3f4c5b6a78901234567"

DEFAULT_UDP_PORT=39540
DEFAULT_MODE="udp"
DEFAULT_PORTS="443,80,2053,2083,2087,2096,8443"

# ---- Inner tunnel ----
IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30

# ---- Crypto / timing ----
EPOCH_LEN=3600
MTU_ESP=1400
MTU_UDP=1360
REPLAY_WINDOW=2048

# Save outbound XFRM sequence and jump it forward on hard rebuild.
# This prevents restarting the same SA at sequence 0.
SEQ_BUMP=134217728

# ---- UDP port rotation ----
PORT_ROTATION=1
PORT_MIN=24000
PORT_MAX=29999
PORT_RADIUS=2
DEFAULT_PORT_FAILOVER_AFTER=90

# ---- Watchdog ----
DEFAULT_RX_STALL_SEC=90
DEFAULT_HARD_REBUILD_AFTER=240
PING_INTERVAL=5
PING_FAILS=6

# ---- Runtime variables ----
ROLE=""
MASTER="$STATIC_MASTER"

IRAN_IP=""
KHAREJ_IP=""

MODE="$DEFAULT_MODE"
UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""
FWD_PROTO="both"

LOCAL_INNER=""
PEER_INNER=""
PEER_PUB=""

OUT_LABEL=""
IN_LABEL=""

MTU="$MTU_UDP"
LOCAL_ADDR=""
WAN_DEV=""

CUR_EPOCH=0
ACTIVE_OUT_EPOCH=0

RX0=0
TX0=0
RX_STALL_START=0
LAST_DIAG=0
FAILS=0
FAIL_START=0

HARD_REBUILD_AFTER="${DEFAULT_HARD_REBUILD_AFTER}"
RX_STALL_SEC="${DEFAULT_RX_STALL_SEC}"
PORT_FAILOVER_AFTER="${DEFAULT_PORT_FAILOVER_AFTER}"

XPREV=""

# ------------------------------------------------------------------------------
# Embedded UDP encap helper
# ------------------------------------------------------------------------------
PY_UDP='
import select
import socket
import sys
import time

UDP_ENCAP = 100
UDP_ENCAP_ESPINUDP = 2

ports = []
for raw in sys.argv[1:]:
    p = int(raw)
    if p not in ports:
        ports.append(p)

socks = []
for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    s.setsockopt(socket.IPPROTO_UDP, UDP_ENCAP, UDP_ENCAP_ESPINUDP)
    s.bind(("0.0.0.0", port))
    socks.append(s)

if not socks:
    raise SystemExit("no UDP ports configured")

while True:
    try:
        readable, _, _ = select.select(socks, [], [], 30.0)
        for s in readable:
            try:
                s.recvfrom(65535)
            except Exception:
                pass
    except InterruptedError:
        pass
    except Exception:
        time.sleep(0.2)
'

# ------------------------------------------------------------------------------
# UI
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'
  C_G=$'\e[1;32m'
  C_Y=$'\e[1;33m'
  C_B=$'\e[1;36m'
  C_M=$'\e[1;35m'
  C_0=$'\e[0m'
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
    err "Please run as root."
    exit 1
  fi
}

confirm() {
  local def=${2:-n}
  local a
  local p="[y/N]"
  [[ $def == y ]] && p="[Y/n]"
  read -r -p "$1 $p " a
  a=${a:-$def}
  [[ $a =~ ^[Yy] ]]
}

pause() {
  read -r -p "Press Enter to continue..." _
}

# ------------------------------------------------------------------------------
# Validation / helpers
# ------------------------------------------------------------------------------
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

valid_port() {
  [[ $1 =~ ^[0-9]{1,5}$ ]] &&
    (( 10#$1 >= 1 && 10#$1 <= 65535 ))
}

norm_ports() {
  local raw=${1//[[:space:]]/}
  local spec a b
  local -a out=() specs=()

  raw=${raw//،/,}
  [[ -n $raw ]] || return 1

  IFS=',' read -ra specs <<< "$raw"

  for spec in "${specs[@]}"; do
    [[ -z $spec ]] && continue

    if [[ $spec =~ ^([0-9]+)-([0-9]+)$ ]]; then
      a=${BASH_REMATCH[1]}
      b=${BASH_REMATCH[2]}
      valid_port "$a" && valid_port "$b" &&
        (( 10#$a <= 10#$b )) || return 1
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
    if [[ $spec == *-* ]]; then
      a=${spec%-*}
      b=${spec#*-}
    else
      a=$spec
      b=$spec
    fi
    (( $2 >= a && $2 <= b )) && return 0
  done

  return 1
}

ssh_ports() {
  local p
  if have sshd; then
    p=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
  fi
  [[ -n $p ]] || p=22
  echo "$p"
}

kdf_sha512() {
  printf '%s' "$1" | sha512sum | awk '{print $1}'
}

kdf_sha256() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

epoch_port() {
  local e=$1
  local digest n span
  digest=$(kdf_sha256 "${MASTER}|udp-port|${e}" | cut -c1-7)
  span=$((PORT_MAX - PORT_MIN + 1))
  n=$((16#$digest))
  echo $((PORT_MIN + (n % span)))
}

port_for_epoch() {
  local e=$1
  if [[ "${PORT_ROTATION}" == "1" ]]; then
    epoch_port "$e"
  else
    echo "$UDP_PORT"
  fi
}

epoch_port_list() {
  local center=$1 radius=${2:-$PORT_RADIUS}
  local e p
  local -a ports=()

  for ((e=center-radius; e<=center+radius; e++)); do
    p=$(port_for_epoch "$e")
    ports+=("$p")
  done

  printf '%s\n' "${ports[@]}" | sort -n -u | paste -sd, -
}

is_udp_port_used() {
  local p=$1
  ss -Hlun 2>/dev/null | awk -v p=":$p" '$5 ~ p"$" {found=1} END{exit !found}'
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

  addr=$(ip -4 route get 1.1.1.1 2>/dev/null |
    awk '{for(i=1;i<NF;i++) if($i=="src"){print $(i+1); exit}}')

  if [[ -z $addr ]] || is_private_ip "$addr"; then
    if have curl; then
      pub=$(curl -4 -fsS --max-time 4 https://api.ipify.org 2>/dev/null)
      valid_ip "$pub" && addr=$pub
    fi
  fi

  echo "$addr"
}

# ------------------------------------------------------------------------------
# Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1

  # shellcheck disable=SC1090
  source "$CONF"

  MASTER=${MASTER:-$STATIC_MASTER}
  MODE=${MODE:-$DEFAULT_MODE}
  UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}
  FWD_PROTO=${FWD_PROTO:-both}

  PORT_ROTATION=${PORT_ROTATION:-1}
  PORT_RADIUS=${PORT_RADIUS:-2}
  PORT_MIN=${PORT_MIN:-24000}
  PORT_MAX=${PORT_MAX:-29999}

  HARD_REBUILD_AFTER=${HARD_REBUILD_AFTER:-$DEFAULT_HARD_REBUILD_AFTER}
  RX_STALL_SEC=${RX_STALL_SEC:-$DEFAULT_RX_STALL_SEC}
  PORT_FAILOVER_AFTER=${PORT_FAILOVER_AFTER:-$DEFAULT_PORT_FAILOVER_AFTER}

  case "$ROLE" in
    iran)
      LOCAL_INNER=$IP_IRAN
      PEER_INNER=$IP_KHAREJ
      PEER_PUB=$KHAREJ_IP
      OUT_LABEL=i2k
      IN_LABEL=k2i
      ;;
    kharej)
      LOCAL_INNER=$IP_KHAREJ
      PEER_INNER=$IP_IRAN
      PEER_PUB=$IRAN_IP
      OUT_LABEL=k2i
      IN_LABEL=i2k
      ;;
    *)
      return 1
      ;;
  esac

  [[ -n $MASTER && -n $PEER_PUB ]] || return 1

  if [[ "$MODE" == "udp" ]]; then
    MTU=$MTU_UDP
  else
    MTU=$MTU_ESP
  fi

  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"
  chmod 700 "$CONF_DIR"

  (
    umask 077
    {
      echo "# ${APP} config"
      printf 'ROLE=%q\n' "$ROLE"
      printf 'MASTER=%q\n' "$MASTER"
      printf 'IRAN_IP=%q\n' "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n' "$KHAREJ_IP"
      printf 'MODE=%q\n' "$MODE"
      printf 'UDP_PORT=%q\n' "$UDP_PORT"
      printf 'PORTS=%q\n' "$PORTS"
      printf 'FWD_PROTO=%q\n' "$FWD_PROTO"
      printf 'PORT_ROTATION=%q\n' "$PORT_ROTATION"
      printf 'PORT_RADIUS=%q\n' "$PORT_RADIUS"
      printf 'PORT_MIN=%q\n' "$PORT_MIN"
      printf 'PORT_MAX=%q\n' "$PORT_MAX"
      printf 'RX_STALL_SEC=%q\n' "$RX_STALL_SEC"
      printf 'PORT_FAILOVER_AFTER=%q\n' "$PORT_FAILOVER_AFTER"
      printf 'HARD_REBUILD_AFTER=%q\n' "$HARD_REBUILD_AFTER"
    } > "$CONF"
  )

  chmod 600 "$CONF"
}

# ------------------------------------------------------------------------------
# Dependencies / modules / kernel
# ------------------------------------------------------------------------------
ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()

  have systemctl || {
    err "systemd is required."
    return 1
  }

  for c in ip iptables ping ss sha256sum sha512sum awk head python3 modprobe sysctl; do
    have "$c" || missing+=("$c")
  done

  (( ${#missing[@]} == 0 )) && return 0

  if have apt-get; then
    pm=apt
  elif have dnf; then
    pm=dnf
  elif have yum; then
    pm=yum
  fi

  [[ -n $pm ]] || {
    err "Missing: ${missing[*]}"
    return 1
  }

  for c in "${missing[@]}"; do
    case "$c" in
      ip|ss) pkgs+=(iproute2) ;;
      ping) pkgs+=(iputils-ping) ;;
      iptables) pkgs+=(iptables) ;;
      python3) pkgs+=(python3) ;;
      modprobe) pkgs+=(kmod) ;;
      *) pkgs+=(procps coreutils) ;;
    esac
  done

  # De-duplicate package list.
  mapfile -t pkgs < <(printf '%s\n' "${pkgs[@]}" | awk '!seen[$0]++')

  info "Installing dependencies: ${pkgs[*]}"

  if [[ "$pm" == "apt" ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1 || return 1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1 || return 1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1 || return 1
  fi

  return 0
}

load_modules() {
  local m
  for m in xfrm_interface xfrm_user esp4 gcm aesni_intel nf_conntrack xt_TCPMSS iptable_nat; do
    modprobe -q "$m" 2>/dev/null || true
  done
  return 0
}

check_kernel() {
  local t="espchk0"
  local out

  load_modules
  ip link del "$t" 2>/dev/null || true

  if ! out=$(ip link add "$t" type xfrm dev lo if_id 4242 2>&1); then
    err "Kernel lacks XFRM-interface support: $out"
    return 1
  fi

  ip link del "$t" 2>/dev/null || true
  return 0
}

# ------------------------------------------------------------------------------
# Firewall
# ------------------------------------------------------------------------------
ipt() {
  iptables -w 5 "$@"
}

fw_chain_reset() {
  local table=$1 chain=$2 hook=$3

  while ipt -t "$table" -D "$hook" -j "$chain" 2>/dev/null; do :; done
  ipt -t "$table" -N "$chain" 2>/dev/null || ipt -t "$table" -F "$chain"
  ipt -t "$table" -I "$hook" 1 -j "$chain"
}

fw_chain_remove() {
  local table=$1 chain=$2 hook=$3

  while ipt -t "$table" -D "$hook" -j "$chain" 2>/dev/null; do :; done
  ipt -t "$table" -F "$chain" 2>/dev/null || true
  ipt -t "$table" -X "$chain" 2>/dev/null || true
}

fw_remove() {
  have iptables || return 0

  fw_chain_remove filter ESPT_IN INPUT
  fw_chain_remove filter ESPT_OUT OUTPUT
  fw_chain_remove filter ESPT_FWD FORWARD
  fw_chain_remove mangle ESPT_MSS POSTROUTING
  fw_chain_remove nat ESPT_PRE PREROUTING
  fw_chain_remove nat ESPT_POST POSTROUTING
}

fw_apply() {
  local spec d pr p
  local -a specs=() protos=() uports=()

  IFS=',' read -ra uports <<< "$(epoch_port_list "$CUR_EPOCH" "$PORT_RADIUS")"

  # INPUT: inner interface, and outer ESP-in-UDP/ESP traffic from peer.
  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT

  if [[ "$MODE" == "udp" ]]; then
    for p in "${uports[@]}"; do
      ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$p" -j ACCEPT
    done
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi

  # OUTPUT: important on hosts whose default OUTPUT policy is DROP.
  fw_chain_reset filter ESPT_OUT OUTPUT
  if [[ "$MODE" == "udp" ]]; then
    for p in "${uports[@]}"; do
      ipt -A ESPT_OUT -p udp -d "$PEER_PUB" --dport "$p" -j ACCEPT
    done
  else
    ipt -A ESPT_OUT -p 50 -d "$PEER_PUB" -j ACCEPT
  fi

  # FORWARD: only tunnel interface traffic.
  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  # TCP MSS clamp on egress to the XFRM interface.
  local target_mss=$((MTU - 40))
  (( target_mss < 536 )) && target_mss=536

  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp \
    --tcp-flags SYN,RST SYN --set-mss "$target_mss"

  # Iran side NAT / port forwarding.
  if [[ "$ROLE" == "iran" ]]; then
    fw_chain_reset nat ESPT_PRE PREROUTING
    fw_chain_reset nat ESPT_POST POSTROUTING

    case "$FWD_PROTO" in
      tcp) protos=(tcp) ;;
      udp) protos=(udp) ;;
      *)   protos=(tcp udp) ;;
    esac

    IFS=',' read -ra specs <<< "$PORTS"

    for spec in "${specs[@]}"; do
      [[ -z "$spec" ]] && continue
      d=${spec/-/:}

      for pr in "${protos[@]}"; do
        ipt -t nat -A ESPT_PRE ! -i "$IF_NAME" -p "$pr" \
          --dport "$d" -j DNAT --to-destination "$IP_KHAREJ"
      done
    done

    ipt -t nat -A ESPT_POST -o "$IF_NAME" -d "$IP_KHAREJ" \
      -j SNAT --to-source "$IP_IRAN"
  fi

  return 0
}

# ------------------------------------------------------------------------------
# Sysctl
# ------------------------------------------------------------------------------
sysctl_apply() {
  mkdir -p "$(dirname "$SYSCTL_FILE")"

  cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_udp_timeout = 300
net.netfilter.nf_conntrack_udp_timeout_stream = 300
EOF

  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true

  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------------------
# XFRM interface / policies
# ------------------------------------------------------------------------------
iface_setup() {
  local out

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    # Keep an existing healthy interface.
    ip link set "$IF_NAME" up 2>/dev/null || true
    ip link set "$IF_NAME" mtu "$MTU" 2>/dev/null || true
    sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1 || true
    return 0
  fi

  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
    log "ERROR: cannot create $IF_NAME: $out"
    return 1
  fi

  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || return 1
  ip link set "$IF_NAME" mtu "$MTU" up || return 1

  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1 || true
  return 0
}

policy_del_one() {
  local src=$1 dst=$2 dir=$3

  ip xfrm policy delete src "$src/32" dst "$dst/32" dir "$dir" if_id "$IF_ID" 2>/dev/null || true
}

policies_remove() {
  policy_del_one "$IP_IRAN"   "$IP_KHAREJ" out
  policy_del_one "$IP_KHAREJ" "$IP_IRAN"   out
  policy_del_one "$IP_IRAN"   "$IP_KHAREJ" in
  policy_del_one "$IP_KHAREJ" "$IP_IRAN"   in
  ip xfrm policy delete src "$IP_IRAN/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null || true
  ip xfrm policy delete src "$IP_KHAREJ/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null || true
}

policies_setup() {
  policies_remove

  ip xfrm policy add \
    src "$LOCAL_INNER/32" dst "$PEER_INNER/32" \
    dir out if_id "$IF_ID" \
    tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" \
    proto esp reqid "$IF_ID" mode tunnel \
    priority 1000 >/dev/null 2>&1 || return 1

  ip xfrm policy add \
    src "$PEER_INNER/32" dst "$LOCAL_INNER/32" \
    dir in if_id "$IF_ID" \
    tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" \
    proto esp reqid "$IF_ID" mode tunnel \
    priority 1000 >/dev/null 2>&1 || return 1

  ip xfrm policy add \
    src "$PEER_INNER/32" dst 0.0.0.0/0 \
    dir fwd if_id "$IF_ID" \
    tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" \
    proto esp reqid "$IF_ID" mode tunnel \
    priority 1000 >/dev/null 2>&1 || return 1

  return 0
}

# ------------------------------------------------------------------------------
# XFRM SA sequence persistence
# ------------------------------------------------------------------------------
saved_oseq_for_epoch() {
  local e=$1
  local saved_e saved_oseq saved_spi

  [[ -r "$SEQ_FILE" ]] || return 1

  read -r saved_e saved_oseq saved_spi < "$SEQ_FILE" || return 1

  [[ "$saved_e" == "$e" && "$saved_oseq" =~ ^[0-9]+$ ]] || return 1
  echo "$saved_oseq"
}

state_oseq() {
  local spi=$1
  local result

  result=$(
    ip -s xfrm state list 2>/dev/null |
      awk -v wanted="$spi" '
        $1=="src" {
          found=0
        }
        /proto esp spi/ {
          if (index($0, "spi " wanted) || index($0, "spi " wanted "(")) {
            found=1
          }
        }
        found && /anti-replay context:/ {
          for (i=1; i<=NF; i++) {
            if ($i=="oseq") {
              v=$(i+1)
              gsub(",", "", v)
              gsub("[^0-9A-Fa-fx]", "", v)
              print v
              exit
            }
          }
        }
      '
  )

  [[ -n "$result" ]] || return 1

  if [[ "$result" == 0x* || "$result" == 0X* ]]; then
    printf '%d\n' "$((result))"
  else
    printf '%d\n' "$result"
  fi
}

persist_oseq() {
  local spi oseq

  (( ACTIVE_OUT_EPOCH > 0 )) || return 0
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"

  spi=$(awk -v e="$ACTIVE_OUT_EPOCH" -v d="out" '$1==d && $2==e {print $3; exit}' "$REG" 2>/dev/null)
  [[ -n "$spi" ]] || return 0

  oseq=$(state_oseq "$spi" 2>/dev/null) || return 0

  printf '%s %s %s\n' "$ACTIVE_OUT_EPOCH" "$oseq" "$spi" > "$SEQ_FILE"
  chmod 600 "$SEQ_FILE"
}

# ------------------------------------------------------------------------------
# XFRM SA management
# ------------------------------------------------------------------------------
sa_spi_for() {
  local label=$1 e=$2
  printf '0x1%s\n' "$(kdf_sha512 "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
}

sa_key_for() {
  local label=$1 e=$2
  # 36 bytes = AES-256 key (32 bytes) + RFC4106 salt (4 bytes).
  printf '%s\n' "$(kdf_sha512 "${MASTER}|key|${label}|${e}" | cut -c1-72)"
}

sa_reg_delete() {
  local dir=$1 e=$2
  [[ -f "$REG" ]] || return 0

  awk -v d="$dir" -v ep="$e" '!( $1==d && $2==ep )' "$REG" > "${REG}.tmp"
  mv -f "${REG}.tmp" "$REG"
}

sa_state_exists() {
  local src=$1 dst=$2 spi=$3
  ip xfrm state get src "$src" dst "$dst" proto esp spi "$spi" >/dev/null 2>&1
}

sa_delete_by_rec() {
  local dir=$1 e=$2 spi=$3 src=$4 dst=$5

  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null || true
  sa_reg_delete "$dir" "$e"
}

sa_add() {
  local dir=$1 e=$2
  local src dst label spi key out
  local initial_oseq=""
  local p

  if [[ "$dir" == "out" ]]; then
    src=$LOCAL_ADDR
    dst=$PEER_PUB
    label=$OUT_LABEL
  else
    src=$PEER_PUB
    dst=$LOCAL_ADDR
    label=$IN_LABEL
  fi

  spi=$(sa_spi_for "$label" "$e")
  key=$(sa_key_for "$label" "$e")

  # If REG says it exists, verify the actual kernel SA instead of blindly trusting REG.
  if sa_state_exists "$src" "$dst" "$spi"; then
    grep -q "^$dir $e " "$REG" 2>/dev/null ||
      echo "$dir $e $spi $src $dst" >> "$REG"
    return 0
  fi

  sa_reg_delete "$dir" "$e"

  if [[ "$dir" == "out" ]]; then
    if initial_oseq=$(saved_oseq_for_epoch "$e" 2>/dev/null); then
      initial_oseq=$((initial_oseq + SEQ_BUMP))
    fi
  fi

  local -a args=(
    src "$src"
    dst "$dst"
    proto esp
    spi "$spi"
    reqid "$IF_ID"
    mode tunnel
    replay-window "$REPLAY_WINDOW"
    aead 'rfc4106(gcm(aes))' "0x${key}" 128
  )

  if [[ "$dir" == "in" && "$e" != "" ]]; then
    :
  fi

  if [[ "$MODE" == "udp" ]]; then
    p=$(port_for_epoch "$e")
    args+=(encap espinudp "$p" "$p" 0.0.0.0)
  fi

  if [[ -n "$initial_oseq" ]]; then
    args+=(replay-oseq "0x$(printf '%x' "$initial_oseq")")
  fi

  args+=(if_id "$IF_ID")

  # Remove only the exact state, never flush all ESP states.
  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null || true

  if ! out=$(ip xfrm state add "${args[@]}" 2>&1); then
    log "ERROR: cannot add SA dir=$dir epoch=$e spi=$spi: $out"
    return 1
  fi

  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

prune_sa() {
  local center=$1 active_out=$2
  local dir ep spi src dst keep
  local tmp

  [[ -f "$REG" ]] || return 0

  tmp=$(mktemp)

  while read -r dir ep spi src dst; do
    [[ -n "$spi" ]] || continue

    keep=0

    if [[ "$dir" == "out" ]]; then
      (( ep == active_out )) && keep=1
    else
      # Keep a symmetric receive window around current UTC epoch.
      if (( ep >= center-PORT_RADIUS && ep <= center+PORT_RADIUS )); then
        keep=1
      fi
    fi

    if (( keep )); then
      echo "$dir $ep $spi $src $dst" >> "$tmp"
    else
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null || true
    fi
  done < "$REG"

  mv -f "$tmp" "$REG"
}

install_in_window() {
  local center=$1
  local e

  for ((e=center-PORT_RADIUS; e<=center+PORT_RADIUS; e++)); do
    sa_add in "$e" || return 1
  done

  prune_sa "$center" "$ACTIVE_OUT_EPOCH"
  return 0
}

activate_out_epoch() {
  local e=$1
  local old="${ACTIVE_OUT_EPOCH:-0}"
  local old_spi old_src old_dst

  if (( old == e )); then
    sa_add out "$e" || return 1
    return 0
  fi

  # Install new outbound first. The peer already has this epoch in its receive window.
  sa_add out "$e" || return 1

  if (( old > 0 )); then
    read -r _ _ old_spi old_src old_dst < <(
      awk -v d="out" -v ep="$old" '$1==d && $2==ep {print; exit}' "$REG"
    )
    [[ -n "$old_spi" ]] &&
      ip xfrm state delete src "$old_src" dst "$old_dst" proto esp spi "$old_spi" 2>/dev/null || true
    sa_reg_delete out "$old"
  fi

  ACTIVE_OUT_EPOCH="$e"
  return 0
}

sync_epoch_state() {
  local now_e=$1
  local target=$now_e

  install_in_window "$now_e" || return 1

  if (( ACTIVE_OUT_EPOCH == 0 )); then
    activate_out_epoch "$target" || return 1
  elif (( ACTIVE_OUT_EPOCH < now_e )); then
    activate_out_epoch "$target" || return 1
  fi

  return 0
}

hard_rebuild() {
  persist_oseq
  fw_remove
  udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null || true
  setup_all
}

sa_flush() {
  local dir ep spi src dst

  if [[ -f "$REG" ]]; then
    while read -r dir ep spi src dst; do
      [[ -n "$spi" ]] ||
        continue
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null || true
    done < "$REG"
  fi

  rm -f "$REG"
}

# ------------------------------------------------------------------------------
# UDP helper
# ------------------------------------------------------------------------------
udp_helper_stop() {
  if [[ -f "$UDP_PID_FILE" ]]; then
    local pid
    pid=$(cat "$UDP_PID_FILE" 2>/dev/null || true)

    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      kill "$pid" 2>/dev/null || true
      for _ in {1..10}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
      done
      kill -9 "$pid" 2>/dev/null || true
    fi

    rm -f "$UDP_PID_FILE"
  fi
}

udp_helper_start() {
  local ports="$1"
  local -a plist=()

  IFS=',' read -ra plist <<< "$ports"
  (( ${#plist[@]} > 0 )) || return 1

  udp_helper_stop
  : > "$UDP_LOG"
  chmod 600 "$UDP_LOG"

  # Optional diagnostic: warn about local UDP listeners occupying a rotated port.
  local p
  for p in "${plist[@]}"; do
    if is_udp_port_used "$p"; then
      warn "UDP port $p is already in use locally. Tunnel may not be able to bind it."
    fi
  done

  nohup python3 -c "$PY_UDP" "${plist[@]}" >>"$UDP_LOG" 2>&1 &
  echo $! > "$UDP_PID_FILE"

  sleep 0.5

  if ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
    log "ERROR: UDP helper failed. Ports=$ports"
    tail -n 20 "$UDP_LOG" 2>/dev/null || true
    rm -f "$UDP_PID_FILE"
    return 1
  fi

  return 0
}

udp_ports_current() {
  local e=$1
  epoch_port_list "$e" "$PORT_RADIUS"
}

# ------------------------------------------------------------------------------
# Setup / repair
# ------------------------------------------------------------------------------
setup_all() {
  mkdir -p "$RUN_DIR" "$STATE_DIR"
  chmod 700 "$RUN_DIR" "$STATE_DIR"

  : > "$REG"

  load_modules

  route_info "$PEER_PUB" || {
    log "ERROR: no route to peer $PEER_PUB"
    return 1
  }

  iface_setup || return 1
  policies_setup || return 1

  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  ACTIVE_OUT_EPOCH=0

  install_in_window "$CUR_EPOCH" || return 1
  activate_out_epoch "$CUR_EPOCH" || return 1

  if [[ "$MODE" == "udp" ]]; then
    udp_helper_start "$(udp_ports_current "$CUR_EPOCH")" || return 1
  fi

  sysctl_apply
  fw_apply

  log "tunnel up: $LOCAL_INNER <-> $PEER_INNER mode=$MODE outer_ports=$(udp_ports_current "$CUR_EPOCH") epoch=$CUR_EPOCH"
  return 0
}

soft_runtime_repair() {
  local now_e=$(( $(date +%s) / EPOCH_LEN ))

  route_info "$PEER_PUB" || return 1
  iface_setup || return 1
  policies_setup || return 1

  CUR_EPOCH=$now_e

  if [[ "$MODE" == "udp" ]]; then
    if [[ ! -f "$UDP_PID_FILE" ]] ||
       ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
      udp_helper_start "$(udp_ports_current "$CUR_EPOCH")" || return 1
    fi
  fi

  sync_epoch_state "$CUR_EPOCH" || return 1
  sysctl_apply
  fw_apply

  return 0
}

# ------------------------------------------------------------------------------
# Counters / diagnostics
# ------------------------------------------------------------------------------
if_counters() {
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

xfrm_stat_snapshot() {
  [[ -r /proc/net/xfrm_stat ]] || return 0
  awk '$2 ~ /^[0-9]+$/ {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat
  echo
}

xfrm_state_summary() {
  ip -s xfrm state list nokeys 2>/dev/null |
    awk '
      /^src / {print}
      /proto esp spi/ {print}
      /encap type/ {print}
      /anti-replay context:/ {print}
      /lifetime current:/ {print}
      /stats:/ {getline; print}
    '
}

xfrm_policy_summary() {
  ip -s xfrm policy list 2>/dev/null |
    awk '
      /^src / {print}
      /dir (in|out|fwd)/ {print}
      /priority/ {print}
      /tmpl / {print}
      /index / {print}
    '
}

health_reason() {
  local rx tx
  read -r rx tx <<< "$(if_counters)"

  if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
    echo "interface-missing"
    return
  fi

  if ! route_info "$PEER_PUB"; then
    echo "peer-route-missing"
    return
  fi

  if [[ "$MODE" == "udp" ]] &&
     { [[ ! -f "$UDP_PID_FILE" ]] ||
       ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; }; then
    echo "udp-helper-missing"
    return
  fi

  if (( FAILS >= PING_FAILS )); then
    if (( tx > TX0 && rx == RX0 )); then
      echo "asymmetric-no-rx"
    else
      echo "peer-ping-failed"
    fi
    return
  fi

  echo "ok"
}

log_diagnostics() {
  local now
  now=$(date +%s)

  # Avoid spamming diagnostics on a persistent outage.
  if (( now - LAST_DIAG < 30 )); then
    return
  fi

  LAST_DIAG=$now

  log "---- diagnostic snapshot ----"
  log "health=$(health_reason) role=$ROLE epoch=$CUR_EPOCH active_out=$ACTIVE_OUT_EPOCH"
  log "route=$(ip -4 route get "$PEER_PUB" 2>/dev/null | head -n1)"
  log "iface=$(ip -br addr show "$IF_NAME" 2>/dev/null || true)"
  log "outer_dev=$WAN_DEV outer_local=$LOCAL_ADDR peer_public=$PEER_PUB"
  log "outer_ports=$(udp_ports_current "$CUR_EPOCH")"
  log "if_counters=$(if_counters)"
  log "xfrm_stat=$(xfrm_stat_snapshot)"
  log "xfrm_states:"
  xfrm_state_summary | while IFS= read -r line; do
    [[ -n "$line" ]] && log "  $line"
  done
  log "xfrm_policies:"
  xfrm_policy_summary | while IFS= read -r line; do
    [[ -n "$line" ]] && log "  $line"
  done
  log "udp_sockets:"
  ss -Hlunp 2>/dev/null | grep -E ":($(tr ',' '|' <<< "$(udp_ports_current "$CUR_EPOCH")"))[[:space:]]" |
    head -n 20 | while IFS= read -r line; do
      log "  $line"
    done
  log "---- end diagnostic snapshot ----"
}

cmd_diag() {
  load_config || {
    err "Not installed."
    return 1
  }

  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  route_info "$PEER_PUB" || true

  echo
  echo "=== ESP Tunnel Diagnostic v${VERSION} ==="
  echo "Role:             $ROLE"
  echo "Mode:             $MODE"
  echo "Service:          $(systemctl is-active "$APP" 2>/dev/null || true)"
  echo "Peer public:      $PEER_PUB"
  echo "Local public:     $LOCAL_ADDR"
  echo "WAN device:       $WAN_DEV"
  echo "Tunnel:           $LOCAL_INNER <-> $PEER_INNER"
  echo "Epoch:            $CUR_EPOCH"
  echo "Active OUT epoch: ${ACTIVE_OUT_EPOCH:-unknown}"
  echo "UDP receive ports: $(udp_ports_current "$CUR_EPOCH")"
  echo "Port rotation:    $PORT_ROTATION"
  echo "Port range:       $PORT_MIN-$PORT_MAX"
  echo "RX/TX bytes:      $(if_counters)"
  echo

  echo "--- routes ---"
  ip -4 route show table main
  echo

  echo "--- XFRM state (no keys) ---"
  ip xfrm state list nokeys 2>/dev/null || true
  echo

  echo "--- XFRM policy ---"
  ip xfrm policy list 2>/dev/null || true
  echo

  echo "--- XFRM statistics ---"
  cat /proc/net/xfrm_stat 2>/dev/null || true
  echo

  echo "--- interface ---"
  ip -s link show "$IF_NAME" 2>/dev/null || true
  echo

  echo "--- UDP sockets ---"
  ss -lunp 2>/dev/null | grep -E ":($(tr ',' '|' <<< "$(udp_ports_current "$CUR_EPOCH")"))[[:space:]]" || true
  echo

  echo "--- firewall counters ---"
  iptables -nvL ESPT_IN 2>/dev/null || true
  iptables -nvL ESPT_OUT 2>/dev/null || true
  iptables -nvL ESPT_FWD 2>/dev/null || true
  iptables -t mangle -nvL ESPT_MSS 2>/dev/null || true
  echo

  echo "--- time ---"
  date -u
  if have timedatectl; then
    timedatectl show -p NTPSynchronized -p TimeUSec -p Timezone 2>/dev/null || true
  fi
  echo

  echo "--- kernel ---"
  uname -a
  echo

  echo "--- journal tail ---"
  journalctl -u "$APP" -n 80 --no-pager 2>/dev/null || true
}

# ------------------------------------------------------------------------------
# Watchdog
# ------------------------------------------------------------------------------
watchdog_rebuild() {
  local reason=$1
  local now=$(date +%s)
  local now_e=$(( now / EPOCH_LEN ))
  local next_e=$((now_e + 1))
  local outage_age=0
  local repair_ok=0
  local ping_ok=0

  (( FAIL_START > 0 )) && outage_age=$((now - FAIL_START))

  log "watchdog event: $reason outage=${outage_age}s"
  log_diagnostics

  # 1) Non-destructive runtime repair first.
  if soft_runtime_repair; then
    repair_ok=1
  else
    log "runtime repair failed."
  fi

  if (( repair_ok )); then
    if ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      ping_ok=1
    fi
  fi

  if (( ping_ok )); then
    log "runtime repair restored peer reachability; no destructive rebuild needed."
    FAILS=0
    FAIL_START=0
    RX_STALL_START=0
    read -r RX0 TX0 <<< "$(if_counters)"
    return
  fi

  # If the structural repair itself failed, a full rebuild is the correct response.
  if (( ! repair_ok )); then
    log "structural repair failed; performing full rebuild now."
    if hard_rebuild; then
      FAILS=0
      FAIL_START=0
      RX_STALL_START=0
      read -r RX0 TX0 <<< "$(if_counters)"
    else
      log "ERROR: hard rebuild failed."
    fi
    return
  fi

  # 2) For UDP, change the outbound key/port before destroying the tunnel.
  #    Only move one epoch ahead while the local clock is still within the
  #    peer's receive window.
  if [[ "$MODE" == "udp" ]] && (( FAIL_START > 0 )) &&
     (( outage_age >= PORT_FAILOVER_AFTER )) &&
     (( ACTIVE_OUT_EPOCH <= now_e )); then

    log "attempting deterministic port/key failover: out epoch $ACTIVE_OUT_EPOCH -> $next_e"

    if activate_out_epoch "$next_e"; then
      CUR_EPOCH=$now_e
      fw_apply
      if ! udp_helper_start "$(udp_ports_current "$CUR_EPOCH")"; then
        log "WARN: UDP helper refresh failed after failover."
      fi

      if ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
        log "failover restored peer reachability."
        FAILS=0
        FAIL_START=0
        RX_STALL_START=0
        read -r RX0 TX0 <<< "$(if_counters)"
        return
      fi

      log "failover did not restore peer reachability; retaining new outbound epoch."
      read -r RX0 TX0 <<< "$(if_counters)"
      return
    fi
  fi

  # 3) A destructive rebuild is the last resort after a sustained outage.
  if (( FAIL_START > 0 )) && (( outage_age >= HARD_REBUILD_AFTER )); then
    log "persistent outage beyond ${HARD_REBUILD_AFTER}s; performing hard rebuild."
    if hard_rebuild; then
      FAILS=0
      FAIL_START=0
      RX_STALL_START=0
      read -r RX0 TX0 <<< "$(if_counters)"
      return
    fi
    log "ERROR: hard rebuild failed."
  fi

  # Keep FAIL_START alive so a subsequent watchdog call can reach the failover
  # and hard-rebuild thresholds instead of resetting the outage timer.
  FAILS=0
}

cmd_daemon() {
  local tries=0
  local e now rx tx spi oseq local_out_spi next_e
  local last_oseq_save=0

  load_config || {
    log "ERROR: missing config"
    exit 1
  }

  mkdir -p "$RUN_DIR" "$STATE_DIR"
  chmod 700 "$RUN_DIR" "$STATE_DIR"

  trap 'persist_oseq; log "stop signal received"; exit 0' TERM INT

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && {
      log "ERROR: no route to $PEER_PUB"
      exit 1
    }
    sleep 2
  done

  setup_all || {
    log "ERROR: setup failed"
    exit 1
  }

  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  read -r RX0 TX0 <<< "$(if_counters)"

  while true; do
    sleep "$PING_INTERVAL"
    now=$(date +%s)

    # Save outbound sequence periodically.
    if (( now - last_oseq_save >= PING_INTERVAL )); then
      persist_oseq
      last_oseq_save=$now
    fi

    # 1) Epoch / receive-window maintenance.
    e=$(( now / EPOCH_LEN ))
    CUR_EPOCH=$e

    if ! sync_epoch_state "$e"; then
      log "WARN: epoch sync failed."
    fi

    # 2) UDP helper maintenance.
    if [[ "$MODE" == "udp" ]]; then
      if [[ ! -f "$UDP_PID_FILE" ]] ||
         ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
        log "WARN: UDP helper died; restarting helper only."
        udp_helper_start "$(udp_ports_current "$CUR_EPOCH")" || true
        fw_apply
      fi
    fi

    # 3) Interface / policy structural checks.
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      watchdog_rebuild "interface vanished"
      continue
    fi

    if ! ip xfrm policy list 2>/dev/null |
      grep -q "if_id $IF_ID"; then
      watchdog_rebuild "xfrm policy missing"
      continue
    fi

    # 4) Ensure current outbound state really exists.
    local_out_spi=$(awk -v d="out" -v ep="$ACTIVE_OUT_EPOCH" '$1==d && $2==ep {print $3; exit}' "$REG" 2>/dev/null)
    if [[ -z "$local_out_spi" ]] ||
       ! ip xfrm state list 2>/dev/null | grep -q "spi $local_out_spi"; then
      watchdog_rebuild "outbound SA missing"
      continue
    fi

    # 5) Traffic asymmetry detection.
    read -r rx tx <<< "$(if_counters)"

    if (( tx > TX0 && rx == RX0 )); then
      if (( RX_STALL_START == 0 )); then
        RX_STALL_START=$now
      fi
    else
      RX_STALL_START=0
      RX0=$rx
      TX0=$tx
    fi

    # 6) Health ping. Ping failure alone is not enough for hard teardown.
    if ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      FAILS=0
      FAIL_START=0
      RX_STALL_START=0
    else
      (( FAIL_START == 0 )) && FAIL_START=$now
      FAILS=$((FAILS + 1))

      if (( FAILS >= PING_FAILS )); then
        watchdog_rebuild "peer unreachable by inner keepalive for $((PING_FAILS*PING_INTERVAL))s"
        continue
      fi
    fi

    # 7) Proactive sequence exhaustion protection.
    if (( ACTIVE_OUT_EPOCH > 0 )); then
      spi=$(awk -v d="out" -v ep="$ACTIVE_OUT_EPOCH" '$1==d && $2==ep {print $3; exit}' "$REG" 2>/dev/null)
      if [[ -n "$spi" ]] && oseq=$(state_oseq "$spi" 2>/dev/null); then
        if (( oseq > 3900000000 )); then
          next_e=$((e + 1))
          log "WARN: outbound ESP sequence near 32-bit exhaustion; switching to epoch $next_e"
          if activate_out_epoch "$next_e"; then
            fw_apply
          fi
        fi
      fi
    fi
  done
}

# ------------------------------------------------------------------------------
# Commands / setup
# ------------------------------------------------------------------------------
cmd_teardown() {
  persist_oseq
  fw_remove
  udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null || true
  log "tunnel torn down"
}

cmd_fw() {
  load_config || exit 1
  route_info "$PEER_PUB" || exit 1
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  fw_apply
}

install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  [[ -f "$src" ]] || return 1
  [[ "$src" != "$BIN" ]] && install -m 755 "$src" "$BIN"
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP Tunnel Service (${APP} v${VERSION})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN} daemon
ExecStopPost=${BIN} teardown
Restart=always
RestartSec=3
KillMode=control-group
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF
}

start_service() {
  write_unit
  systemctl daemon-reload
  systemctl enable "$APP" >/dev/null 2>&1
  systemctl restart "$APP"

  sleep 2

  if systemctl is-active --quiet "$APP" &&
     ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service started successfully."
    return 0
  fi

  err "Service failed to start."
  journalctl -u "$APP" -n 50 --no-pager
  return 1
}

ask_ports() {
  local raw norm p

  while true; do
    read -r -p "Ports to forward [${DEFAULT_PORTS}]: " raw
    raw=${raw:-$DEFAULT_PORTS}

    if ! norm=$(norm_ports "$raw"); then
      err "Invalid list format."
      continue
    fi

    for p in $(ssh_ports); do
      if ports_include "$norm" "$p"; then
        err "Port $p is SSH. Forwarding it may lock you out."
        continue 2
      fi
    done

    PORTS=$norm
    break
  done
}

ask_fwd_proto() {
  local c

  echo "Forwarding Protocol:"
  echo "  1) TCP + UDP (default)"
  echo "  2) TCP only"
  echo "  3) UDP only"

  read -r -p "Select [1]: " c

  case "$c" in
    2) FWD_PROTO=tcp ;;
    3) FWD_PROTO=udp ;;
    *) FWD_PROTO=both ;;
  esac
}

setup_iran() {
  confirm_reinstall || return
  install_self || return

  info "Configuring IRAN Server side (10.10.10.2)"

  ensure_deps || return
  check_kernel || return

  local det
  det=$(detect_public_ip)

  read -r -p "Iran Public IP [$det]: " IRAN_IP
  IRAN_IP=${IRAN_IP:-$det}

  valid_ip "$IRAN_IP" || {
    err "Invalid Iran public IPv4."
    return
  }

  while true; do
    read -r -p "Kharej (foreign) Server Public IP: " KHAREJ_IP
    valid_ip "$KHAREJ_IP" && break
    err "Invalid IPv4 address."
  done

  ask_ports
  ask_fwd_proto

  ROLE=iran
  MASTER="$STATIC_MASTER"
  MODE="$DEFAULT_MODE"
  UDP_PORT="$DEFAULT_UDP_PORT"
  PORT_ROTATION=1
  PORT_RADIUS=2
  PORT_MIN=24000
  PORT_MAX=29999
  RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
  PORT_FAILOVER_AFTER="$DEFAULT_PORT_FAILOVER_AFTER"
  HARD_REBUILD_AFTER="$DEFAULT_HARD_REBUILD_AFTER"

  write_config
  load_config
  start_service || return

  echo
  ok "Iran server setup complete."
  echo "Deterministic UDP rotation: ${PORT_MIN}-${PORT_MAX}"
  echo "The peer listens on the current epoch window automatically."
  echo "Run option 2 on Kharej and enter this Iran IP: ${C_Y}${IRAN_IP}${C_0}"
  echo

  pause
}

setup_kharej() {
  confirm_reinstall || return
  install_self || return

  info "Configuring KHAREJ Client side (10.10.10.1)"

  ensure_deps || return
  check_kernel || return

  local det
  det=$(detect_public_ip)

  read -r -p "Kharej Public IP [$det]: " KHAREJ_IP
  KHAREJ_IP=${KHAREJ_IP:-$det}

  valid_ip "$KHAREJ_IP" || {
    err "Invalid Kharej public IPv4."
    return
  }

  while true; do
    read -r -p "Iran Server Public IP: " IRAN_IP
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done

  ROLE=kharej
  MASTER="$STATIC_MASTER"
  MODE="$DEFAULT_MODE"
  UDP_PORT="$DEFAULT_UDP_PORT"
  PORTS=""
  FWD_PROTO="both"
  PORT_ROTATION=1
  PORT_RADIUS=2
  PORT_MIN=24000
  PORT_MAX=29999
  RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
  PORT_FAILOVER_AFTER="$DEFAULT_PORT_FAILOVER_AFTER"
  HARD_REBUILD_AFTER="$DEFAULT_HARD_REBUILD_AFTER"

  write_config
  load_config

  start_service || return

  echo
  info "Testing ping to Iran (${PEER_INNER})..."
  ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER" || true

  echo
  ok "Kharej client setup complete."
  pause
}

confirm_reinstall() {
  if load_config 2>/dev/null; then
    warn "Already configured as $ROLE."
    confirm "Overwrite configuration?" n || return 1
  fi
  return 0
}

cmd_status() {
  load_config || {
    warn "Not installed."
    return 1
  }

  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  route_info "$PEER_PUB" || true

  echo "ESP Tunnel v${VERSION}"
  echo "Role:             $ROLE"
  echo "Mode:             $MODE"
  echo "Service:          $(systemctl is-active "$APP" 2>/dev/null || true)"
  echo "Public peer:      $PEER_PUB"
  echo "WAN device:       $WAN_DEV"
  echo "Tunnel:           $LOCAL_INNER <-> $PEER_INNER"
  echo "Epoch:            $CUR_EPOCH"
  echo "Active OUT epoch: ${ACTIVE_OUT_EPOCH:-unknown}"
  echo "UDP ports:        $(udp_ports_current "$CUR_EPOCH")"
  echo "RX/TX bytes:      $(if_counters)"
  echo "Health reason:    $(health_reason)"
  echo
  ip -br addr show "$IF_NAME" 2>/dev/null || true
  echo
  ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 5 || true
}

uninstall_all() {
  confirm "Remove tunnel completely?" n || return

  systemctl disable --now "$APP" >/dev/null 2>&1 || true
  cmd_teardown

  rm -f "$UNIT_FILE" "$SYSCTL_FILE" "$BIN"
  rm -rf "$CONF_DIR" "$RUN_DIR" "$STATE_DIR"

  systemctl daemon-reload
  ok "Tunnel fully removed."
}

menu() {
  while true; do
    echo
    echo "${C_B}======================================================${C_0}"
    echo "${C_B}       ESP Tunnel Manager v${VERSION}                 ${C_0}"
    echo "${C_B}======================================================${C_0}"
    echo "  1) Setup Iran Server"
    echo "  2) Setup Kharej Client"
    echo "  3) Status & Ping"
    echo "  4) Full Diagnostics"
    echo "  5) Live Journal Log"
    echo "  6) Uninstall"
    echo "  0) Exit"
    echo

    read -r -p "Select: " ch

    case "$ch" in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; pause ;;
      4) cmd_diag; pause ;;
      5) journalctl -u "$APP" -f -n 50 ;;
      6) uninstall_all; pause ;;
      0|q|Q) exit 0 ;;
      *) warn "Invalid selection." ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu)      need_root; menu ;;
    status)    need_root; cmd_status ;;
    diag)      need_root; cmd_diag ;;
    daemon)    need_root; cmd_daemon ;;
    teardown)  need_root; cmd_teardown ;;
    fw)        need_root; cmd_fw ;;
    *)         exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
