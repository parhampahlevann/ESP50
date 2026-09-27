#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager  -  point-to-point tunnel over IP protocol 50 (ESP)
#
#    Iran server   : 10.10.10.2   (menu option 1)
#    Kharej client : 10.10.10.1   (menu option 2)
#
#  How it works
#   * Linux kernel XFRM (IPsec ESP) + an "xfrm interface" (espt0) on each side.
#     No IKE daemon and no handshake: only encrypted ESP packets hit the wire.
#   * Cipher: AES-256-GCM in the kernel (AES-NI accelerated, very light).
#   * One random master key (shown once as a "token" on the Iran server).
#     Per-direction session keys are derived from it and rotate every hour
#     with zero downtime (both sides derive the same keys from the UTC clock;
#     the previous/current/next hour inbound SAs are always loaded).
#   * The Iran server DNATs the chosen ports to 10.10.10.1 through the tunnel.
#     The xfrm policies only allow traffic between 10.10.10.2 <-> 10.10.10.1.
#   * Optional fallback transport: ESP-in-UDP (for NAT / when protocol 50 is
#     blocked by the datacenter or ISP).
#
#  v1.1 watchdog upgrade
#   * New: asymmetric-blackout detector - flags "outbound traffic flowing but
#     nothing received" (the exact pattern seen in a real 24h-interval outage:
#     TX counters climbing, RX frozen at 0 on both ends) and rebuilds early,
#     instead of waiting for the plain ping-timeout path.
#   * New: xfrm kernel error counters (/proc/net/xfrm_stat) are polled every
#     cycle; any new non-zero counter is logged immediately as an early warning
#     and included in the forensic snapshot.
#   * New: forensic snapshot capture (xfrm state, interface counters, xfrm
#     error counters, last 40 *scoped* kernel log lines via `journalctl -k`)
#     is written to the service log right before every watchdog-triggered
#     rebuild, so the actual next occurrence is diagnosable after the fact.
#   * New: unconditional preventive rebuild every FORCE_REBUILD_SEC (default
#     12h, 0 = disabled) - a safety net independent of whether a problem was
#     even detected. Configurable from the menu, no separate cron/timer unit
#     needed. Both sides derive keys purely from (master key, UTC hour), so
#     a rebuild on either side needs no coordination with the other.
#   * New: on-demand health check (Live Log -> option 4): packet loss, xfrm
#     error counters, loaded SA count, plain verdict.
#
#  Usage:  bash esp-tunnel.sh        (interactive menu, run as root)
#          esp-tunnel                (after first install)
# ==============================================================================

APP="esp-tunnel"
VERSION="1.1"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"

IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30
EPOCH_LEN=3600          # key rotation period (seconds)
SEQ_STEP=1000000        # initial ESP sequence seed per second inside an epoch
MTU_ESP=1400
MTU_UDP=1380
DEFAULT_UDP_PORT=4500
DEFAULT_FORCE_REBUILD_SEC=43200   # 12h - unconditional preventive rebuild, 0 = disabled
DEFAULT_RX_STALL_SEC=45           # seconds of "tx moving, rx frozen" before an early rebuild

# ---- runtime state (filled by load_config) -----------------------------------
ROLE=""; MASTER=""; IRAN_IP=""; KHAREJ_IP=""; MODE="esp"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_ESP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0
FORCE_REBUILD_SEC="$DEFAULT_FORCE_REBUILD_SEC"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"

# ---- daemon watchdog state (globals; meaningful only while cmd_daemon runs) --
RX0=0; TX0=0; RX_STALL_START=0; LAST_REBUILD=0; FAILS=0; PEER_STATE="unknown"; XPREV=""

PY_UDP='
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP = UDP_ENCAP_ESPINUDP
while True:
    try:
        s.recvfrom(65535)
    except Exception:
        pass
'

# ------------------------------------------------------------------------------
#  Small helpers
# ------------------------------------------------------------------------------
if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_B=$'\e[1;36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
fi
info() { echo "${C_B}[*]${C_0} $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; }
warn() { echo "${C_Y}[!]${C_0} $*" >&2; }
err()  { echo "${C_R}[x]${C_0} $*" >&2; }
log()  { echo "[${APP}] $*"; }          # daemon logs (journald adds timestamps)
have() { command -v "$1" >/dev/null 2>&1; }

need_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Please run as root (sudo -i)."
    exit 1
  fi
}

confirm() {   # confirm "question" [y|n]   (default answer)
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

# "1080, 443 ,8000-8100"  ->  "1080,443,8000-8100"   (returns 1 if invalid)
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

ports_include() {   # ports_include "1080,8000-8100" 8050
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

rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }

# Sets LOCAL_ADDR (our source address towards $1) and WAN_DEV
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
#  Config
# ------------------------------------------------------------------------------
load_config() {
  [[ -r $CONF ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF"
  MODE=${MODE:-esp}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
  FORCE_REBUILD_SEC=${FORCE_REBUILD_SEC:-$DEFAULT_FORCE_REBUILD_SEC}
  RX_STALL_SEC=${RX_STALL_SEC:-$DEFAULT_RX_STALL_SEC}
  case $ROLE in
    iran)   LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP; OUT_LABEL=i2k; IN_LABEL=k2i ;;
    kharej) LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   PEER_PUB=$IRAN_IP;   OUT_LABEL=k2i; IN_LABEL=i2k ;;
    *) return 1 ;;
  esac
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1
  if [[ $MODE == udp ]]; then MTU=$MTU_UDP; else MTU=$MTU_ESP; fi
  return 0
}

write_config() {
  mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
  (
    umask 077
    {
      echo "# ${APP} config - contains the secret master key, keep private"
      printf 'ROLE=%q\n'      "$ROLE"
      printf 'MASTER=%q\n'    "$MASTER"
      printf 'IRAN_IP=%q\n'   "$IRAN_IP"
      printf 'KHAREJ_IP=%q\n' "$KHAREJ_IP"
      printf 'MODE=%q\n'      "$MODE"
      printf 'UDP_PORT=%q\n'  "$UDP_PORT"
      printf 'PORTS=%q\n'     "$PORTS"
      printf 'FWD_PROTO=%q\n' "$FWD_PROTO"
      printf 'FORCE_REBUILD_SEC=%q\n' "$FORCE_REBUILD_SEC"
      printf 'RX_STALL_SEC=%q\n'      "$RX_STALL_SEC"
    } > "$CONF"
  )
  chmod 600 "$CONF"
}

# token = base64( v1|master|iran_ip|kharej_ip|mode|udp_port|ports|proto|checksum )
make_token() {
  local payload chk
  payload="v1|${MASTER}|${IRAN_IP}|${KHAREJ_IP}|${MODE}|${UDP_PORT}|${PORTS}|${FWD_PROTO}"
  chk=$(printf '%s' "$payload" | sha256sum | cut -c1-6)
  printf '%s|%s' "$payload" "$chk" | base64 -w0
}

T_MASTER=""; T_IRAN=""; T_KHAREJ=""; T_MODE=""; T_UDP=""; T_PORTS=""; T_PROTO=""
parse_token() {
  local t dec ver chk want
  t=$(tr -d '[:space:]' <<<"$1")
  [[ -n $t ]] || return 1
  dec=$(base64 -d <<<"$t" 2>/dev/null) || return 1
  IFS='|' read -r ver T_MASTER T_IRAN T_KHAREJ T_MODE T_UDP T_PORTS T_PROTO chk <<<"$dec"
  [[ $ver == v1 ]] || return 1
  want=$(printf '%s' "${ver}|${T_MASTER}|${T_IRAN}|${T_KHAREJ}|${T_MODE}|${T_UDP}|${T_PORTS}|${T_PROTO}" | sha256sum | cut -c1-6)
  [[ $chk == "$want" ]] || return 1
  [[ $T_MASTER =~ ^[0-9a-f]{64}$ ]] || return 1
  valid_ip "$T_IRAN" && valid_ip "$T_KHAREJ" || return 1
  [[ $T_MODE == esp || $T_MODE == udp ]] || return 1
  valid_port "$T_UDP" || return 1
  [[ $T_PROTO == tcp || $T_PROTO == udp || $T_PROTO == both ]] || return 1
  norm_ports "$T_PORTS" >/dev/null || return 1
  return 0
}

# ------------------------------------------------------------------------------
#  Pre-flight: dependencies + kernel support
# ------------------------------------------------------------------------------
ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required (systemctl not found)."; return 1; }
  for c in ip iptables ping ss sha256sum sha512sum base64 awk od head; do
    have "$c" || missing+=("$c")
  done
  if [[ $MODE == udp ]] && ! have python3; then missing+=(python3); fi
  (( ${#missing[@]} == 0 )) && return 0

  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || { err "Missing commands: ${missing[*]} (no supported package manager found)."; return 1; }

  for c in "${missing[@]}"; do
    case $c in
      ip|ss)   [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)    [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      iptables|python3) pkgs+=("$c") ;;
      *)       pkgs+=(coreutils) ;;
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
  for m in xfrm_interface xfrm_user esp4 gcm aesni_intel nf_conntrack xt_TCPMSS iptable_nat; do
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
#  Firewall (iptables, dedicated chains so cleanup is exact)
# ------------------------------------------------------------------------------
ipt() { iptables -w 5 "$@"; }

fw_chain_reset() {   # table chain hook-chain
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

  # accept the tunnel transport from the peer + everything that comes out of the tunnel
  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  if [[ $MODE == udp ]]; then
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$UDP_PORT" -j ACCEPT
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi

  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  # avoid fragmentation / PMTU black holes inside the tunnel
  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

  if [[ $ROLE == iran ]]; then
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
    # everything that enters the tunnel leaves with the tunnel address 10.10.10.2
    ipt -t nat -A ESPT_POST -o "$IF_NAME" -d "$IP_KHAREJ" -j SNAT --to-source "$IP_IRAN"
  fi
  return 0
}

sysctl_apply() {
  printf 'net.ipv4.ip_forward = 1\n' > "$SYSCTL_FILE"
  sysctl -qw net.ipv4.ip_forward=1 >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# ------------------------------------------------------------------------------
#  Interface / policies / security associations
# ------------------------------------------------------------------------------
iface_setup() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
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
  local out
  policies_remove
  # out : only 10.10.10.local -> 10.10.10.peer may enter the tunnel
  # in  : only 10.10.10.peer  -> 10.10.10.local is accepted for this host
  # fwd : replies coming back through the tunnel (source must be the peer tunnel IP)
  out=$(ip xfrm policy add src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
        tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy out: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy in: $out"; return 1; }
  out=$(ip xfrm policy add src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
        tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy fwd: $out"; return 1; }
  return 0
}

# SA registry: one line per installed SA -> "<dir> <epoch> <spi> <src> <dst>"
sa_add() {   # sa_add <in|out> <epoch>
  local dir=$1 e=$2 src dst label spi key seq out
  local -a args=()
  if [[ $dir == out ]]; then src=$LOCAL_ADDR; dst=$PEER_PUB;  label=$OUT_LABEL
  else                       src=$PEER_PUB;   dst=$LOCAL_ADDR; label=$IN_LABEL
  fi
  grep -q "^$dir $e " "$REG" 2>/dev/null && return 0

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)     # 32-byte AES key + 4-byte GCM salt
  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  args+=(if_id "$IF_ID")

  ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
  if [[ $dir == out ]]; then
    # start the sequence counter high inside the epoch so a restart never reuses a GCM nonce
    seq=$(( ($(date +%s) % EPOCH_LEN) * SEQ_STEP ))
    if ! out=$(ip xfrm state add "${args[@]}" replay-oseq "$seq" 2>&1); then
      out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
      log "note: replay-oseq not supported by this iproute2, continuing without it"
    fi
  else
    out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
  fi
  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

prune_sa() {   # prune_sa <current-epoch>
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

install_epoch() {   # newest outbound first, inbound for previous/current/next epoch
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
      [[ -n $spi ]] && ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    done < "$REG"
  fi
  rm -f "$REG"
}

udp_helper_stop() {
  if [[ -f $UDP_PID_FILE ]]; then
    kill "$(cat "$UDP_PID_FILE")" 2>/dev/null
    rm -f "$UDP_PID_FILE"
  fi
}

udp_helper_start() {   # holds the UDP socket that lets the kernel decapsulate ESP-in-UDP
  udp_helper_stop
  python3 -c "$PY_UDP" "$UDP_PORT" >/dev/null 2>&1 &
  echo $! > "$UDP_PID_FILE"
  sleep 0.7
  if ! kill -0 "$(cat "$UDP_PID_FILE")" 2>/dev/null; then
    log "ERROR: cannot open UDP port $UDP_PORT for ESP-in-UDP (already in use?)"
    return 1
  fi
  return 0
}

teardown_all() {
  fw_remove
  udp_helper_stop
  sa_flush
  policies_remove
  ip link del "$IF_NAME" 2>/dev/null
  return 0
}

setup_all() {
  teardown_all
  mkdir -p "$RUN_DIR"; : > "$REG"
  load_modules
  route_info "$PEER_PUB" || { log "ERROR: no route to peer $PEER_PUB"; return 1; }
  iface_setup            || return 1
  policies_setup         || return 1
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  install_epoch "$CUR_EPOCH" || return 1
  if [[ $MODE == udp ]]; then udp_helper_start || return 1; fi
  sysctl_apply
  fw_apply
  log "tunnel up: role=$ROLE ${LOCAL_INNER} <-> ${PEER_INNER}  transport=$MODE  local=$LOCAL_ADDR($WAN_DEV) peer=$PEER_PUB mtu=$MTU epoch=$CUR_EPOCH"
  return 0
}

# ------------------------------------------------------------------------------
#  Watchdog helpers: interface counters, xfrm error counters, forensic dump
# ------------------------------------------------------------------------------
if_counters() {   # prints "<rx_bytes> <tx_bytes>" for $IF_NAME
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

xfrm_nonzero_counters() {   # e.g. "XfrmInStateProtoError=3 XfrmInTmplMismatch=1"
  awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null
}

# Dumps SA state, interface counters, xfrm error counters and recent *kernel*
# log (not the whole boot buffer) so a rebuild that just happened is still
# diagnosable afterwards. Uses fd 3 for the SA-registry loop so the inner
# `... | while read` pipelines don't fight over stdin.
forensic_snapshot() {
  local reason=$1 dir ep spi src dst line
  log "----- forensic snapshot: ${reason} -----"
  if [[ -s $REG ]]; then
    while read -r dir ep spi src dst <&3; do
      [[ -n $spi ]] || continue
      ip xfrm state get src "$src" dst "$dst" proto esp spi "$spi" 2>&1 | while IFS= read -r line; do
        log "xfrm-state (${dir}/epoch ${ep}): ${line}"
      done
    done 3< "$REG"
  fi
  ip -s link show "$IF_NAME" 2>&1 | while IFS= read -r line; do log "link: ${line}"; done
  local x; x=$(xfrm_nonzero_counters)
  log "xfrm error counters: ${x:-none (clean)}"
  journalctl -k -n 40 --no-pager 2>/dev/null | while IFS= read -r line; do log "kernel: ${line}"; done
  log "----- end forensic snapshot -----"
}

# Common rebuild path for every watchdog trigger: logs (with or without a full
# forensic dump), tears down + rebuilds, and resets all watchdog counters so
# the freshly-rebuilt tunnel gets a clean slate.
watchdog_rebuild() {   # watchdog_rebuild "<reason>" [skip-forensic]
  local reason=$1
  if [[ ${2:-} == skip-forensic ]]; then
    log "$reason"
  else
    forensic_snapshot "$reason"
  fi
  if route_info "$PEER_PUB" && setup_all; then
    log "rebuild complete"
  else
    log "ERROR: rebuild attempt failed, will retry next cycle"
  fi
  LAST_REBUILD=$(date +%s)
  RX_STALL_START=0
  FAILS=0
  PEER_STATE="unknown"
  read -r RX0 TX0 <<< "$(if_counters)"
}

# ------------------------------------------------------------------------------
#  Daemon (runs under systemd): setup, hourly key rotation, health watchdog
# ------------------------------------------------------------------------------
cmd_daemon() {
  local tries=0 last_fix=0 e now xcur rx tx
  load_config || { log "ERROR: missing or invalid $CONF"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB after 60s"; exit 1; }
    sleep 2
  done
  setup_all || { log "ERROR: setup failed"; exit 1; }
  LAST_REBUILD=$(date +%s)
  read -r RX0 TX0 <<< "$(if_counters)"
  XPREV=$(xfrm_nonzero_counters)
  log "watchdog active: rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"

  while true; do
    sleep 5 &
    wait $!
    now=$(date +%s)

    # --- hourly key rotation (make-before-break, no packet loss) ---
    e=$(( now / EPOCH_LEN ))
    if (( e != CUR_EPOCH )); then
      log "key rotation: epoch $CUR_EPOCH -> $e"
      if install_epoch "$e"; then CUR_EPOCH=$e; else log "WARN: key rotation failed, will retry"; fi
    fi

    # --- unconditional preventive rebuild (the "every 12h" safety net) ---
    if (( FORCE_REBUILD_SEC > 0 && now - LAST_REBUILD >= FORCE_REBUILD_SEC )); then
      watchdog_rebuild "scheduled preventive rebuild (every $((FORCE_REBUILD_SEC/3600))h)" skip-forensic
      continue
    fi

    # --- interface missing ---
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      watchdog_rebuild "interface $IF_NAME vanished"
      continue
    fi

    # --- xfrm kernel error counters: early warning, logged even without a rebuild ---
    xcur=$(xfrm_nonzero_counters)
    if [[ -n $xcur && $xcur != "$XPREV" ]]; then
      log "WARN: new xfrm error counters: $xcur"
    fi
    XPREV=$xcur

    # --- asymmetric blackout: outbound flowing, nothing received (the exact
    #     pattern seen in production - TX climbing, RX frozen on both ends) ---
    read -r rx tx <<< "$(if_counters)"
    if (( tx > TX0 && rx == RX0 )); then
      (( RX_STALL_START == 0 )) && RX_STALL_START=$now
      if (( now - RX_STALL_START >= RX_STALL_SEC )); then
        watchdog_rebuild "asymmetric blackout: no inbound traffic for ${RX_STALL_SEC}s while outbound is active"
        continue
      fi
    else
      RX_STALL_START=0; RX0=$rx; TX0=$tx
    fi

    # --- ping watchdog (also exercises the path when otherwise idle) ---
    if ping -c1 -W1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      if [[ $PEER_STATE != up ]]; then log "peer $PEER_INNER reachable - tunnel UP"; fi
      PEER_STATE=up; FAILS=0
    else
      FAILS=$(( FAILS + 1 ))
      if (( FAILS == 3 )); then PEER_STATE=down; log "peer $PEER_INNER not answering for ~15s"; fi
      if (( FAILS >= 12 )); then
        if (( now - last_fix >= 180 )); then
          last_fix=$now
          watchdog_rebuild "peer unreachable (ping) for 60s+"
        fi
        FAILS=3
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
#  Installation helpers
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
Description=ESP (IP protocol 50) tunnel (${APP})
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
    confirm "Re-install and overwrite it?" n || return 1
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
  local c
  echo
  echo "Transport:"
  echo "  1) Raw ESP - IP protocol 50   (default: fastest, smallest overhead)"
  echo "  2) ESP-in-UDP                 (fallback: use it if protocol 50 is blocked or a NAT is in front of a server)"
  read -r -p "Select [1]: " c
  if [[ $c == 2 ]]; then
    MODE=udp
    while true; do
      read -r -p "UDP port for ESP-in-UDP [${DEFAULT_UDP_PORT}]: " UDP_PORT
      UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}
      valid_port "$UDP_PORT" && break
      err "Invalid port."
    done
  else
    MODE=esp
    UDP_PORT=$DEFAULT_UDP_PORT
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

print_token() {
  local tok
  tok=$(make_token)
  echo
  echo "${C_Y}================= TOKEN (secret - contains the encryption key) =================${C_0}"
  echo "$tok"
  echo "${C_Y}=================================================================================${C_0}"
  echo "Copy it to the Kharej server: run this script there -> option 2 -> paste the token."
  echo "Send it over a secure channel (SSH/SCP). Anyone with the token can decrypt the tunnel."
}

# ------------------------------------------------------------------------------
#  Menu actions
# ------------------------------------------------------------------------------
setup_iran() {
  local det
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the IRAN server side (tunnel IP ${IP_IRAN})"
  ask_transport
  ensure_deps  || { pause; return; }
  check_kernel || { pause; return; }

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
  if [[ $LOCAL_ADDR != "$IRAN_IP" ]]; then
    warn "This server's local address towards Kharej is $LOCAL_ADDR, not $IRAN_IP (NAT?)."
    warn "Raw ESP through NAT often fails - if it does, re-install using ESP-in-UDP."
  fi

  echo
  ask_ports
  ask_fwd_proto

  ROLE=iran
  MASTER=$(rand_hex 32)
  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC
  write_config
  load_config
  start_service || { pause; return; }
  print_token
  echo
  echo "Forwarding: [${PORTS}] (${FWD_PROTO}) on this server  ->  ${IP_KHAREJ} through the tunnel."
  echo "Your services on Kharej must listen on 0.0.0.0 or ${IP_KHAREJ} (not only 127.0.0.1)."
  echo "Open the ESP protocol (IP proto 50$( [[ $MODE == udp ]] && echo ", UDP ${UDP_PORT}" )) in your provider's external firewall if it has one."
  echo
  pause
}

setup_kharej() {
  local tok
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the KHAREJ client side (tunnel IP ${IP_KHAREJ})"
  while true; do
    read -r -p "Paste the token from the Iran server: " tok
    if parse_token "$tok"; then break; fi
    err "Invalid token (copy error?). Copy it again from the Iran server (menu option 8)."
  done
  MODE=$T_MODE
  ensure_deps  || { pause; return; }
  check_kernel || { pause; return; }

  IRAN_IP=$T_IRAN; KHAREJ_IP=$T_KHAREJ; UDP_PORT=$T_UDP
  PORTS=$(norm_ports "$T_PORTS"); FWD_PROTO=$T_PROTO; MASTER=$T_MASTER; ROLE=kharej
  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC

  if ! route_info "$IRAN_IP"; then err "No route to Iran server $IRAN_IP."; pause; return; fi
  if [[ $LOCAL_ADDR != "$KHAREJ_IP" ]]; then
    warn "This server's local address is $LOCAL_ADDR but the token says $KHAREJ_IP (NAT or wrong server?)."
    confirm "Continue anyway?" n || return
  fi

  write_config
  load_config
  start_service || { pause; return; }

  echo
  info "Testing the tunnel (5 pings to ${PEER_INNER})..."
  ping -c 5 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 3
  echo
  echo "Services for ports [${PORTS}] on this server must listen on 0.0.0.0 or ${IP_KHAREJ}."
  echo "Traffic arrives from ${IP_IRAN} (the Iran server's tunnel IP)."
  echo "Open the ESP protocol (IP proto 50$( [[ $MODE == udp ]] && echo ", UDP ${UDP_PORT}" )) in your provider's external firewall if it has one."
  echo
  pause
}

cmd_status() {
  local st epoch left line
  if ! load_config 2>/dev/null; then
    warn "Tunnel is not installed. Use menu option 1 (Iran) or 2 (Kharej)."
    return
  fi
  st=$(systemctl is-active "$APP" 2>/dev/null)
  epoch=$(( $(date +%s) / EPOCH_LEN ))
  left=$(( EPOCH_LEN - $(date +%s) % EPOCH_LEN ))

  echo "${C_B}===================== ESP Tunnel status =====================${C_0}"
  echo "Role          : $ROLE   (${LOCAL_INNER}  <->  ${PEER_INNER})"
  echo "Peer public IP: $PEER_PUB"
  if [[ $MODE == udp ]]; then echo "Transport     : ESP-in-UDP, port $UDP_PORT"
  else echo "Transport     : raw ESP (IP protocol 50)"; fi
  echo "Cipher        : AES-256-GCM, MTU $MTU, next key rotation in $((left / 60)) min (epoch $epoch)"
  echo "Watchdog      : rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"
  if [[ $st == active ]]; then echo "Service       : ${C_G}active${C_0}"; else echo "Service       : ${C_R}${st}${C_0}"; fi

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    echo "Interface     : $(ip -br addr show "$IF_NAME" | awk '{print $1, $2, $3}')"
  else
    echo "Interface     : ${C_R}$IF_NAME missing${C_0}"
  fi
  echo "Loaded SAs    : $(wc -l < "$REG" 2>/dev/null || echo 0)  (1 outbound + 3 inbound expected)"
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
  echo
  echo "Tip: check raw ESP on the wire:  tcpdump -ni $WAN_DEV 'ip proto 50'"
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

health_check() {
  local out loss line x
  echo "Running health check (~3s of pings)..."
  out=$(ping -c 10 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1)
  echo "$out" | tail -n 3
  loss=$(grep -oE '[0-9]+% packet loss' <<< "$out" | grep -oE '^[0-9]+')
  echo
  echo "Interface    : $(ip -br link show "$IF_NAME" 2>/dev/null || echo "${IF_NAME} missing")"
  x=$(xfrm_nonzero_counters)
  echo "XFRM errors  : ${x:-none (clean)}"
  echo "SAs loaded   : $(wc -l < "$REG" 2>/dev/null || echo 0) (expect 4: 1 outbound + 3 inbound)"
  echo
  if [[ -z $loss ]]; then
    echo "${C_R}Verdict: could not measure (ping did not run)${C_0}"
  elif (( loss == 0 )) && [[ -z $x ]]; then
    echo "${C_G}Verdict: healthy (0% loss, no xfrm errors)${C_0}"
  elif (( loss < 50 )); then
    echo "${C_Y}Verdict: degraded (${loss}% loss)${C_0}"
  else
    echo "${C_R}Verdict: down / severely degraded (${loss}% loss)${C_0}"
  fi
}

live_log() {
  local c
  if ! load_config 2>/dev/null; then warn "Tunnel is not installed."; return; fi
  echo
  echo "Live Log:"
  echo "  1) Service log (events, key rotations, up/down, forensic snapshots)"
  echo "  2) Live ping monitor (packet loss + latency/jitter through the tunnel)"
  echo "  3) Live traffic counters (kbit/s, pps, errors)"
  echo "  4) Run health check now"
  read -r -p "Select [1]: " c
  case ${c:-1} in
    1) echo "(Ctrl+C to return)"; trap ':' INT; journalctl -u "$APP" -f -n 40 --no-pager; trap - INT ;;
    2) echo "(Ctrl+C to stop and see the summary)"; trap ':' INT; ping -O -i 0.5 -I "$IF_NAME" "$PEER_INNER"; trap - INT ;;
    3) live_counters ;;
    4) health_check; pause ;;
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
  ok "Tunnel fully removed (net.ipv4.ip_forward was left unchanged)."
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
  warn "The token changed (ports are part of it) - the Kharej side does not need to be updated."
}

show_token() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  if [[ $ROLE != iran ]]; then warn "The token is created on the Iran server (it is the same key)."; return; fi
  print_token
}

restart_tunnel() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  systemctl restart "$APP" && ok "Restarted."
}

change_watchdog() {
  load_config 2>/dev/null || { warn "Tunnel is not installed."; return; }
  local h s
  echo "Current: preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled), rx-stall trigger ${RX_STALL_SEC}s"
  read -r -p "New preventive-rebuild interval in hours (0 = disable) [$((FORCE_REBUILD_SEC/3600))]: " h
  h=${h:-$((FORCE_REBUILD_SEC/3600))}
  [[ $h =~ ^[0-9]+$ ]] || { err "Invalid number."; return; }
  read -r -p "New rx-stall trigger in seconds, min 10 [$RX_STALL_SEC]: " s
  s=${s:-$RX_STALL_SEC}
  [[ $s =~ ^[0-9]+$ ]] && (( s >= 10 )) || { err "Invalid number (min 10)."; return; }
  FORCE_REBUILD_SEC=$(( h * 3600 ))
  RX_STALL_SEC=$s
  write_config
  if systemctl is-active --quiet "$APP"; then systemctl restart "$APP"; fi
  ok "Updated: preventive rebuild $( (( h == 0 )) && echo disabled || echo "every ${h}h"), rx-stall trigger ${RX_STALL_SEC}s."
}

banner() {
  [[ -t 1 ]] && clear
  echo "${C_B}==============================================================${C_0}"
  echo "${C_B}   ESP Tunnel Manager v${VERSION}  -  IP protocol 50 (ESP)${C_0}"
  echo "${C_B}   Iran ${IP_IRAN}  <=======  ESP  =======>  Kharej ${IP_KHAREJ}${C_0}"
  echo "${C_B}==============================================================${C_0}"
  if load_config 2>/dev/null; then
    echo " Installed role: $ROLE   |   service: $(systemctl is-active "$APP" 2>/dev/null)"
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
    echo "  4) Live Log"
    echo "  5) Uninstall Full Tunnel"
    echo "  ------------------------------------"
    echo "  6) Change forwarded ports (Iran)"
    echo "  7) Restart tunnel"
    echo "  8) Show token (Iran)"
    echo "  9) Watchdog / preventive-rebuild settings"
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
      7) restart_tunnel; echo; pause ;;
      8) show_token; echo; pause ;;
      9) change_watchdog; echo; pause ;;
      0|q|Q) exit 0 ;;
      *) warn "Invalid choice."; sleep 1 ;;
    esac
  done
}

usage() {
  echo "Usage: $0 [menu|status|daemon|teardown|fw]"
}

main() {
  case "${1:-menu}" in
    menu)     need_root; menu ;;
    status)   need_root; cmd_status ;;
    daemon)   need_root; cmd_daemon ;;
    teardown) need_root; cmd_teardown ;;
    fw)       need_root; cmd_fw ;;
    *)        usage; exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
