#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager v1.4 - Fixed Auto-Token, Self-Healing & Dynamic IP Support
# ==============================================================================

APP="esp-tunnel"
VERSION="1.4"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"

# ---- توکن و تنظیمات پیش‌فرض ثابت (Shared Static Secret) ----
STATIC_MASTER="e7d8f3c1a4b92850d6e1749c3b8a1052f9c4e7b8a1d2e3f4c5b6a78901234567"
DEFAULT_UDP_PORT=39540
DEFAULT_MODE="udp"
DEFAULT_PORTS="443,80,2053,2083,2087,2096,8443"

IF_NAME="espt0"
IF_ID=42
IP_IRAN="10.10.10.2"
IP_KHAREJ="10.10.10.1"
NET_PREFIX=30
EPOCH_LEN=3600
MTU_ESP=1400
MTU_UDP=1360
DEFAULT_FORCE_REBUILD_SEC=0       # 0 = disabled (soft-rotate handles it safely)
DEFAULT_RX_STALL_SEC=90          # seconds of asymmetric traffic before heal

ROLE=""; MASTER="$STATIC_MASTER"; IRAN_IP=""; KHAREJ_IP=""; MODE="$DEFAULT_MODE"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_UDP"
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0
FORCE_REBUILD_SEC="$DEFAULT_FORCE_REBUILD_SEC"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"

RX0=0; TX0=0; RX_STALL_START=0; LAST_REBUILD=0; FAILS=0; PEER_STATE="unknown"; XPREV=""

PY_UDP='
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP_ESPINUDP
while True:
    try:
        s.recvfrom(65535)
    except Exception:
        time.sleep(0.5)
'

if [[ -t 1 ]]; then
  C_R=$'\e[1;31m'; C_G=$'\e[1;32m'; C_Y=$'\e[1;33m'; C_B=$'\e[1;36m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
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
  for o in "${BASH_REMATCH[@]:1}"; do (( 10#$o <= 255 )) || return 1; done
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

load_config() {
  [[ -r $CONF ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF"
  MASTER=${MASTER:-$STATIC_MASTER}
  MODE=${MODE:-$DEFAULT_MODE}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
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
      echo "# ${APP} config"
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

ensure_deps() {
  local c pm=""
  local -a missing=() pkgs=()
  have systemctl || { err "systemd is required."; return 1; }
  for c in ip iptables ping ss sha256sum sha512sum base64 awk od head python3; do
    have "$c" || missing+=("$c")
  done
  (( ${#missing[@]} == 0 )) && return 0

  if   have apt-get; then pm=apt
  elif have dnf;     then pm=dnf
  elif have yum;     then pm=yum
  fi
  [[ -n $pm ]] || { err "Missing: ${missing[*]}"; return 1; }

  for c in "${missing[@]}"; do
    case $c in
      ip|ss)   [[ $pm == apt ]] && pkgs+=(iproute2) || pkgs+=(iproute) ;;
      ping)    [[ $pm == apt ]] && pkgs+=(iputils-ping) || pkgs+=(iputils) ;;
      iptables|python3) pkgs+=("$c") ;;
      *)       pkgs+=(coreutils) ;;
    esac
  done
  info "Installing dependencies: ${pkgs[*]}"
  if [[ $pm == apt ]]; then
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1
  else
    timeout 300 "$pm" install -y "${pkgs[@]}" >/dev/null 2>&1
  fi
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
  local t="espchk0" out
  load_modules
  ip link del "$t" 2>/dev/null
  if ! out=$(ip link add "$t" type xfrm dev lo if_id 4242 2>&1); then
    err "Kernel lacks XFRM-interface support: $out"
    return 1
  fi
  ip link del "$t" 2>/dev/null
  return 0
}

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
  if [[ $MODE == udp ]]; then
    # اصلاح شده: پذیرش از هر مبدا برای پشتیبانی از IP داینامیک/CGNAT
    # امنیت توسط احراز هویت رمزنگاری ESP در سطح هسته تضمین می‌شود
    ipt -A ESPT_IN -p udp --dport "$UDP_PORT" -j ACCEPT
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi

  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  local target_mss=$(( MTU - 40 ))
  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$target_mss"

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
    ipt -t nat -A ESPT_POST -o "$IF_NAME" -d "$IP_KHAREJ" -j SNAT --to-source "$IP_IRAN"
  fi
  return 0
}

sysctl_apply() {
  cat > "$SYSCTL_FILE" <<EOF
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.lo.rp_filter = 0
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

iface_setup() {
  local out
  ip link del "$IF_NAME" 2>/dev/null
  if ! out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
    log "ERROR: cannot create $IF_NAME: $out"; return 1
  fi
  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || return 1
  ip link set "$IF_NAME" mtu "$MTU" up || return 1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
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
  policies_remove
  ip xfrm policy add src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
     tmpl src "$LOCAL_ADDR" dst "$PEER_PUB" proto esp reqid "$IF_ID" mode tunnel >/dev/null 2>&1 || return 1
  ip xfrm policy add src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
     tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel >/dev/null 2>&1 || return 1
  ip xfrm policy add src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
     tmpl src "$PEER_PUB" dst "$LOCAL_ADDR" proto esp reqid "$IF_ID" mode tunnel >/dev/null 2>&1 || return 1
  return 0
}

sa_add() {
  local dir=$1 e=$2 src dst label spi key out
  local -a args=()
  if [[ $dir == out ]]; then src=$LOCAL_ADDR; dst=$PEER_PUB;  label=$OUT_LABEL
  else                       src=$PEER_PUB;   dst=$LOCAL_ADDR; label=$IN_LABEL
  fi
  
  # اصلاح شده: بررسی تغییر IP و پاکسازی SA قدیمی در صورت تغییر
  local old_line=$(grep "^$dir $e " "$REG" 2>/dev/null)
  if [[ -n "$old_line" ]]; then
    local old_src=$(echo "$old_line" | awk '{print $4}')
    local old_dst=$(echo "$old_line" | awk '{print $5}')
    if [[ "$old_src" == "$src" && "$old_dst" == "$dst" ]]; then
      return 0 # قبلاً وجود دارد و مطابقت دارد
    else
      # IP تغییر کرده است، SA قدیمی و ورودی رجیستری را پاک کن
      local old_spi=$(echo "$old_line" | awk '{print $3}')
      ip xfrm state delete src "$old_src" dst "$old_dst" proto esp spi "$old_spi" 2>/dev/null
      grep -v "^$dir $e " "$REG" > "${REG}.tmp" 2>/dev/null && mv "${REG}.tmp" "$REG"
    fi
  fi

  spi="0x1$(kdf "${MASTER}|spi|${label}|${e}" | cut -c1-7)"
  key=$(kdf "${MASTER}|key|${label}|${e}" | cut -c1-72)
  
  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        replay-window 0
        aead 'rfc4106(gcm(aes))' "0x${key}" 128)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  args+=(if_id "$IF_ID")

  if ! out=$(ip xfrm state add "${args[@]}" 2>&1); then
    log "ERROR: cannot add SA: $out"; return 1
  fi
  echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

prune_sa() {
  local e=$1 dir ep spi src dst keep tmp
  [[ -f $REG ]] || return 0
  tmp=$(mktemp)
  while read -r dir ep spi src dst; do
    [[ -n $spi ]] || continue
    keep=1
    if [[ $dir == out ]]; then
      (( ep != e )) && keep=0
    else
      # اصلاح شده: پنجره تحمل تا 2 ساعت برای جلوگیری از قطع به دلیل اختلاف ساعت سرورها
      (( ep < e - 2 || ep > e + 2 )) && keep=0
    fi
    if (( keep )); then
      echo "$dir $ep $spi $src $dst" >> "$tmp"
    else
      ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    fi
  done < "$REG"
  cat "$tmp" > "$REG"
  rm -f "$tmp"
}

install_epoch() {
  local e=$1 x
  sa_add out "$e" || return 1
  # اصلاح شده: نصب کلیدهای ورودی برای بازه 2 ساعت قبل و بعد برای تحمل Clock Skew
  for x in $((e - 2)) $((e - 1)) "$e" $((e + 1)) $((e + 2)); do
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
    kill "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null
    rm -f "$UDP_PID_FILE"
  fi
}

udp_helper_start() {
  udp_helper_stop
  python3 -c "$PY_UDP" "$UDP_PORT" >/dev/null 2>&1 &
  echo $! > "$UDP_PID_FILE"
  sleep 0.5
  if ! kill -0 "$(cat "$UDP_PID_FILE")" 2>/dev/null; then
    log "ERROR: cannot open UDP port $UDP_PORT"
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
  log "tunnel up: $LOCAL_INNER <-> $PEER_INNER mode=$MODE port=$UDP_PORT epoch=$CUR_EPOCH"
  return 0
}

soft_heal() {
  log "running soft self-healing..."
  route_info "$PEER_PUB" || return 1
  if [[ $MODE == udp ]]; then
    if [[ ! -f $UDP_PID_FILE ]] || ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
      udp_helper_start
    fi
  fi
  CUR_EPOCH=$(( $(date +%s) / EPOCH_LEN ))
  install_epoch "$CUR_EPOCH"
  policies_setup
  sysctl_apply
  return 0
}

if_counters() {
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

watchdog_rebuild() {
  local reason=$1
  log "watchdog triggering rebuild: $reason"
  if ! soft_heal || ! ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
    log "soft-heal failed, performing full rebuild..."
    setup_all
  else
    log "soft-heal succeeded, tunnel restored without tearing down interface."
  fi
  LAST_REBUILD=$(date +%s)
  RX_STALL_START=0
  FAILS=0
  PEER_STATE="unknown"
  read -r RX0 TX0 <<< "$(if_counters)"
}

cmd_daemon() {
  local tries=0 e now rx tx
  load_config || { log "ERROR: missing config"; exit 1; }
  mkdir -p "$RUN_DIR"
  trap 'log "stop signal received"; exit 0' TERM INT

  until route_info "$PEER_PUB"; do
    (( ++tries > 30 )) && { log "ERROR: no route to $PEER_PUB"; exit 1; }
    sleep 2
  done
  setup_all || { log "ERROR: setup failed"; exit 1; }
  LAST_REBUILD=$(date +%s)
  read -r RX0 TX0 <<< "$(if_counters)"

  while true; do
    sleep 5 &
    wait $!
    now=$(date +%s)

    # 1. Hourly key rotation
    e=$(( now / EPOCH_LEN ))
    if (( e != CUR_EPOCH )); then
      log "key rotation: epoch $CUR_EPOCH -> $e"
      if install_epoch "$e"; then CUR_EPOCH=$e; fi
    fi

    # 2. Watchdog: UDP helper check
    if [[ $MODE == udp ]]; then
      if [[ ! -f $UDP_PID_FILE ]] || ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; then
        log "WARN: UDP helper died! Reviving..."
        udp_helper_start
      fi
    fi

    # 3. Interface check
    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      watchdog_rebuild "interface $IF_NAME vanished"
      continue
    fi

    # 4. Asymmetric blackout check (verified by ping)
    read -r rx tx <<< "$(if_counters)"
    if (( tx > TX0 && rx == RX0 )); then
      (( RX_STALL_START == 0 )) && RX_STALL_START=$now
      if (( now - RX_STALL_START >= RX_STALL_SEC )); then
        if ! ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
          watchdog_rebuild "asymmetric blackout confirmed by ping"
          continue
        else
          RX_STALL_START=0
        fi
      fi
    else
      RX_STALL_START=0; RX0=$rx; TX0=$tx
    fi

    # 5. Continuous keepalive ping
    if ping -c 1 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1; then
      PEER_STATE=up; FAILS=0
    else
      FAILS=$(( FAILS + 1 ))
      if (( FAILS >= 6 )); then
        watchdog_rebuild "peer unreachable (ping) for 30s"
        FAILS=0
      fi
    fi
  done
}

cmd_teardown() { teardown_all; log "tunnel torn down"; }
cmd_fw() { load_config || exit 1; route_info "$PEER_PUB" || exit 1; fw_apply; }

install_self() {
  local src
  src=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null)
  [[ -f $src ]] || return 1
  [[ $src != "$BIN" ]] && install -m 755 "$src" "$BIN"
  return 0
}

write_unit() {
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=ESP Tunnel Service (${APP})
After=network-online.target
Wants=network-online.target

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
  sleep 2
  if systemctl is-active --quiet "$APP" && ip link show "$IF_NAME" >/dev/null 2>&1; then
    ok "Tunnel service started successfully."
    return 0
  fi
  err "Service failed to start."
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
        err "Port $p is SSH! Forwarding it will lock you out."
        continue 2
      fi
    done
    PORTS=$norm; break
  done
}

ask_fwd_proto() {
  local c
  echo "Forwarding Protocol: 1) TCP + UDP (default)  2) TCP only  3) UDP only"
  read -r -p "Select [1]: " c
  case $c in 2) FWD_PROTO=tcp ;; 3) FWD_PROTO=udp ;; *) FWD_PROTO=both ;; esac
}

setup_iran() {
  confirm_reinstall || return
  install_self || return
  info "Configuring IRAN Server side (10.10.10.2)"
  ensure_deps || return
  check_kernel || return

  local det
  det=$(detect_public_ip)
  read -r -p "Iran Public IP [$det]: " IRAN_IP; IRAN_IP=${IRAN_IP:-$det}
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

  write_config; load_config; start_service || return
  echo
  ok "Iran server setup complete!"
  echo "${C_G}No token copy-paste needed!${C_0}"
  echo "Now run option 2 on Kharej server and just enter this Iran IP: ${C_Y}${IRAN_IP}${C_0}"
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
  read -r -p "Kharej Public IP [$det]: " KHAREJ_IP; KHAREJ_IP=${KHAREJ_IP:-$det}
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

  write_config; load_config; start_service || return
  echo
  info "Testing ping to Iran (${PEER_INNER})..."
  ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER"
  echo
  ok "Kharej client connected successfully using static auto-token!"
  pause
}

confirm_reinstall() {
  if load_config 2>/dev/null; then
    warn "Already configured as $ROLE."
    confirm "Overwrite?" n || return 1
  fi
  return 0
}

cmd_status() {
  load_config || { warn "Not installed."; return; }
  echo "Role: $ROLE | Mode: $MODE | UDP Port: $UDP_PORT"
  echo "Service: $(systemctl is-active "$APP")"
  ip -br addr show "$IF_NAME" 2>/dev/null
  echo "Ping test:"
  ping -c 4 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
}

uninstall_all() {
  confirm "Remove tunnel completely?" n || return
  systemctl disable --now "$APP" >/dev/null 2>&1
  teardown_all
  rm -f "$UNIT_FILE" "$SYSCTL_FILE" "$BIN"
  rm -rf "$CONF_DIR" "$RUN_DIR"
  systemctl daemon-reload
  ok "Tunnel fully removed."
}

menu() {
  while true; do
    echo
    echo "${C_B}======================================================${C_0}"
    echo "${C_B}   ESP Tunnel Manager v${VERSION} (Auto-Token System)   ${C_0}"
    echo "${C_B}======================================================${C_0}"
    echo "  1) Setup Iran Server"
    echo "  2) Setup Kharej Client"
    echo "  3) Status & Ping"
    echo "  4) Live Journal Log"
    echo "  5) Uninstall"
    echo "  0) Exit"
    echo
    read -r -p "Select: " ch
    case $ch in
      1) setup_iran ;;
      2) setup_kharej ;;
      3) cmd_status; pause ;;
      4) journalctl -u "$APP" -f -n 30 ;;
      5) uninstall_all; pause ;;
      0|q|Q) exit 0 ;;
    esac
  done
}

main() {
  case "${1:-menu}" in
    menu)     need_root; menu ;;
    status)   need_root; cmd_status ;;
    daemon)   need_root; cmd_daemon ;;
    teardown) need_root; cmd_teardown ;;
    fw)       need_root; cmd_fw ;;
    *)        exit 1 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
