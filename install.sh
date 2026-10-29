#!/usr/bin/env bash
# ==============================================================================
#  ESP Tunnel Manager  -  point-to-point tunnel over UDP / Proto 50 (ESP) / 47 (GRE)
#
#    Iran server   : 10.0.0.2   (menu option 1)
#    Kharej client : 10.0.0.1   (menu option 2)
#
#  v1.7 No-Crypto (cipher_null), Direct-GRE & Anti-Packet-Loss Edition
#   * Fix: Resolved iptables nf_tables "multiple --in-interface options not allowed"
#     error in ESPT_PRE by splitting interface/peer exclusions into RETURN rules.
#   * Mod: AES encryption disabled (uses cipher_null / digest_null & replay-window 0).
#   * Fix: GRE mode (Protocol 47) now runs as a clean, single-layer direct GRE
#     tunnel on espt0 instead of stacking redundant unencrypted ESP inside GRE.
#   * Fix: ESP-in-UDP mode now defaults to port 4500 (configurable) with built-in
#     10s UDP keepalive to avoid ISP QUIC-443 throttling and NAT state timeouts.
#   * Fix: Multi-probe watchdog ping (-c 3 -i 0.2) to prevent false-positive rebuilds.
#
#  Usage:  bash esp-tunnel.sh        (interactive menu, run as root)
#          esp-tunnel                (after first install)
# ==============================================================================

APP="esp-tunnel"
VERSION="1.7"
BIN="/usr/local/bin/${APP}"
CONF_DIR="/etc/${APP}"
CONF="${CONF_DIR}/config"
UNIT_FILE="/etc/systemd/system/${APP}.service"
SYSCTL_FILE="/etc/sysctl.d/99-${APP}.conf"
RUN_DIR="/run/${APP}"
REG="${RUN_DIR}/sa.list"
UDP_PID_FILE="${RUN_DIR}/udp.pid"

SHARED_SECRET="123"

IF_NAME="espt0"
IF_ID=42
GRE_IF="espgre0"
IP_IRAN="10.0.0.2"
IP_KHAREJ="10.0.0.1"
NET_PREFIX=30
MTU_ESP=1380
MTU_UDP=1360
MTU_GRE=1420
DEFAULT_UDP_PORT=4500
DEFAULT_FORCE_REBUILD_SEC=0       # 0 = disabled by default
DEFAULT_RX_STALL_SEC=60           # seconds of "tx moving, rx frozen" before soft recovery

# ---- runtime state (filled by load_config) -----------------------------------
ROLE=""; MASTER=""; IRAN_IP=""; KHAREJ_IP=""; MODE="udp"; UDP_PORT="$DEFAULT_UDP_PORT"
PORTS=""; FWD_PROTO="both"
LOCAL_INNER=""; PEER_INNER=""; PEER_PUB=""; OUT_LABEL=""; IN_LABEL=""; MTU="$MTU_UDP"
XFRM_LOCAL=""; XFRM_PEER=""
LOCAL_ADDR=""; WAN_DEV=""; CUR_EPOCH=0
FORCE_REBUILD_SEC="$DEFAULT_FORCE_REBUILD_SEC"; RX_STALL_SEC="$DEFAULT_RX_STALL_SEC"
GRE_SUPPORTED=0

# ---- daemon watchdog state ---------------------------------------------------
RX0=0; TX0=0; RX_STALL_START=0; LAST_REBUILD=0; FAILS=0; PEER_STATE="unknown"; XPREV=""

PY_UDP='
import socket, sys, time
port = int(sys.argv[1])
peer = sys.argv[2] if len(sys.argv) > 2 else ""
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
except Exception:
    pass
s.bind(("0.0.0.0", port))
s.setsockopt(socket.IPPROTO_UDP, 100, 2)   # UDP_ENCAP = UDP_ENCAP_ESPINUDP
s.settimeout(10.0)
last_ka = 0.0
while True:
    now = time.monotonic()
    if peer and now - last_ka >= 10.0:
        try:
            s.sendto(b"\xff", (peer, port))
        except Exception:
            pass
        last_ka = now
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
derive_role_vars() {
  case $ROLE in
    iran)
      LOCAL_INNER=$IP_IRAN;   PEER_INNER=$IP_KHAREJ; PEER_PUB=$KHAREJ_IP; OUT_LABEL=i2k; IN_LABEL=k2i
      ;;
    kharej)
      LOCAL_INNER=$IP_KHAREJ; PEER_INNER=$IP_IRAN;   PEER_PUB=$IRAN_IP;   OUT_LABEL=k2i; IN_LABEL=i2k
      ;;
    *) return 1 ;;
  esac
  return 0
}

load_config() {
  [[ -r $CONF ]] || return 1
  # shellcheck disable=SC1090
  source "$CONF"
  MODE=${MODE:-udp}; UDP_PORT=${UDP_PORT:-$DEFAULT_UDP_PORT}; FWD_PROTO=${FWD_PROTO:-both}
  FORCE_REBUILD_SEC=${FORCE_REBUILD_SEC:-$DEFAULT_FORCE_REBUILD_SEC}
  RX_STALL_SEC=${RX_STALL_SEC:-$DEFAULT_RX_STALL_SEC}
  derive_role_vars || return 1
  [[ -n $MASTER && -n $PEER_PUB ]] || return 1
  if [[ $MODE == udp ]]; then
    MTU=$MTU_UDP
  elif [[ $MODE == gre ]]; then
    MTU=$MTU_GRE
  else
    MTU=$MTU_ESP
  fi
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

compute_master() {
  printf '%s' "$SHARED_SECRET" | sha256sum | awk '{print $1}'
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
  have python3 || missing+=(python3)
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
  for m in xfrm_interface xfrm_user esp4 crypto_null nf_conntrack xt_TCPMSS iptable_nat iptable_raw ip_gre gre tcp_bbr sch_fq; do
    modprobe -q "$m" 2>/dev/null
  done
  return 0
}

check_kernel() {
  local t="espchk0" g="grechk0" out virt
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

  ip link del "$g" 2>/dev/null
  if out=$(ip link add "$g" type gre local 127.0.0.2 remote 127.0.0.3 ttl 64 2>&1); then
    GRE_SUPPORTED=1
    ip link del "$g" 2>/dev/null
  else
    GRE_SUPPORTED=0
    warn "Kernel lacks GRE (Protocol 47) tunnel support: $out - the GRE transport will be skipped."
  fi

  ip xfrm state delete src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 2>/dev/null
  if ! out=$(ip xfrm state add src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 mode tunnel \
             enc cipher_null "" auth digest_null "" 2>&1); then
    err "Kernel lacks ESP cipher_null support: $out"
    return 1
  fi
  ip xfrm state delete src 127.0.0.2 dst 127.0.0.3 proto esp spi 0x1c0ffee0 2>/dev/null
  return 0
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
  fw_chain_remove filter ESPT_IN      INPUT
  fw_chain_remove filter ESPT_FWD     FORWARD
  fw_chain_remove mangle ESPT_MSS     POSTROUTING
  fw_chain_remove mangle ESPT_MSS     PREROUTING
  fw_chain_remove mangle ESPT_MSS     FORWARD
  fw_chain_remove nat    ESPT_PRE     PREROUTING
  fw_chain_remove nat    ESPT_POST    POSTROUTING
  fw_chain_remove raw    ESPT_RAW_PRE PREROUTING
  fw_chain_remove raw    ESPT_RAW_OUT OUTPUT
}

fw_apply() {
  local spec d pr mss_val
  local -a specs=() protos=()
  mss_val=$(( MTU - 40 ))

  fw_chain_reset filter ESPT_IN INPUT
  ipt -A ESPT_IN -i "$IF_NAME" -j ACCEPT
  if [[ $MODE == udp ]]; then
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --dport "$UDP_PORT" -j ACCEPT
    ipt -A ESPT_IN -p udp -s "$PEER_PUB" --sport "$UDP_PORT" -j ACCEPT
  elif [[ $MODE == gre ]]; then
    ipt -A ESPT_IN -p 47 -s "$PEER_PUB" -j ACCEPT
  else
    ipt -A ESPT_IN -p 50 -s "$PEER_PUB" -j ACCEPT
  fi

  # Bypass conntrack on raw outer tunnel packets to prevent state table locks
  if ipt -t raw -L -n >/dev/null 2>&1; then
    fw_chain_reset raw ESPT_RAW_PRE PREROUTING
    fw_chain_reset raw ESPT_RAW_OUT OUTPUT
    if [[ $MODE == gre ]]; then
      ipt -t raw -A ESPT_RAW_PRE -p 47 -s "$PEER_PUB" -j CT --notrack 2>/dev/null || \
      ipt -t raw -A ESPT_RAW_PRE -p 47 -s "$PEER_PUB" -j NOTRACK 2>/dev/null
      ipt -t raw -A ESPT_RAW_OUT -p 47 -d "$PEER_PUB" -j CT --notrack 2>/dev/null || \
      ipt -t raw -A ESPT_RAW_OUT -p 47 -d "$PEER_PUB" -j NOTRACK 2>/dev/null
    elif [[ $MODE == esp ]]; then
      ipt -t raw -A ESPT_RAW_PRE -p 50 -s "$PEER_PUB" -j CT --notrack 2>/dev/null || \
      ipt -t raw -A ESPT_RAW_PRE -p 50 -s "$PEER_PUB" -j NOTRACK 2>/dev/null
      ipt -t raw -A ESPT_RAW_OUT -p 50 -d "$PEER_PUB" -j CT --notrack 2>/dev/null || \
      ipt -t raw -A ESPT_RAW_OUT -p 50 -d "$PEER_PUB" -j NOTRACK 2>/dev/null
    fi
  fi

  fw_chain_reset filter ESPT_FWD FORWARD
  ipt -A ESPT_FWD -i "$IF_NAME" -j ACCEPT
  ipt -A ESPT_FWD -o "$IF_NAME" -j ACCEPT

  # Clamp TCP MSS strictly on tunnel interface traffic
  fw_chain_reset mangle ESPT_MSS FORWARD
  fw_chain_reset mangle ESPT_MSS POSTROUTING
  ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val"
  ipt -t mangle -A ESPT_MSS -i "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val"

  if [[ $ROLE == iran ]]; then
    fw_chain_reset nat ESPT_PRE  PREROUTING
    fw_chain_reset nat ESPT_POST POSTROUTING

    # Separate RETURN rules (avoids nf_tables "multiple --in-interface" error and protects outer tunnel packets)
    ipt -t nat -A ESPT_PRE -s "$PEER_PUB" -j RETURN
    ipt -t nat -A ESPT_PRE -i "$IF_NAME" -j RETURN
    ipt -t nat -A ESPT_PRE -i lo -j RETURN

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
        ipt -t nat -A ESPT_PRE -p "$pr" --dport "$d" -j DNAT --to-destination "$IP_KHAREJ"
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
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.tcp_mtu_probing = 1
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.core.netdev_max_backlog = 32768
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
EOF
  sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" >/dev/null 2>&1
  return 0
}

# ------------------------------------------------------------------------------
#  Direct Path & Anti-Disruption Optimizations
# ------------------------------------------------------------------------------
ensure_direct_path() {
  local mss_val=$(( MTU - 40 ))

  # 1. Ensure MSS rules exist without flushing live traffic unnecessarily
  if ! ipt -t mangle -C ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null; then
    ipt -t mangle -F ESPT_MSS 2>/dev/null
    ipt -t mangle -A ESPT_MSS -o "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null
    ipt -t mangle -A ESPT_MSS -i "$IF_NAME" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$mss_val" 2>/dev/null
  fi

  # 2. Disable Reverse Path Filtering on tunnel interfaces
  sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null
  sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null
  sysctl -qw "net.ipv4.conf.${IF_NAME}.rp_filter=0" 2>/dev/null
  [[ -n $WAN_DEV ]] && sysctl -qw "net.ipv4.conf.${WAN_DEV}.rp_filter=0" 2>/dev/null

  # 3. Disable ICMP Redirects
  sysctl -qw net.ipv4.conf.all.accept_redirects=0 2>/dev/null
  sysctl -qw net.ipv4.conf.all.send_redirects=0 2>/dev/null
  sysctl -qw net.ipv4.conf.all.secure_redirects=0 2>/dev/null

  # 4. Force static route to peer public IP
  local gw
  gw=$(ip -4 route get "$PEER_PUB" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="via"){print $(i+1); exit}}')
  if [[ -n $gw && -n $WAN_DEV && $WAN_DEV != "$IF_NAME" ]]; then
    ip route replace "$PEER_PUB" via "$gw" dev "$WAN_DEV" src "$LOCAL_ADDR" 2>/dev/null || \
    ip route replace "$PEER_PUB" dev "$WAN_DEV" src "$LOCAL_ADDR" 2>/dev/null
  fi

  # 5. Increase conntrack & socket buffers
  sysctl -qw net.netfilter.nf_conntrack_max=1048576 2>/dev/null
  sysctl -qw net.core.rmem_max=33554432 2>/dev/null
  sysctl -qw net.core.wmem_max=33554432 2>/dev/null
  sysctl -qw net.core.netdev_max_backlog=32768 2>/dev/null
}

# ------------------------------------------------------------------------------
#  Interface / policies / security associations
# ------------------------------------------------------------------------------
iface_setup() {
  local out tries=0
  ip link del "$GRE_IF" 2>/dev/null
  ip link del "$IF_NAME" 2>/dev/null
  sleep 0.2

  if [[ $MODE == gre ]]; then
    # Direct single-layer GRE interface on espt0 (no redundant XFRM ESP layer inside GRE)
    if ! out=$(ip link add "$IF_NAME" type gre local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 nopmtudisc 2>&1); then
      out=$(ip link add "$IF_NAME" type gre local "$LOCAL_ADDR" remote "$PEER_PUB" ttl 64 2>&1) || {
        log "ERROR: cannot create GRE interface $IF_NAME: $out"
        return 1
      }
    fi
  else
    XFRM_LOCAL=$LOCAL_ADDR
    XFRM_PEER=$PEER_PUB
    while (( tries < 5 )); do
      if out=$(ip link add "$IF_NAME" type xfrm dev "$WAN_DEV" if_id "$IF_ID" 2>&1); then
        break
      fi
      log "WARN: cannot create interface $IF_NAME ($out), retrying..."
      sleep 1
      ((tries++))
    done
    if (( tries >= 5 )); then
      log "ERROR: cannot create interface $IF_NAME: $out"; return 1
    fi
  fi

  ip addr add "${LOCAL_INNER}/${NET_PREFIX}" dev "$IF_NAME" || { log "ERROR: cannot set $LOCAL_INNER on $IF_NAME"; return 1; }
  ip link set "$IF_NAME" txqueuelen 4000 mtu "$MTU" up || { log "ERROR: cannot bring $IF_NAME up"; return 1; }
  return 0
}

policies_remove() {
  local a b
  for a in "$IP_IRAN" "$IP_KHAREJ" "10.10.10.2" "10.10.10.1"; do
    for b in "$IP_IRAN" "$IP_KHAREJ" "10.10.10.2" "10.10.10.1"; do
      [[ $a == "$b" ]] && continue
      ip xfrm policy delete src "$a/32" dst "$b/32" dir out if_id "$IF_ID" 2>/dev/null
      ip xfrm policy delete src "$a/32" dst "$b/32" dir in  if_id "$IF_ID" 2>/dev/null
    done
    ip xfrm policy delete src "$a/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" 2>/dev/null
  done
}

policies_setup() {
  [[ $MODE == gre ]] && return 0
  local out
  out=$(ip xfrm policy update src "$LOCAL_INNER/32" dst "$PEER_INNER/32" dir out if_id "$IF_ID" \
        tmpl src "$XFRM_LOCAL" dst "$XFRM_PEER" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy out: $out"; return 1; }
  out=$(ip xfrm policy update src "$PEER_INNER/32" dst "$LOCAL_INNER/32" dir in if_id "$IF_ID" \
        tmpl src "$XFRM_PEER" dst "$XFRM_LOCAL" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy in: $out"; return 1; }
  out=$(ip xfrm policy update src "$PEER_INNER/32" dst 0.0.0.0/0 dir fwd if_id "$IF_ID" \
        tmpl src "$XFRM_PEER" dst "$XFRM_LOCAL" proto esp reqid "$IF_ID" mode tunnel 2>&1) \
    || { log "ERROR: policy fwd: $out"; return 1; }
  return 0
}

sa_add() {
  local dir=$1 e=${2:-0} src dst label spi out
  local -a args=()
  if [[ $dir == out ]]; then src=$XFRM_LOCAL; dst=$XFRM_PEER;  label=$OUT_LABEL
  else                       src=$XFRM_PEER;  dst=$XFRM_LOCAL; label=$IN_LABEL
  fi

  spi="0x1$(kdf "${MASTER}|spi|${label}" | cut -c1-7)"
  args=(src "$src" dst "$dst" proto esp spi "$spi" reqid "$IF_ID" mode tunnel
        enc cipher_null "" auth digest_null "" replay-window 0)
  if [[ $MODE == udp ]]; then args+=(encap espinudp "$UDP_PORT" "$UDP_PORT" 0.0.0.0); fi
  args+=(if_id "$IF_ID")

  if ! out=$(ip xfrm state update "${args[@]}" 2>&1); then
    ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
    out=$(ip xfrm state add "${args[@]}" 2>&1) || { log "ERROR: cannot add SA: $out"; return 1; }
  fi
  grep -q "^$dir " "$REG" 2>/dev/null || echo "$dir $e $spi $src $dst" >> "$REG"
  return 0
}

install_epoch() {
  local e=${1:-0}
  : > "$REG"
  if [[ $MODE == gre ]]; then
    echo "gre 0 direct $LOCAL_ADDR $PEER_PUB" > "$REG"
    return 0
  fi
  sa_add out "$e" || return 1
  sa_add in  "$e" || return 1
  return 0
}

sa_flush() {
  local dir ep spi src dst
  if [[ -f $REG ]]; then
    while read -r dir ep spi src dst; do
      [[ -n $spi && $spi != direct ]] && ip xfrm state delete src "$src" dst "$dst" proto esp spi "$spi" 2>/dev/null
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

udp_helper_start() {
  udp_helper_stop
  python3 -c "$PY_UDP" "$UDP_PORT" "$PEER_PUB" >/dev/null 2>&1 &
  echo $! > "$UDP_PID_FILE"
  sleep 0.6
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
  ip xfrm state flush 2>/dev/null
  ip xfrm policy flush 2>/dev/null
  ip link del "$IF_NAME" 2>/dev/null
  ip link del "$GRE_IF" 2>/dev/null
  sleep 0.3
  return 0
}

setup_all() {
  udp_helper_stop
  sa_flush
  policies_remove
  ip xfrm state flush 2>/dev/null
  ip xfrm policy flush 2>/dev/null
  ip link del "$IF_NAME" 2>/dev/null
  ip link del "$GRE_IF" 2>/dev/null
  mkdir -p "$RUN_DIR"; : > "$REG"
  load_modules
  route_info "$PEER_PUB" || { log "ERROR: no route to peer $PEER_PUB"; return 1; }
  sysctl_apply
  if [[ $MODE == udp ]]; then udp_helper_start || return 1; fi
  iface_setup            || return 1
  policies_setup         || return 1
  CUR_EPOCH=0
  install_epoch "$CUR_EPOCH" || return 1
  fw_apply
  ensure_direct_path
  log "tunnel up: role=$ROLE ${LOCAL_INNER} <-> ${PEER_INNER}  transport=$MODE$( [[ $MODE == udp ]] && echo "($UDP_PORT)" )  cipher=null  local=$LOCAL_ADDR($WAN_DEV) peer=$PEER_PUB mtu=$MTU"
  return 0
}

# ------------------------------------------------------------------------------
#  Watchdog helpers
# ------------------------------------------------------------------------------
if_counters() {
  local r t
  r=$(cat "/sys/class/net/${IF_NAME}/statistics/rx_bytes" 2>/dev/null) || r=0
  t=$(cat "/sys/class/net/${IF_NAME}/statistics/tx_bytes" 2>/dev/null) || t=0
  echo "${r:-0} ${t:-0}"
}

xfrm_nonzero_counters() {
  awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null
}

peer_ping_ok() {
  ping -c 3 -i 0.2 -W 1 -I "$IF_NAME" "$PEER_INNER" >/dev/null 2>&1
}

forensic_snapshot() {
  local reason=$1 line
  log "----- forensic snapshot: ${reason} -----"
  ip -s link show "$IF_NAME" 2>&1 | while IFS= read -r line; do log "link: ${line}"; done
  local x; x=$(xfrm_nonzero_counters)
  log "xfrm error counters: ${x:-none (clean)}"
  log "----- end forensic snapshot -----"
}

soft_recover() {
  route_info "$PEER_PUB" || return 1
  if [[ $MODE != gre ]]; then
    XFRM_LOCAL=$LOCAL_ADDR
    XFRM_PEER=$PEER_PUB
  fi
  if [[ $MODE == udp ]] && { [[ ! -f $UDP_PID_FILE ]] || ! kill -0 "$(cat "$UDP_PID_FILE" 2>/dev/null)" 2>/dev/null; }; then
    udp_helper_start || return 1
  fi
  policies_setup || return 1
  install_epoch 0 || return 1
  ensure_direct_path
  peer_ping_ok
}

watchdog_rebuild() {
  local reason=$1
  if [[ ${2:-} != skip-forensic ]]; then
    log "attempting non-disruptive soft recovery ($reason)..."
    if soft_recover; then
      log "soft recovery succeeded without interface teardown"
      RX_STALL_START=0
      FAILS=0
      PEER_STATE=up
      read -r RX0 TX0 <<< "$(if_counters)"
      return 0
    fi
    forensic_snapshot "$reason"
  else
    log "$reason"
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
#  Daemon
# ------------------------------------------------------------------------------
cmd_daemon() {
  local tries=0 last_fix=0 now xcur rx tx
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

    if (( FORCE_REBUILD_SEC > 0 && now - LAST_REBUILD >= FORCE_REBUILD_SEC )); then
      watchdog_rebuild "scheduled preventive rebuild (every $((FORCE_REBUILD_SEC/3600))h)" skip-forensic
      continue
    fi

    if ! ip link show "$IF_NAME" >/dev/null 2>&1; then
      watchdog_rebuild "interface $IF_NAME vanished"
      continue
    fi

    if [[ $MODE != gre ]]; then
      xcur=$(xfrm_nonzero_counters)
      if [[ -n $xcur && $xcur != "$XPREV" ]]; then
        log "WARN: new xfrm error counters: $xcur"
      fi
      XPREV=$xcur
    fi

    read -r rx tx <<< "$(if_counters)"
    if (( tx > TX0 && rx == RX0 )); then
      (( RX_STALL_START == 0 )) && RX_STALL_START=$now
      TX0=$tx
      if (( now - RX_STALL_START >= RX_STALL_SEC )); then
        if ! peer_ping_ok; then
          watchdog_rebuild "asymmetric blackout: no inbound traffic for ${RX_STALL_SEC}s while outbound is active"
          continue
        else
          RX_STALL_START=0
          read -r RX0 TX0 <<< "$(if_counters)"
        fi
      fi
    else
      RX_STALL_START=0; RX0=$rx; TX0=$tx
    fi

    if peer_ping_ok; then
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
  ensure_direct_path
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
Description=ESP (UDP / IP protocol 50 / GRE 47) tunnel (${APP})
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
    read -r -p "Ports to forward through the tunnel (comma separated, e.g. 1080,443,8000-8100) [23902]: " raw
    raw=${raw:-23902}
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
  local c up gre_note=""
  (( GRE_SUPPORTED == 1 )) || gre_note="  [NOT supported by this kernel]"
  echo
  echo "Transport:"
  echo "  1) ESP-in-UDP (No-Crypto)      (Recommended: Bypasses ISP Proto 47/50 drops & NAT)"
  echo "  2) Raw ESP - IP protocol 50    (Direct IP Proto 50 without encryption)"
  echo "  3) Protocol 47 (Direct GRE)    (Single-layer pure GRE tunnel)${gre_note}"
  echo "  4) Auto  (test each mode against peer, keep whichever has lowest loss)"
  read -r -p "Select [1]: " c
  case ${c:-1} in
    1)
      MODE=udp
      while true; do
        read -r -p "UDP tunnel port (must match on both servers, avoid 443 due to QUIC filter) [${DEFAULT_UDP_PORT}]: " up
        up=${up:-$DEFAULT_UDP_PORT}
        if valid_port "$up"; then
          UDP_PORT=$up
          break
        fi
        err "Invalid UDP port (1-65535)."
      done
      ;;
    2)
      MODE=esp
      UDP_PORT=$DEFAULT_UDP_PORT
      ;;
    4)
      MODE=auto
      ;;
    *)
      MODE=gre
      UDP_PORT=$DEFAULT_UDP_PORT
      ;;
  esac
}

mode_label() {
  case $1 in
    udp) echo "ESP-in-UDP (${UDP_PORT})" ;;
    esp) echo "Raw ESP (proto 50)" ;;
    gre) echo "Direct GRE (proto 47)" ;;
    *)   echo "$1" ;;
  esac
}

auto_select_transport() {
  local -a candidates=()
  local m loss best_mode="" best_loss=101 tested=0

  if (( GRE_SUPPORTED == 1 )); then
    candidates=(udp gre esp)
  else
    candidates=(udp esp)
  fi

  echo
  info "Auto mode: bringing up each transport against ${PEER_PUB} and measuring real packet loss (~8s each)..."
  echo

  for m in "${candidates[@]}"; do
    MODE=$m
    case $m in
      udp) UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_UDP ;;
      gre) UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_GRE ;;
      esp) UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_ESP ;;
    esac

    printf '  %-24s ' "$(mode_label "$m")"
    if ! setup_all >/tmp/.espt-auto.log 2>&1; then
      echo "${C_R}setup failed${C_0}"
      teardown_all >/dev/null 2>&1
      continue
    fi
    sleep 2
    loss=$(ping -c 6 -i 0.4 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>/dev/null | grep -oE '[0-9]+% packet loss' | grep -oE '^[0-9]+')
    [[ -z $loss ]] && loss=100
    teardown_all >/dev/null 2>&1
    tested=$((tested + 1))

    if   (( loss == 0 ));   then echo "${C_G}${loss}% loss${C_0}"
    elif (( loss < 100 ));  then echo "${C_Y}${loss}% loss${C_0}"
    else                         echo "${C_R}no response${C_0}"
    fi

    if (( loss < best_loss )); then best_loss=$loss; best_mode=$m; fi
  done
  echo

  if (( tested == 0 || best_loss >= 100 )); then
    warn "No reply from the peer on any transport - it's probably not installed/running on the other side yet."
    MODE=udp; UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_UDP
    warn "Defaulting to $(mode_label "$MODE"). Make sure both servers use the SAME transport mode."
  else
    MODE=$best_mode
    case $MODE in
      udp) UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_UDP ;;
      gre) UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_GRE ;;
      esp) UDP_PORT=$DEFAULT_UDP_PORT; MTU=$MTU_ESP ;;
    esac
    ok "Selected: $(mode_label "$MODE")  (${best_loss}% loss in the test)"
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
  info "Setting up the IRAN server side (tunnel IP ${IP_IRAN})"

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

  ROLE=iran
  derive_role_vars

  if ! route_info "$KHAREJ_IP"; then err "No route to $KHAREJ_IP from this server."; pause; return; fi
  if [[ $LOCAL_ADDR != "$IRAN_IP" ]]; then
    warn "This server's local address towards Kharej is $LOCAL_ADDR, not $IRAN_IP (NAT?)."
  fi

  echo
  ask_ports
  ask_fwd_proto

  MASTER=$(compute_master)
  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC

  ensure_deps  || { pause; return; }
  check_kernel || { pause; return; }

  while true; do
    ask_transport
    if [[ $MODE == auto ]]; then
      auto_select_transport
      break
    elif [[ $MODE == gre && $GRE_SUPPORTED -ne 1 ]]; then
      err "This kernel doesn't support GRE tunnels - pick a different transport."
      continue
    else
      break
    fi
  done

  write_config
  load_config || { err "internal error writing config"; pause; return; }
  start_service || { pause; return; }
  echo
  ok "Setup complete on Iran. Now run option 2 on the Kharej server with the SAME transport."
  echo "Forwarding: [${PORTS}] (${FWD_PROTO}) on this server  ->  ${IP_KHAREJ} through the tunnel."
  echo
  pause
}

setup_kharej() {
  local det
  confirm_reinstall || return
  install_self || { pause; return; }

  echo
  info "Setting up the KHAREJ client side (tunnel IP ${IP_KHAREJ})"

  det=$(detect_public_ip)
  while true; do
    read -r -p "Iran server public IP: " IRAN_IP
    valid_ip "$IRAN_IP" && break
    err "Invalid IPv4 address."
  done
  while true; do
    read -r -p "Kharej (this) server public IP [${det}]: " KHAREJ_IP
    KHAREJ_IP=${KHAREJ_IP:-$det}
    valid_ip "$KHAREJ_IP" && break
    err "Invalid IPv4 address."
  done

  MASTER=$(compute_master); ROLE=kharej
  derive_role_vars
  FORCE_REBUILD_SEC=$DEFAULT_FORCE_REBUILD_SEC
  RX_STALL_SEC=$DEFAULT_RX_STALL_SEC

  if ! route_info "$IRAN_IP"; then err "No route to Iran server $IRAN_IP."; pause; return; fi
  if [[ $LOCAL_ADDR != "$KHAREJ_IP" ]]; then
    warn "This server's local address is $LOCAL_ADDR but configured Kharej IP is $KHAREJ_IP (NAT?)."
    confirm "Continue anyway?" y || return
  fi

  ensure_deps  || { pause; return; }
  check_kernel || { pause; return; }

  while true; do
    ask_transport
    if [[ $MODE == auto ]]; then
      auto_select_transport
      break
    elif [[ $MODE == gre && $GRE_SUPPORTED -ne 1 ]]; then
      err "This kernel doesn't support GRE tunnels - pick a different transport."
      continue
    else
      break
    fi
  done

  write_config
  load_config || { err "internal error writing config"; pause; return; }
  start_service || { pause; return; }

  echo
  info "Testing the tunnel (5 pings to ${PEER_INNER})..."
  ping -c 5 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 3
  echo
  pause
}

cmd_status() {
  local st line
  if ! load_config 2>/dev/null; then
    warn "Tunnel is not installed. Use menu option 1 (Iran) or 2 (Kharej)."
    return
  fi
  st=$(systemctl is-active "$APP" 2>/dev/null)

  echo "${C_B}===================== ESP Tunnel status =====================${C_0}"
  echo "Role          : $ROLE   (${LOCAL_INNER}  <->  ${PEER_INNER})"
  echo "Peer public IP: $PEER_PUB"
  if [[ $MODE == udp ]]; then
    echo "Transport     : ESP-in-UDP (port $UDP_PORT, cipher_null)"
  elif [[ $MODE == gre ]]; then
    echo "Transport     : Protocol 47 (Direct Single-Layer GRE on $IF_NAME)"
  else
    echo "Transport     : Raw ESP (IP protocol 50, cipher_null)"
  fi
  echo "Cipher        : Disabled (Plain / No-AES), MTU $MTU"
  echo "Watchdog      : rx-stall trigger ${RX_STALL_SEC}s, preventive rebuild $( (( FORCE_REBUILD_SEC > 0 )) && echo "every $((FORCE_REBUILD_SEC/3600))h" || echo disabled)"
  if [[ $st == active ]]; then echo "Service       : ${C_G}active${C_0}"; else echo "Service       : ${C_R}${st}${C_0}"; fi

  if ip link show "$IF_NAME" >/dev/null 2>&1; then
    echo "Interface     : $(ip -br addr show "$IF_NAME" | awk '{print $1, $2, $3}')"
  else
    echo "Interface     : ${C_R}$IF_NAME missing${C_0}"
  fi
  echo
  echo "--- Ping through the tunnel (10 packets) ---"
  ping -c 10 -i 0.2 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1 | tail -n 2
  echo
  echo "--- Interface counters ---"
  ip -s link show "$IF_NAME" 2>/dev/null | sed -n '3,6p'
  if [[ $MODE != gre ]]; then
    echo
    line=$(awk '$2 != 0 {printf "%s=%s ", $1, $2}' /proc/net/xfrm_stat 2>/dev/null)
    if [[ -n $line ]]; then
      echo "XFRM counters : $line"
    else
      echo "XFRM counters : clean (no errors)"
    fi
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

health_check() {
  local out loss x
  echo "Running health check (~3s of pings)..."
  out=$(ping -c 10 -i 0.3 -W 1 -I "$IF_NAME" "$PEER_INNER" 2>&1)
  echo "$out" | tail -n 3
  loss=$(grep -oE '[0-9]+% packet loss' <<< "$out" | grep -oE '^[0-9]+')
  echo
  echo "Interface    : $(ip -br link show "$IF_NAME" 2>/dev/null || echo "${IF_NAME} missing")"
  x=$(xfrm_nonzero_counters)
  echo "XFRM errors  : ${x:-none (clean)}"
  echo
  if [[ -z $loss ]]; then
    echo "${C_R}Verdict: could not measure (ping did not run)${C_0}"
  elif (( loss == 0 )); then
    echo "${C_G}Verdict: healthy (0% loss)${C_0}"
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
  echo "  1) Service log (events, up/down, forensic snapshots)"
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
  warn "Ports updated - the Kharej side does not need to be updated."
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
  echo "${C_B}   ESP Tunnel Manager v${VERSION}  -  No-Crypto & Direct-GRE${C_0}"
  echo "${C_B}   Iran ${IP_IRAN}  <=======  TUN  =======>  Kharej ${IP_KHAREJ}${C_0}"
  echo "${C_B}==============================================================${C_0}"
  if load_config 2>/dev/null; then
    echo " Installed role: $ROLE ($MODE)   |   service: $(systemctl is-active "$APP" 2>/dev/null)"
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
    echo "  8) Watchdog / preventive-rebuild settings"
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
      8) change_watchdog; echo; pause ;;
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
