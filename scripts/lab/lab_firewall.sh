#!/bin/sh
set -eu

HOST_IP='192.168.217.1'
LAB_IP='192.168.217.10'
NETPLAN_NAT='/etc/netplan/60-malpdf-nat.yaml'
UNIT_PATH='/etc/systemd/system/malpdf-firewall.service'
INSTALL_BIN='/usr/local/sbin/malpdf-firewall'

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo 'Root required (run with sudo).' >&2
    exit 1
  fi
}

valid_iface() {
  case "$1" in
    ''|*[!a-zA-Z0-9._-]*) return 1 ;;
    *) return 0 ;;
  esac
}

detect_hostonly_if() {
  found=$(/usr/sbin/ip -o -4 addr show | awk -v ip="$LAB_IP/" '$4 ~ ("^" ip) {print $2}' | sort -u)
  if [ -z "$found" ] && ls /etc/netplan/*.yaml >/dev/null 2>&1; then
    found=$(awk '
      /^[[:space:]]*ethernets:[[:space:]]*$/ {in_eth=1; eth_indent=match($0,/[^ ]/)-1; next}
      in_eth {
        ind=match($0,/[^ ]/)-1
        if (ind <= eth_indent && $0 ~ /[^[:space:]]/) {in_eth=0; next}
        if ($0 ~ /^[[:space:]]*[a-zA-Z0-9._-]+:[[:space:]]*$/) {
          if (iface == "" || ind == if_indent) {
            if_indent=ind; iface=$1; sub(/:$/, "", iface)
          }
        }
        if ($0 ~ /192\.168\.217\.10\// && iface != "") {print iface; exit}
      }
    ' /etc/netplan/*.yaml)
  fi
  count=$(printf '%s\n' "$found" | sed '/^$/d' | wc -l)
  if [ "$count" -ne 1 ] || ! valid_iface "$found"; then
    echo "Cannot uniquely determine Host-Only interface for $LAB_IP" >&2
    exit 1
  fi
  printf '%s\n' "$found"
}

detect_nat_ifs() {
  host_if=$1
  for dev in /sys/class/net/*; do
    [ -e "$dev" ] || continue
    name=$(basename "$dev")
    [ "$name" = 'lo' ] && continue
    [ "$name" = "$host_if" ] && continue
    [ -f "$dev/type" ] || continue
    [ "$(cat "$dev/type")" = '1' ] || continue
    valid_iface "$name" || continue
    printf '%s\n' "$name"
  done
}

apply_ipv6_lock() {
  /usr/sbin/ip6tables-restore <<'EOF'
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
COMMIT
EOF
}

apply_phase2_rules() {
  host_if=$1
  /usr/sbin/iptables-restore <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i $host_if -s $HOST_IP/32 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
-A OUTPUT -o $host_if -j DROP
-A OUTPUT -d 192.168.0.0/16 -j DROP
-A OUTPUT -d 10.0.0.0/8 -j DROP
-A OUTPUT -d 172.16.0.0/12 -j DROP
COMMIT
EOF
  apply_ipv6_lock
}

phase2() {
  require_root
  host_if=$(detect_hostonly_if)
  if [ -d "/sys/class/net/$host_if" ]; then
    for nat_if in $(detect_nat_ifs "$host_if"); do
      if /usr/bin/systemctl is-active --quiet systemd-networkd.service 2>/dev/null; then
        /usr/bin/networkctl down "$nat_if" >/dev/null 2>&1 || true
      fi
      /usr/sbin/ip addr flush dev "$nat_if" >/dev/null 2>&1 || true
      /usr/sbin/ip link set dev "$nat_if" down >/dev/null 2>&1 || true
    done
  fi
  apply_phase2_rules "$host_if"
  echo "phase2_locked host_only=$host_if"
}

write_nat_netplan() {
  nat_if=$1
  tmp=$(mktemp /etc/netplan/.60-malpdf-nat.XXXXXX)
  trap 'rm -f "$tmp"' EXIT HUP INT TERM
  cat > "$tmp" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    $nat_if:
      dhcp4: true
      dhcp6: false
      optional: true
      activation-mode: manual
EOF
  chmod 0600 "$tmp"
  chown root:root "$tmp"
  mv "$tmp" "$NETPLAN_NAT"
  trap - EXIT HUP INT TERM
}

phase1() {
  require_root
  host_if=$(detect_hostonly_if)
  nat_ifs=$(detect_nat_ifs "$host_if")
  nat_count=$(printf '%s\n' "$nat_ifs" | sed '/^$/d' | wc -l)
  if [ "$nat_count" -eq 0 ]; then
    echo 'No secondary NAT interface found; add Adapter 2 (NAT) in VMware first.' >&2
    exit 1
  fi
  if [ "$nat_count" -ne 1 ]; then
    echo 'Multiple secondary interfaces found; refusing ambiguous NAT activation.' >&2
    exit 1
  fi
  nat_if=$nat_ifs
  echo 'WARNING: Phase 1 enables NAT Internet on this VM. Never run this after untrusted PDFs without reverting snapshot first.' >&2
  write_nat_netplan "$nat_if"
  /usr/sbin/netplan apply
  /usr/sbin/iptables-restore <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i $host_if -s $HOST_IP/32 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -i $nat_if -p udp --sport 67:68 --dport 67:68 -j ACCEPT
-A OUTPUT -o $host_if -j DROP
-A OUTPUT -o $nat_if -p udp --dport 67:68 -j ACCEPT
COMMIT
EOF
  apply_ipv6_lock
  /usr/sbin/ip link set dev "$nat_if" up
  /usr/bin/networkctl up "$nat_if" >/dev/null 2>&1 || true
  nat_gw=''
  wait_sec=0
  while [ "$wait_sec" -lt 15 ]; do
    nat_gw=$(/usr/sbin/ip -4 route show dev "$nat_if" default | awk '/^default/ {for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}')
    [ -n "$nat_gw" ] && break
    sleep 1
    wait_sec=$((wait_sec + 1))
  done
  if [ -z "$nat_gw" ]; then
    phase2 >/dev/null
    echo "NAT interface $nat_if did not obtain a default gateway within 15s; reverted to phase2_locked." >&2
    exit 1
  fi
  case "$nat_gw" in
    *[!0-9.]*)
      phase2 >/dev/null
      echo 'Invalid NAT gateway IPv4 address; reverted to phase2_locked.' >&2
      exit 1
      ;;
  esac
  /usr/sbin/iptables-restore <<EOF
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A INPUT -i $host_if -s $HOST_IP/32 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -i $nat_if -p udp --sport 67:68 --dport 67:68 -j ACCEPT
-A OUTPUT -o $host_if -j DROP
-A OUTPUT -o $nat_if -p udp --dport 67:68 -j ACCEPT
-A OUTPUT -o $nat_if -d $nat_gw/32 -p udp --dport 53 -j ACCEPT
-A OUTPUT -o $nat_if -d $nat_gw/32 -p tcp --dport 53 -j ACCEPT
-A OUTPUT -d 192.168.0.0/16 -j DROP
-A OUTPUT -d 10.0.0.0/8 -j DROP
-A OUTPUT -d 172.16.0.0/12 -j DROP
-A OUTPUT -d 169.254.0.0/16 -j DROP
-A OUTPUT -d 100.64.0.0/10 -j DROP
-A OUTPUT -o $nat_if -m conntrack --ctstate NEW -j ACCEPT
COMMIT
EOF
  apply_ipv6_lock
  echo "phase1_nat host_only=$host_if nat=$nat_if gateway=$nat_gw"
}

canonicalize_rules() {
  awk '
    {
      gsub(/--ctstate ESTABLISHED,RELATED/, "--ctstate RELATED,ESTABLISHED")
      gsub(/-m tcp --dport 22/, "--dport 22")
      if (match($0, /-s 192\.168\.217\.1\/32 -i [^ ]+/)) {
        seg = substr($0, RSTART, RLENGTH)
        split(seg, p, " ")
        sub(/-s 192\.168\.217\.1\/32 -i [^ ]+/, "-i " p[4] " -s 192.168.217.1/32")
      }
      print
    }
  '
}

status() {
  require_root
  host_if=$(detect_hostonly_if)
  nat_list=''
  nat_up='false'
  for nat_if in $(detect_nat_ifs "$host_if"); do
    if [ -n "$nat_list" ]; then
      nat_list="$nat_list,\"$nat_if\""
    else
      nat_list="\"$nat_if\""
    fi
    if /usr/sbin/ip -o link show dev "$nat_if" | grep -qE '(<|,)UP(,|>)'; then
      nat_up='true'
    fi
  done
  in_rules=$(/usr/sbin/iptables -S INPUT)
  fwd_rules=$(/usr/sbin/iptables -S FORWARD)
  out_rules=$(/usr/sbin/iptables -S OUTPUT)
  v6_in=$(/usr/sbin/ip6tables -S INPUT)
  v6_fwd=$(/usr/sbin/ip6tables -S FORWARD)
  v6_out=$(/usr/sbin/ip6tables -S OUTPUT)
  nat_tbl=$(/usr/sbin/iptables -t nat -S)
  mangle_v4=$(/usr/sbin/iptables -t mangle -S)
  mangle_v6=$(/usr/sbin/ip6tables -t mangle -S)
  in_pol=$(printf '%s\n' "$in_rules" | awk '$1=="-P" {print $3; exit}')
  fwd_pol=$(printf '%s\n' "$fwd_rules" | awk '$1=="-P" {print $3; exit}')
  out_pol=$(printf '%s\n' "$out_rules" | awk '$1=="-P" {print $3; exit}')
  v6_pol=$(printf '%s\n' "$v6_out" | awk '$1=="-P" {print $3; exit}')
  host_blocked='false'
  rfc_blocked='false'
  ssh_ok='false'
  printf '%s\n' "$out_rules" | grep -Fq -- "-A OUTPUT -o $host_if -j DROP" && host_blocked='true'
  if printf '%s\n' "$out_rules" | grep -Fq -- '-A OUTPUT -d 192.168.0.0/16 -j DROP' &&
     printf '%s\n' "$out_rules" | grep -Fq -- '-A OUTPUT -d 10.0.0.0/8 -j DROP' &&
     printf '%s\n' "$out_rules" | grep -Fq -- '-A OUTPUT -d 172.16.0.0/12 -j DROP'; then
    rfc_blocked='true'
  fi
  printf '%s\n' "$in_rules" | grep -Eq -- "^-A INPUT (-i $host_if -s $HOST_IP/32|-s $HOST_IP/32 -i $host_if) -p tcp (-m tcp )?--dport 22 -m conntrack --ctstate NEW -j ACCEPT$" && ssh_ok='true'
  canon_in=$(printf '%s\n' "$in_rules" | canonicalize_rules)
  canon_out=$(printf '%s\n' "$out_rules" | canonicalize_rules)
  exp_in=$(cat <<EOF
-P INPUT DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A INPUT -i $host_if -s $HOST_IP/32 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
EOF
)
  exp_out=$(cat <<EOF
-P OUTPUT DROP
-A OUTPUT -o lo -j ACCEPT
-A OUTPUT -m conntrack --ctstate INVALID -j DROP
-A OUTPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A OUTPUT -o $host_if -j DROP
-A OUTPUT -d 192.168.0.0/16 -j DROP
-A OUTPUT -d 10.0.0.0/8 -j DROP
-A OUTPUT -d 172.16.0.0/12 -j DROP
EOF
)
  exp_v6_in=$(cat <<'EOF'
-P INPUT DROP
-A INPUT -i lo -j ACCEPT
EOF
)
  exp_v6_out=$(cat <<'EOF'
-P OUTPUT DROP
-A OUTPUT -o lo -j ACCEPT
EOF
)
  exp_nat=$(cat <<'EOF'
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
EOF
)
  exp_mangle=$(cat <<'EOF'
-P PREROUTING ACCEPT
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-P POSTROUTING ACCEPT
EOF
)
  rules_exact='false'
  if [ "$canon_in" = "$exp_in" ] && [ "$fwd_rules" = '-P FORWARD DROP' ] && [ "$canon_out" = "$exp_out" ] &&
     [ "$v6_in" = "$exp_v6_in" ] && [ "$v6_fwd" = '-P FORWARD DROP' ] && [ "$v6_out" = "$exp_v6_out" ] &&
     [ "$nat_tbl" = "$exp_nat" ] && [ "$mangle_v4" = "$exp_mangle" ] && [ "$mangle_v6" = "$exp_mangle" ]; then
    rules_exact='true'
  fi
  mode='unconfigured'
  if [ "$in_pol" = 'DROP' ] && [ "$fwd_pol" = 'DROP' ] && [ "$out_pol" = 'DROP' ] && [ "$v6_pol" = 'DROP' ] &&
     [ "$host_blocked" = 'true' ] && [ "$rfc_blocked" = 'true' ] && [ "$ssh_ok" = 'true' ]; then
    if [ "$nat_up" = 'false' ] && [ "$rules_exact" = 'true' ]; then
      mode='phase2_locked'
    elif [ "$nat_up" = 'true' ]; then
      mode='phase1_nat'
    fi
  fi
  printf '{"host_only_if":"%s","nat_ifs":[%s],"nat_up":%s,"ipv4_policy":{"INPUT":"%s","FORWARD":"%s","OUTPUT":"%s"},"ipv6_output_policy":"%s","hostonly_outbound_blocked":%s,"rfc1918_blocked":%s,"ssh_inbound_restricted":%s,"mode":"%s"}\n' \
    "$host_if" "$nat_list" "$nat_up" "$in_pol" "$fwd_pol" "$out_pol" "$v6_pol" "$host_blocked" "$rfc_blocked" "$ssh_ok" "$mode"
}

install_boot() {
  require_root
  src=$0
  if [ "$src" != "$INSTALL_BIN" ]; then
    install -o root -g root -m 0755 "$src" "$INSTALL_BIN"
  fi
  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=MalPDF 1-way stateful firewall (Phase 2 locked)
DefaultDependencies=no
After=local-fs.target
Before=network-pre.target systemd-networkd.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=30
ExecStart=$INSTALL_BIN phase2

[Install]
WantedBy=network-pre.target multi-user.target
EOF
  chmod 0644 "$UNIT_PATH"
  chown root:root "$UNIT_PATH"
  /usr/bin/systemctl daemon-reload
  /usr/bin/systemctl disable malpdf-firewall.service >/dev/null 2>&1 || true
  /usr/bin/systemctl enable malpdf-firewall.service
  "$INSTALL_BIN" phase2
}

case "${1:-}" in
  phase2|apply) phase2 ;;
  phase1|nat-up) phase1 ;;
  status|check) status ;;
  install-boot) install_boot ;;
  *)
    echo 'Usage: lab_firewall.sh {phase2|phase1|status|install-boot}' >&2
    exit 2
    ;;
esac
