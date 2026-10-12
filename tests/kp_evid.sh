#!/usr/bin/env bash
# ad-hoc: capture retdyn4 retval distribution (forced ifindex evidence).
# enp0s3 (deb13) ifindex = 2.
source "$(dirname "$0")/lib.sh"
S_NAME=S1kpr
TBL=dynrt_s1k
cleanup() {
  nft_drop "$TBL" 2>/dev/null
  r 'ip route replace 192.168.200.0/24 dev enp0s3 2>/dev/null; true'
  kp_disarm
}
trap cleanup EXIT

r 'ip route replace 192.168.200.0/24 dev enp0s8 2>/dev/null; true'
nft_apply "$TBL" <<DEF > /dev/null
table inet dynrt_s1k {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		iifname "enp0s3"
		ip daddr 192.168.200.12
		# proto-restricted to the test flow: slots must not be written
		# for unrelated ct (management SSH on this iface) -- report "ambient-pass"
		icmp type echo-request
		DYNSRCROUTE
	}
}
DEF
kp_arm
hping "$D13_IP" 8
sleep 1

echo "=== retdyn4 arg1 distribution (enp0s3=0x2) ==="
rs <<'EOF'
grep ' retdyn4:' /sys/kernel/tracing/trace | grep -o 'arg1=0x[0-9a-fA-F]*' | sort | uniq -c | sort -rn
EOF
echo "=== sample forced (arg1=2) lines ==="
rs <<'EOF'
grep ' retdyn4:' /sys/kernel/tracing/trace | grep 'arg1=2' | tail -3 | sed 's/^\s*//'
EOF
echo "KPEVID_DONE"
