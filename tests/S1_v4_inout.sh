#!/usr/bin/env bash
# S1 -- L3/L4 on IPv4, INPUT/OUTPUT, interface discrimination.
#
# Topology (VERIFIED by live wire captures -- two SEPARATE L2 segments):
#   seg1: host enp4s0 (192.168.200.67) <--> deb13 enp0s3 (192.168.200.12)
#   seg2: host brvm0  (192.168.129.1)  <--> deb13 enp0s8 (192.168.129.12)
#   A packet egressing deb13 enp0s8 is visible ONLY on the brvm0 capture
#   (enp4s0 capture = 0), and vice versa.
#
# Kernel semantics (net/ipv4/icmp.c, 6.12.111): the v4 echo REPLY is a
# locally-generated packet but, unlike v6 (flowi6_oif = icmp6_iif), it is
# NOT oif-pinned (flowi4_oif = l3mdev_master_ifindex(skb->dev) -> 0 on a
# plain NIC), so its egress follows the FIB.  Also: the reply's source
# address is always the request's destination (192.168.200.12), regardless
# of egress iface -- so the WIRE LOCATION of the reply (seg1 vs seg2
# capture), not its bytes, is the egress discriminator.
#
# NOTE (env): the 2026-10-11 syntax fix: the rules were previously written
# multi-line inside the chain block, which nft parses as SEPARATE per-line
# rules -- the match lines became no-verdict no-ops and counter/DYNSRCROUTE/
# DYNRT ran unconditionally (this was misdiagnosed as "match expressions are
# no-ops").  Rules are now single-line conjunctions; nft counters below are
# valid again (still kept informational for the wire-capture verdict).  The
# test's own v4 SSH transport runs over seg1 (enp0s3) polluting raw tx
# counters -- so raw iface deltas below are INFORMATIONAL only; the verdict
# rests on wire captures (exact echo-reply tuple per segment) + delivery +
# dmesg.
#
# Plan
#   b0  baseline: ping A->deb13 without rules           (expect 5/5)
#   b1  NEG: misroute 192.168.200.0/24 -> enp0s8, NO rule.
#       The reply is not forced and must follow the misroute out enp0s8:
#       echo-reply tuple >= 5 in the SEG2 (brvm0) capture, <= 2 in SEG1
#       (enp4s0).  The module's nft EXPRESSIONS must not fire (tagop/tgmop
#       = 0).  NOTE: the oif/mac ops (dyn4/dyn6/dynsk/macop) fire on EVERY
#       local route/neighbor lookup while the module is loaded -- the kernel
#       (net/ipv4/ipv6 route.c -> nf_dynrt.c) consults them per flowi, so
#       those probe counts are always > 0 on a busy box and are
#       informational only.
#   b2  POS: same misroute + rule (DYNSRCROUTE in prerouting on enp0s3,
#       DYNRT in output).  Forced FIB lookup must reject the /24
#       (nhc_oif = enp0s8) and route the reply out enp0s3: echo-reply
#       tuple >= 5 in the SEG1 (enp4s0) capture, <= 2 in SEG2; retdyn4
#       retval 2 (enp0s3 ifindex) is supporting soft evidence.
#
# PASS = baseline OK && NEG reply on seg2 wire && POS 5/5 + reply on
#        seg1 wire + dmesg clean.

S_NAME=S1
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s1

REPLY_RE=$(printf '192\.168\.200\.12 > 192\.168\.200\.67: ICMP echo reply')
CAP1=/tmp/opencode/s1_seg1_cap.log
CAP2=/tmp/opencode/s1_seg2_cap.log

cleanup() {
  nft_drop "$TAB" || true
  bh_off "$A_IP" 2>/dev/null || true
  r "ip route replace 192.168.200.0/24 dev enp0s3 2>/dev/null || true"
  kp_disarm || true
}
trap cleanup EXIT

# wire_ping -- run the hping window under tcpdump on both host segments;
# prints "rcvd/sent SEGI SEG2" (SEGI/SEG2 = echo-reply tuple hits).
wire_ping() {
  local b out s1 s2
  rm -f "$CAP1" "$CAP2"
  H "timeout 10 tcpdump -nn -i enp4s0 -s0 'icmp' > $CAP1 2>&1" &
  local p1=$!
  H "timeout 10 tcpdump -nn -i brvm0 -s0 'icmp' > $CAP2 2>&1" &
  local p2=$!
  sleep 1   # tcpdump startup before the ping window starts
  b=$(hping "$D13_IP" 5)
  wait "$p1" "$p2" 2>/dev/null
  s1=$(grep -cE "$REPLY_RE" "$CAP1" 2>/dev/null); case $s1 in '' | *[!0-9]*) s1=0 ;; esac
  s2=$(grep -cE "$REPLY_RE" "$CAP2" 2>/dev/null); case $s2 in '' | *[!0-9]*) s2=0 ;; esac
  say "    WIRE: seg1(enp4s0) echo-reply=$s1  seg2(brvm0) echo-reply=$s2" >&2
  echo "$b $s1 $s2"
}

declare -A EVID
say "S1 : v4 input/output, iface misroute discrimination"
rt_snap | sed 's/^/    route> /'

b0=$(hping "$D13_IP" 5)
say "b0 baseline ping A->deb13 : $b0"
case "$b0" in 5/5) EVID[b0]=OK ;; *) EVID[b0]="bad($b0)" ;; esac

# ---- b1 NEG : misroute, no rule -------------------------------------------
say "b1 NEG: ip route replace 192.168.200.0/24 dev enp0s8 (no rule)"
mis 192.168.200.0/24 enp0s8 || { bad "misroute failed"; finish FAIL "misroute failed"; exit 1; }
KP1=$(kp_arm)
case "$KP1" in *KP_OK*) say "b1 kprobes armed (module should NOT fire: no rule)" ;; *) bad "b1 kprobe arm: $KP1" ;; esac
t3a=$(t13 enp0s3 tx_packets); t8a=$(t13 enp0s8 tx_packets)
read -r b1 SEGI SEG2 <<< "$(wire_ping)"
t3b=$(t13 enp0s3 tx_packets); t8b=$(t13 enp0s8 tx_packets)
d3=$((t3b - t3a)); d8=$((t8b - t8a))
KPB1=$(kp_count | tr '\n' ' ')
# nft-expression probes (tagop/tgmop) are the "module active" indicators;
# dyn4/dyn6/dynsk/macop fire on every route/neighbor lookup (kernel hook in
# route.c -> nf_dynrt.c) and are ALWAYS non-zero on a busy box: informational.
TGO1=$(sed -n 's/.* tagop=\([0-9][0-9]*\).*/\1/p' <<<"$KPB1"); TGO1=${TGO1:-0}
TG1=$(sed -n  's/.* tgmop=\([0-9][0-9]*\).*/\1/p' <<<"$KPB1"); TG1=${TG1:-0}
say "b1 ping=$b1  (raw deltas, INFORMATIONAL: d(enp0s3 tx)=$d3 d(enp0s8 tx)=$d8; own v4-ssh pollutes d3)"
say "b1 kprobe (tagop/tgmop must be 0 -- no nft expression; oif/mac op counts are kernel-hook noise): $KPB1"

neg_ok=NO
if [ "$b1" = 5/5 ] && [ "${SEG2:-0}" -ge 5 ] && [ "${SEGI:-0}" -le 2 ] \
   && [ "$TGO1" -eq 0 ] && [ "$TG1" -eq 0 ]; then
  neg_ok=YES; ok "NEG: reply left enp0s8 (seg2 wire=$SEG2>=5, seg1 wire=$SEGI<=2), expressions silent (tagop=0,tgmop=0) -- misroute effective, module absent"
else
  bad "NEG: ping=$b1 SEGI=$SEGI (<=2) SEG2=$SEG2 (>=5) tagop=$TGO1 tgmop=$TG1 (both 0); captures: $CAP1 $CAP2"
fi
EVID[b1_NEG]=$neg_ok"$b1|SEGI=$SEGI|SEG2=$SEG2|d3=$d3|d8=$d8|tagop=$TGO1,tgmop=$TG1|kp=$KPB1"

# ---- b2 POS : misroute + rule ----------------------------------------------
say "b2 POS: apply rule (DYNSRCROUTE prerouting enp0s3 / DYNRT+counter output)"
out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s1 {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow: slots must not be written
		# for unrelated ct (management SSH on this iface) -- report "ambient-pass"
		iifname "enp0s3" ip daddr 192.168.200.12 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 192.168.200.67 DYNRT counter
	}
}
DEF
)
say "b2 nft: $(tr '\n' ' ' <<<"$out")"
grep -q NFT_OK <<<"$out" || { finish FAIL "nft apply failed"; exit 1; }

CNT0=$(nft_cnt inet "$TAB")
t3a=$(t13 enp0s3 tx_packets); t8a=$(t13 enp0s8 tx_packets)
read -r b2 SEGI SEG2 <<< "$(wire_ping)"
t3b=$(t13 enp0s3 tx_packets); t8b=$(t13 enp0s8 tx_packets)
d3=$((t3b - t3a)); d8=$((t8b - t8a))
CNT=$(nft_cnt inet "$TAB")
dCNT=$(cnt_delta "$CNT0" "$CNT")
KP=$(kp_count | tr '\n' ' ')
KPR=$(kp_retvals retdyn4 | sed 's/^[[:space:]]*//;s/\t/ /g' | tr '\n' ' | ')
DM=$(dm_bad | tr '\n' ' | ')
say "b2 ping=$b2  (raw deltas, INFORMATIONAL: d(enp0s3 tx)=$d3 d(enp0s8 tx)=$d8)"
say "b2 DYNRT counter $CNT0 -> $CNT (dCNT=$dCNT) (dCNT informational: counts DYNRT-positive packets of the test flow)"
say "b2 kprobes: $KP"
say "b2 retdyn4 samples (2 = enp0s3 forced): $KPR"
say "b2 dmesg anomalies: ${DM-<none>}"

pos_ok=NO
if [ "$b2" = 5/5 ] && [ "${SEGI:-0}" -ge 5 ] && [ "${SEG2:-0}" -le 2 ]; then
  pos_ok=YES; ok "POS: all 5 replies delivered, wire shows $SEGI echo repl on seg1 (>=5) and $SEG2 on seg2 (<=2) -> forced oif beats /24 misroute"
else
  bad "POS: ping=$b2 SEGI=$SEGI (>=5) SEG2=$SEG2 (<=2) dCNT=$dCNT; captures: $CAP1 $CAP2"
fi
EVID[b2_POS]=$pos_ok"$b2|SEGI=$SEGI|SEG2=$SEG2|d3=$d3|d8=$d8|cnt=$CNT0->$CNT,dCNT=$dCNT|kp=$KP|kpr=$KPR"

case "${EVID[b0]}" in OK) : ;; *) finish FAIL "baseline bad: ${EVID[*]}"; exit 1 ;; esac
if [ "$neg_ok" = YES ] && [ "$pos_ok" = YES ] && [ -z "${DM:-}" ]; then
  finish PASS "b0=5/5 b1NEG=e_if=enp0s8(${EVID[b1_NEG]}) b2POS=5/5,e_if=enp0s3(${EVID[b2_POS]}) dmesg=clean"
else
  finish FAIL "b0=${EVID[b0]} b1=$neg_ok b2=$pos_ok dm=${DM:-na} :: ${EVID[*]}"
fi
