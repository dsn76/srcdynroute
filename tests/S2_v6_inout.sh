#!/usr/bin/env bash
# S2 -- L3/L4 on IPv6, INPUT/OUTPUT (v6 mirror of S1).
#
# Topology (VERIFIED by ND captures -- two separate L2 segments, NOT one
# shared L2):
#   seg1: host enp4s0 <-> deb13 enp0s3
#   seg2: host brvm0  <-> deb13 enp0s8
# A neighbour solicitation leaving deb13 enp0s8 arrives at host brvm0 and
# the host does NOT answer it for an address it does not own on brvm0
# (that is why the first S2 attempts got 0/5 locally-generated delivery
# with the ND entry stuck FAILED).  Hence the ULA fd00:db8:beef::67 is
# assigned to BOTH host interfaces and ::12 to BOTH deb13 interfaces.
#
# Anomaly (verified buildable in this environment, iproute2 6.15):
#   ip -6 route replace fd00:db8:beef::67 dev enp0s8
# a /128 more specific than the /64; it steals unpinned lookups toward
# enp0s8 (ip -6 route get ::67 -> dev enp0s8).
#
# Kernel semantics (net/ipv6/icmp.c, verified in-tree): a v6 echo REPLY is
# a locally-generated packet whose lookup is oif-pinned to the ingress
# interface (icmpv6_echo_reply: flowi6_oif = icmp6_iif(skb)).  Therefore
# the host-side ping's reply leaves enp0s3 with or without the rule and is
# NOT the forcing evidence.  The evidence is locally-generated v6 FROM deb13
# (oif-unpinned ip6_route_output_flow -> dynrt_force_oif_fl6 hook):
#   no rule      : /128 wins -> egress enp0s8 (seg2)
#   rule + anchor: forced flowi6_oif=enp0s3 (RT6_LOOKUP_F_IFACE) selects
#                  the enp0s3 /64 route -> egress enp0s3 (seg1)
#
# b1 NEG: locally-generated ping6 (deb13 -> ::67) without a rule follows
#         the /128: egress enp0s8 (d8>=3); delivered 5/5 (peer owns ::67
#         on brvm0, ND resolves on seg2 -- verified by hand: 5/5, d8=7).
# b2 POS: host ping first (writes slot + anchor on the enp0s3 ingress),
#         then the same locally-generated ping6 must be forced out enp0s3.
#         The decisive egress evidence is a WIRE CAPTURE on the host during
#         the local-ping window: on seg1 (enp4s0) >=5 echo requests "fd00:
#         db8:beef::12 > fd00:db8:beef::67" and on seg2 (brvm0) <=2 of them
#         (delivery works either way -- host owns $PEER on both ifaces and
#         the veth accepts foreign-MAC unicasts with the PERMANENT ND pin --
#         so wire DIRECTION, not delivery, is the forcing evidence).
#
# ENV NOTE (syntax fix 2026-10-11): earlier probes (t4/t6/p3) appeared to
# prove that nft match expressions (`ip6 daddr`, `oifname`) are NO-OPs in
# inet hook chains -- in fact the rules had been written multi-line inside
# the chain block, which nft parses as SEPARATE per-line rules: the match
# lines became no-verdict no-ops and the counter ran unconditionally (it
# counted ALL egress, even `log`'d v4 ssh).  Rules are now single-line
# conjunctions, so scoped counters only count the matched flow.  All nft
# counters below stay INFORMATIONAL; the verdict relies on wire captures,
# additive raw-iface lower bounds and delivery.
#
#   b0  baseline v6 ping (host -> deb13, seg1)  (5/5, egress enp0s3)
#   b1  NEG: misroute ::67 dev enp0s8, NO rule
#       locally-generated ping6: egress enp0s8, delivered
#   b2  POS: same misroute + DYNSRCROUTE/DYNRT rule
#       host ping 5/5; locally-generated ping6: delivered 5/5, wire shows
#       >=5 echo req on seg1 / <=2 on seg2 (d3loc>=4; raw d8loc and the
#       nft counters are informational -- wire captures decide)
#
# PASS = b0 + b1-NEG + b2-POS + dmesg clean
S_NAME=S2
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s2
V6D=fd00:db8:beef
PEER=${V6D}::67
SELF=${V6D}::12

declare -A EVID
cleanup() {
  nft_drop "$TAB" || true
  r "ip -6 route del $PEER 2>/dev/null || true"
  r "ip -6 addr del $SELF/64 dev enp0s8 2>/dev/null || true"
  r "ip -6 addr del $SELF/64 dev enp0s3 2>/dev/null || true"
  H "ip -6 addr del $PEER/64 dev enp4s0" 2>/dev/null || true
  H "ip -6 addr del $PEER/64 dev brvm0" 2>/dev/null || true
}
trap cleanup EXIT

say "S2 : v6 input/output"

# -- v6 up on both NICs --------------------------------------------------------
# NetworkManager sets net.ipv6.conf.enp0s8.disable_ipv6=1 ([ipv6]
# method=disabled in the enp0s8 connection file) and the HOST runs with
# IPv6 disabled on enp4s0 entirely (net.ipv6.conf.all.disable_ipv6=1) --
# force v6 on both sides BEFORE adding the ULA addresses, otherwise the
# sysctl state is what the kernel had at link-up and the address is
# refused (cannot assign address) / DAD never completes.
r "sysctl -qw net.ipv6.conf.enp0s3.disable_ipv6=0 && sysctl -qw net.ipv6.conf.enp0s8.disable_ipv6=0"
H "sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.enp4s0.disable_ipv6=0 net.ipv6.conf.brvm0.disable_ipv6=0" 2>/dev/null || true
# NOTE on background v6: the box runs avahi mDNS (D-Bus activated; it CANNOT
# be stopped -- `systemctl stop` gets its job canceled and the daemon is
# re-activated) and the test transport itself is a v4 ssh session over seg1.
# Additionally (syntax fix 2026-10-11): the earlier "PROVEN (t4/t6/p3)"
# claim that nft match expressions are NO-OPs in hook chains was an artifact
# of the old multi-line rule syntax (per-line rules -> unconditional
# counters matching ALL egress, even v4 ssh), not an nft/kernel defect.  The
# discriminating evidence is therefore (a) additive LOWER bounds on raw
# iface deltas (background can only help), (b) wire-level tcpdump captures
# of the exact echo-request flows on both segments, and (c) the module's own
# forced-oif behavior via kprobes (informational).
r "ip -6 addr replace $SELF/64 dev enp0s3 && echo D13_V6_OK"
r "ip -6 addr replace $SELF/64 dev enp0s8 && echo D13_V6_8"
H "ip -6 addr replace $PEER/64 dev enp4s0 && echo HOST_V6_OK"
# seg2 delivery (b1): the host must own ::67 on brvm0 as well
H "ip -6 addr replace $PEER/64 dev brvm0 && echo HOST_V6_BR"
sleep 3   # v6 DAD (tentative -> reachable) on both sides

# -- b0 baseline ---------------------------------------------------------------
t3a=$(t13 enp0s3 tx_packets); t8a=$(t13 enp0s8 tx_packets)
r1a=$(dh enp4s0 rx_packets);  r2a=$(dh brvm0 rx_packets)
b0=$(pv6ping "$SELF" 5)   # host -> deb13 ($SELF owns no host-local addr, so the
                          # frames actually cross seg1; $PEER is the HOST's
                          # own address and would loop back on the host)
t3b=$(t13 enp0s3 tx_packets); t8b=$(t13 enp0s8 tx_packets)
r1b=$(dh enp4s0 rx_packets);  r2b=$(dh brvm0 rx_packets)
d3=$((t3b - t3a)); d8=$((t8b - t8a)); h1=$((r1b - r1a)); h2=$((r2b - r2a))
say "b0 baseline ping=$b0  d(enp0s3 tx)=$d3 d(enp0s8 tx)=$d8 d(host enp4s0 rx)=$h1 d(host brvm0 rx)=$h2  (d8 background-polluted: informational only)"
case "$b0" in 5/5) [ "${d3:-0}" -ge 5 ] && EVID[b0]=OK || EVID[b0]="bad(egress d3=$d3)" ;; *) EVID[b0]="bad($b0)" ;; esac
case "${EVID[b0]}" in OK) : ;; *) finish FAIL "baseline broken: ${EVID[b0]}"; exit 1 ;; esac

# ---- b1 NEG : misroute, no rule ----------------------------------------------
say "b1 NEG: ip -6 route replace $PEER dev enp0s8 (no rule); locally-generated v6 must follow it"
g0=$(r "ip -6 route get $PEER" | tr -d '[:space:]\n')
echo "    pre  : $g0"
r "ip -6 route replace $PEER dev enp0s8 && echo MIS6_ON" >/dev/null || { bad "v6 misroute failed"; finish FAIL "misroute failed"; exit 1; }
g1=$(r "ip -6 route get $PEER" | tr -d '[:space:]\n')
echo "    post : $g1"
# NOTE: $g1 is whitespace-stripped (tr -d above) -> grep "devenp0s8", not "dev enp0s8"
grep -q "devenp0s8" <<<"$g1" || { bad "misroute not effective (route get: $g1)"; finish FAIL "misroute not effective"; exit 1; }

# The evidence ping is locally generated on deb13: oif-unpinned
# ip6_route_output_flow -> plain fib6 lookup -> the /128 (enp0s8) wins.
b1host=$(pv6ping "$SELF" 5)   # host -> deb13; informational; reply is oif-pinned (see header)
t3a=$(t13 enp0s3 tx_packets); t8a=$(t13 enp0s8 tx_packets)
b1local=$(r "ping6 -c 5 -W 1 $PEER >/dev/null 2>&1 && echo 5/5 || echo 0/5")
t3b=$(t13 enp0s3 tx_packets); t8b=$(t13 enp0s8 tx_packets)
d3=$((t3b - t3a)); d8=$((t8b - t8a))
say "b1 host-ping=$b1host local-ping6=$b1local  d(enp0s3 tx)=$d3 d(enp0s8 tx)=$d8"

# NOTE: d3 is NOT a discriminator here -- background v6 replies from deb13
# are oif-pinned to enp0s3 (icmp6_iif) in BOTH b1 and b2 and would pollute
# any d3 window.  d8 (enp0s8 tx) is clean: only oif-unpinned v6 ever leaves
# there, i.e. the local ping itself.
neg_ok=NO
if [ "${b1local}" = "5/5" ] && [ "${d8:-0}" -ge 3 ]; then
  neg_ok=YES; ok "NEG: locally-generated v6 delivered and left enp0s8 (d8=$d8; misroute effective, module absent)"
else
  bad "NEG: b1local=$b1local d3=$d3 d8=$d8 (expected 5/5 and d8>=3)"
fi
EVID[b1_NEG]=$neg_ok"local=$b1local|d3=$d3|d8=$d8|host=$b1host"

# ---- b2 POS : misroute still + rule ------------------------------------------
say "b2 POS: apply rule (DYNSRCROUTE prerouting enp0s3 / DYNRT+counter output)"
out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s2 {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow: slots must not be written
		# for unrelated ct (management SSH on this iface) -- report "ambient-pass"
		iifname "enp0s3" ip6 daddr fd00:db8:beef::12 icmpv6 type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip6 daddr fd00:db8:beef::67 DYNRT counter
	}
	# INFORMATIONAL counter only (ENV NOTE in header): since the
	# 2026-10-11 syntax fix chain w correctly conjoins ip6 daddr +
	# oifname, so it counts only $PEER-bound v6 egress on enp0s8.
	# Kept as supporting evidence in the evidence line (the wire
	# capture remains the decisive verdict input).
	chain w {
		type filter hook output priority filter; policy accept;
		ip6 daddr fd00:db8:beef::67 oifname "enp0s8" counter
	}
}
DEF
)
say "b2 nft: $(tr '\n' ' ' <<<"$out")"
grep -q NFT_OK <<<"$out" || { finish FAIL "nft apply failed"; exit 1; }

kp_arm
CNT0=$(nft_cnt inet "$TAB")
W0=$(r "$NFT list chain inet $TAB w 2>/dev/null" | sed -n 's/.*packets \([0-9][0-9]*\).*/\1/p' | head -1)
t3a=$(t13 enp0s3 tx_packets); t8a=$(t13 enp0s8 tx_packets)
r1a=$(dh enp4s0 rx_packets);  r2a=$(dh brvm0 rx_packets)
b2=$(pv6ping "$SELF" 5)   # host -> deb13: writes slot + anchor (iif enp0s3);
                          # reply egress enp0s3 (oif-pinned, informational)
                          # (must be $SELF: $PEER is a host-local address and
                          # would loop back on the host, never firing eval)
t3m=$(t13 enp0s3 tx_packets); t8m=$(t13 enp0s8 tx_packets)
# Defensive: pin the deb13 ND entry for ::67 to the seg2 (brvm0) MAC and
# make it REACHABLE, so the forced b2 TX is never blocked by ND state.
# (If the entry were FAILED, ping6 would re-solicit out enp0s8 and pollute
# d8loc, producing a false NEGATIVE for the forcing.)
# Parse the MAC from `ip link` (NOT `-br`): on this host the -br view of
# brvm0 puts a FLAGS field last, so `awk $NF` once produced
# "BROADCAST,MULTICAST,UP,LOWER_UP" which was then executed as a remote
# command (the old "BROADCAST...: command not found" during S2).
BRMAC=$(ip link show brvm0 2>/dev/null | grep -oE 'ether [0-9a-f]{2}(:[0-9a-f]{2}){5}' | awk '{print $NF}' | head -1)
if [[ "$BRMAC" =~ ^[0-9a-f]{2}(:[0-9a-f]{2}){5}$ ]]; then
  r "ip -6 neigh replace $PEER lladdr $BRMAC dev enp0s8 2>/dev/null || true"
else
  say "WARNING: brvm0 MAC parse failed (got '$BRMAC'); skipping ND pin"
fi
# now the real forcing evidence: locally-generated v6, same misroute still in
# place.  Unpinned lookup would pick the /128 (enp0s8); the anchor forces
# flowi6_oif=enp0s3 in ip6_route_output_flow.  Delivery is EXPECTED to work
# EITHER way (host owns $PEER on both ifaces and the veth accepts foreign-
# MAC unicasts with the PERMANENT pin) -- so the wire DIRECTION, not the
# delivery, is the forcing evidence: capture both segments while pinging.
CAP1=/tmp/opencode/s2_seg1_cap.log
CAP2=/tmp/opencode/s2_seg2_cap.log
rm -f "$CAP1" "$CAP2"
H "timeout 12 tcpdump -nn -i enp4s0 -s0 'ip6' > $CAP1 2>&1" &
CAPPID1=$!
H "timeout 12 tcpdump -nn -i brvm0 -s0 'ip6' > $CAP2 2>&1" &
CAPPID2=$!
sleep 1   # tcpdump startup before the ping window starts
b2local=$(r "ping6 -c 5 -W 1 $PEER >/dev/null 2>&1 && echo 5/5 || echo 0/5")
wait "$CAPPID1" "$CAPPID2" 2>/dev/null
t3b=$(t13 enp0s3 tx_packets); t8b=$(t13 enp0s8 tx_packets)
r1b=$(dh enp4s0 rx_packets);  r2b=$(dh brvm0 rx_packets)
d3=$((t3b - t3a)); d8=$((t8b - t8a)); h1=$((r1b - r1a)); h2=$((r2b - r2a))
d3loc=$((t3b - t3m)); d8loc=$((t8b - t8m))
CNT=$(nft_cnt inet "$TAB")
dCNT=$(cnt_delta "$CNT0" "$CNT")
W1=$(r "$NFT list chain inet $TAB w 2>/dev/null" | sed -n 's/.*packets \([0-9][0-9]*\).*/\1/p' | head -1)
case $W0 in '' | *[!0-9]*) W0=0 ;; esac
case $W1 in '' | *[!0-9]*) W1=0 ;; esac
W8=$((W1 > W0 ? W1 - W0 : 0))
# Wire-level egress evidence (the real discriminator, see header):
EPAT="fd00:db8:beef::12 > fd00:db8:beef::67: ICMP6, echo request"
SEGI=$(grep -cE "$EPAT" "$CAP1" 2>/dev/null); case $SEGI in '' | *[!0-9]*) SEGI=0 ;; esac
SEG2=$(grep -cE "$EPAT" "$CAP2" 2>/dev/null); case $SEG2 in '' | *[!0-9]*) SEG2=0 ;; esac
say "b2 WIRE: seg1 echo req match = $SEGI (expect >=5); seg2 match = $SEG2 (expect <=2)"
echo "    seg1 capture ($CAP1):";  head -10 "$CAP1" 2>/dev/null | sed 's/^/      /'
echo "    seg2 capture ($CAP2):";  head -10 "$CAP2" 2>/dev/null | sed 's/^/      /'
KP=$(kp_count | tr '\n' ' ')
KPR=$(kp_retvals retdyn6 | sed 's/^[[:space:]]*//;s/\t/ /g' | tr '\n' ' | ')
DM=$(dm_bad | tr '\n' ' | ')
say "b2 host-ping=$b2 local-ping6=$b2local  d(enp0s3 tx)=$d3 d(enp0s8 tx)=$d8 d(host enp4s0 rx)=$h1 d(host brvm0 rx)=$h2"
say "b2 local-ping6 egress(enp0s3)=$d3loc egress(enp0s8-raw)=$d8loc (raw counters bg-polluted, informational)"
say "b2 nft counters (informational: scoped conjunctions after syntax fix 2026-10-11): DYNRT chain m $CNT0->$CNT dCNT=$dCNT; chain w $W0->$W1 w8=$W8"
say "b2 kprobes: $KP"
say "b2 dmesg anomalies: ${DM-<none>}"

# Verdict: the WIRE captures are the egress discriminator (nft scoped
# counters are informational only -- ENV NOTE in header).  SEGI>=5 means
# >=5 of the local echo requests visibly left enp0s3; SEG2<=2 means
# essentially none left enp0s8, even though the /128 misroute and the ND
# PERMANENT pin both favor enp0s8.  d3loc is an additive lower bound.
pos_ok=NO
case "$b2:$b2local" in
  5/5:5/5) if [ "${SEGI:-0}" -ge 5 ] && [ "${SEG2:-0}" -le 2 ] && [ "${d3loc:-0}" -ge 4 ]; then
             pos_ok=YES; ok "POS: local v6 delivered 5/5, wire shows $SEGI echo req on seg1 (>=5) and $SEG2 on seg2 (<=2), d3loc=$d3loc -> forced oif beats /128"
           else
             bad "POS: SEGI=$SEGI (>=5) SEG2=$SEG2 (<=2) d3loc=$d3loc (>=4); captures: $CAP1 $CAP2"
           fi ;;
  *)  bad "POS: host=$b2 local=$b2local (expected 5/5:5/5); SEGI=$SEGI SEG2=$SEG2 d3loc=$d3loc" ;;
esac
EVID[b2_POS]=$pos_ok"$b2|local=$b2local|SEGI=$SEGI|SEG2=$SEG2|d3loc=$d3loc|d8loc=$d8loc|cnt=$CNT0->$CNT,dCNT=$dCNT|kp=$KP|kpr=$KPR"

if [ "$neg_ok" = YES ] && [ "$pos_ok" = YES ] && [ -z "${DM:-}" ]; then
  finish PASS "b0=5/5 b1NEG=${EVID[b1_NEG]} b2POS=${EVID[b2_POS]} dmesg=clean"
else
  finish FAIL "b0=${EVID[b0]} b1=$neg_ok b2=$pos_ok dm=${DM:-na} :: ${EVID[*]}"
fi
