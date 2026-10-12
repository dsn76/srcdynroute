#!/usr/bin/env bash
# S4 -- FORWARD + SNAT: slot write in PREROUTING, DYNRT match in FORWARD,
#       reply egress forced through the NATed segment.
#
# Topology (all on deb13):
#   nsA4: a4r (root, 10.0.1.1/24)  <->  a4v (nsA4, 10.0.1.67/24)
#   nsB4: b4r (root, 10.0.2.1/24)  <->  b4v (nsB4, 10.0.2.20/24)
#   root: ip_forward=1; SNAT: iif a4r -> src 10.0.2.1 (segment-2 gateway
#   address, i.e. nsB4's own segment interface -- standard SNAT/masquerade
#   semantics).  Explicit fixed SNAT is used instead of MASQUERADE (determinism).
#
#   SNAT HOOK (kernel-enforced, verified in net/netfilter/nft_nat.c
#   nft_nat_validate on this 6.12.111 tree, upstream-identical check):
#     SNAT expression: POST_ROUTING or LOCAL_IN only
#     DNAT expression: PRE_ROUTING  or LOCAL_OUT only
#   So SNAT lives in the POSTROUTING nat chain; the DYNSRCROUTE writer
#   stays in a PREROUTING filter chain (it stores the request's iif as
#   the reply's forced egress and needs no NAT context at all).
#
# Flow of one ping (nsA4 -> nsB4):
#   request : a4r PREROUTING: conntrack -> DYNSRCROUTE (writes
#             slot[REPLY]: oif=a4r, mac=a4v) -> route -> FORWARD ->
#             b4r POSTROUTING: snat to 10.0.2.1 -> b4v -> nsB4.
#             NOTE: the SNAT map is established AFTER the writer ran
#             (post_routing), so the FIRST request reaches the writer
#             un-NATed and the ct-direction tuple match succeeds.
#   reply   : b4r PREROUTING: core-nat un-SNATs dst 10.0.2.1 -> 10.0.1.67
#             -> ip_route_input: forced-eo (slot[REPLY]=a4r) beats the
#             blackhole (0004 input hook + 0006) -> FORWARD:
#             DYNRT counter (dir=REPLY) -> a4r -> a4v -> nsA4.
#
#   b0  baseline: ping A->B 5, NAT evidence (nsB4 neigh shows 10.0.2.1)
#   b1  NEG: ip route replace 10.0.1.67 blackhole ; no dynrt rules
#       -> normal reply lookup blackholed                  (expect 0/3)
#   b2  POS: same blackhole + writer/reader rules
#       -> forced-oif lookup rejects the blackhole (nhc_oif=0),
#          accepts the /24 on a4r ; egress a4r             (expect 5/5, cnt==5)
#
# PASS = b0 5/5 + NAT evidence + b1 0/3 + b2 5/5 + cnt==5 + dmesg clean.

S_NAME=S4
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s4
TABNAT=dynrt_s4nat
NSA=nsA4 ; A4R=a4r ; A4V=a4v ; A4IP=10.0.1.67
NSB=nsB4 ; B4R=b4r ; B4V=b4v ; B4IP=10.0.2.20 ; B4GW=10.0.2.1

cleanup() {
  nft_drop "$TAB" ip || true
  nft_drop "$TABNAT" ip || true
  bh_off "$A4IP" 2>/dev/null || true
  # rp_filter restore AFTER bh_off (restoring strict with the blackhole up
  # would re-kill the traffic -- S3 lesson)
  if [ -n "${RP4_SAVE:-}" ]; then rpf_put $RP4_SAVE; fi
  r "sysctl -w net.ipv4.ip_forward=${IPF_SAVE:-1} >/dev/null 2>&1 || true"
  ns_down "$NSA" "$A4R" || true
  ns_down "$NSB" "$B4R" || true
  kp_disarm || true
}
trap cleanup EXIT

say "== S4 setup: 2 netns + SNAT infra =="
IPF_SAVE=$(r "sysctl -n net.ipv4.ip_forward" | tr -d '[:space:]'); IPF_SAVE=${IPF_SAVE:-1}
ns_up "$NSA" "$A4R" "$A4V" "10.0.1.1/24" "10.0.1.67/24" || { finish FAIL "ns_up $NSA failed"; exit 1; }
ns_up "$NSB" "$B4R" "$B4V" "10.0.2.1/24" "10.0.2.20/24" || { finish FAIL "ns_up $NSB failed"; exit 1; }
r "sysctl -w net.ipv4.ip_forward=1 >/dev/null"
# rp_filter window (RP_FILTER KILL, proven 2026-10-09): b1/b2 blackhole
# A_IP (10.0.1.67).  With strict rp_filter (deb13 default=2) the reverse-
# path validation on a4r/a4v would DROP every INBOUND request (source is
# the blackholed A_IP) before nsB4 can generate a reply -- so b2 could
# never pass and b1 would pass for the wrong reason.  Relax host + both
# netns sides for the whole test; restored in cleanup after bh_off.
RP4_SAVE=$(rpf_snap "$A4R" "$B4R")
rpf0 "$A4R" "$B4R"
rpf0ns "$NSA" "$A4V"
rpf0ns "$NSB" "$B4V"

# NAT table (SNAT infrastructure -- not dynrt functionality).
# POSTROUTING: SNAT at prerouting is rejected by the kernel (nft_nat_validate)
# and by the nft userspace named-prio table (srcnat: local_in/post_routing).
out=$(nft_apply "$TABNAT" <<'DEF'
table ip dynrt_s4nat {
	chain po {
		type nat hook postrouting priority srcnat;
		policy accept;
		iifname "a4r" ip saddr 10.0.1.67 snat to 10.0.2.1
	}
}
DEF
)
grep -q NFT_OK <<<"$out" || { finish FAIL "nft nat table failed: $(tr '\n' ' ' <<<"$out")"; exit 1; }

nft_drop "$TAB" ip
b0=$(hpings "$NSA" "$B4IP" 5)
sleep 1
NATEV=$(r "ip netns exec $NSB ip neigh show $B4GW 2>/dev/null | head -1")
say "b0 A->B=$b0 ; nsB4 neigh $B4GW: ${NATEV:-none}"
[ "$b0" = 5/5 ] && [ -n "$NATEV" ] && ok "b0 baseline OK + SNAT visible to nsB4" ||
  { bad "b0 ping=$b0 nat=${NATEV:-none}"; finish FAIL "b0 ping=$b0 nat=${NATEV:-none}"; exit 1; }

# ---- b1 NEG: blackhole, no dynrt rules ------------------------------------
say "== b1 NEG: blackhole 10.0.1.67, no dynrt rules =="
bh_on "$A4IP" || { finish FAIL "blackhole add failed"; exit 1; }
sleep 0.5
b1=$(hpings "$NSA" "$B4IP" 3)
say "b1 NEG ping=$b1 (want 0/3)"
neg_ok=NO
case "$b1" in 0/3) neg_ok=YES; ok "NEG: blackhole drops reply (no rules)" ;;
               *)  bad "NEG: got $b1 (unexpected)" ;; esac

# ---- b2 POS: blackhole + dynrt rules ---------------------------------------
say "== b2 POS: same blackhole + writer/reader rules =="
out=$(nft_apply "$TAB" <<'DEF'
table ip dynrt_s4 {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow (defense in depth: the TAP
		# already carries no ambient traffic) -- report "ambient-pass"
		iifname "a4r" ip daddr 10.0.2.20 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook forward priority filter; policy accept;
		ip daddr 10.0.1.67 DYNRT counter
	}
}
DEF
)
grep -q NFT_OK <<<"$out" || { bad "nft apply failed: $(tr '\n' ' ' <<<"$out")"; }

CNT0=$(nft_cnt ip "$TAB")
b2=$(hpings "$NSA" "$B4IP" 5)
CNT=$(nft_cnt ip "$TAB")
dCNT=$(cnt_delta "$CNT0" "$CNT")
say "b2 POS ping=$b2 counter=$CNT0->$CNT (dCNT=$dCNT; want 5/5, >=5)"
pos_ok=NO
if [ "$b2" = 5/5 ] && [ "${dCNT:-0}" -ge 5 ]; then
  pos_ok=YES; ok "POS: reply forced egress a4r despite blackhole, DYNRT counter advanced by $dCNT"
else
  bad "b2 ping=$b2 cnt=$CNT0->$CNT dCNT=$dCNT"
fi

DM=$(dm_bad | tr '\n' ' | ')
say "dmesg: ${DM:-<clean>}"

if [ "$neg_ok" = YES ] && [ "$pos_ok" = YES ] && [ -z "$DM" ]; then
  finish PASS "b0=5/5+SNAT b1NEG=0/3 b2POS=5/5 cnt=$CNT0->$CNT,dCNT=$dCNT"
else
  finish FAIL "b0=5/5+SNAT b1=$b1($neg_ok) b2=$b2($pos_ok,cnt=${CNT0:-?}->${CNT:-?},dCNT=${dCNT:-?}) dm=${DM:-na}"
fi
