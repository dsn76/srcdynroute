#!/usr/bin/env bash
# S5 -- L4 blackhole avoidance via forced-oif FIB lookup (v4, local output).
#
# Topology: host A 192.168.200.67 <-> deb13 192.168.200.12 (seg1: enp4s0/enp0s3).
# Anomaly on deb13: `ip route replace blackhole 192.168.200.67` -- a normal
# reply lookup is guaranteed to die in the FIB; the only escape is the
# module's forced-oif path.
#
# Kernel semantics (6.12.111 tree, net/ipv4/route.c; empirically proven by the
# clean E1/E2 runs of 2026-10-10):
#   * reply WITH flowi4_oif pinned (module force, dynrt_op_oif_fl4): the
#     blackhole alias is evaluated, rejected by the nhc-oif filter, and the
#     output retry path falls back to the native on-link lookup for the
#     destination -> the reply is DELIVERED (E1: 10/10 sequential, 100/100
#     burst, InEchos/OutEchoReps +N/+N).
#   * unforced reply vs the blackhole: dies in the FIB -- MIB signature
#     InEchos +N, OutEchoReps +0 (the Out* MIBs increment only AFTER a
#     successful egress lookup).
#
# The former "KERNEL LIMIT (fib_trie.c short-circuit)" header (run of
# 2026-10-10 02:29) is REFUTED: that run's S5 did not relax rp_filter, so
# strict rp_filter dropped the INBOUND request before any reply was generated
# (lib.sh 4-case matrix, proven 2026-10-09) -- its 0/5 was an rp-filter
# artifact, not a module/kernel boundary.
#
#   b0  baseline 5/5
#   b1  NEG: blackhole, no rule (rpf0, guard) -> 0/5; MIB dInEchos >= 5,
#       dOutEchoReps = 0; expressions silent (tagop = tgmop = 0)
#   b2  POS: blackhole + rule (rpf0, guard)   -> 5/5; MIB dInEchos >= 5,
#       dOutEchoReps >= 5; expressions active (tagop, tgmop > 0)
#
# PASS = b0 5/5 && b1 (0/5, dIE>=5, dORE=0, expr silent) &&
#        b2 (5/5, dIE>=5, dORE>=5, expr active) && dmesg clean.

S_NAME=S5
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s5

cleanup() {
  nft_drop "$TAB" 2>/dev/null || true
  bh_off "$A_IP" 2>/dev/null || true
  # rp_filter restore AFTER bh_off (S3 lesson)
  if [ -n "${RP5_SAVE:-}" ]; then rpf_put $RP5_SAVE 2>/dev/null; fi
  sshguard_off 2>/dev/null || true
  kp_disarm 2>/dev/null || true
}
trap cleanup EXIT

num() { case ${1:-} in ''|*[!0-9]*) echo 0 ;; *) echo "$1" ;; esac; }

say "S5 : blackhole avoidance via forced-oif lookup (LOCAL output path)"
nft_drop "$TAB" || true
FD0=$(foreign_dynrt "$TAB")
[ -z "${FD0:-}" ] || say "WARN: foreign dynrt tables at start: $(tr '\n' ' ' <<<"$FD0")"

b0=$(hping "$D13_IP" 5)
say "b0 baseline ping : $b0"
[ "$b0" = 5/5 ] || { bad "baseline broken"; finish FAIL "baseline=$b0"; exit 1; }

# ---- phase setup: guard + rpf0, then blackhole (hard preconditions) ----------
# LOCKOUT GUARD (S3/S5 lesson): blackholing A_IP also kills the deb13->host
# SSH transport (replies are destined to blackholed A_IP) -> the S3 self-
# lockout of 2026-10-08.  sshguard (ip rule pref 32700, tcp sport 22, private
# table 32760) keeps that channel alive; ICMP (the test pings) still hits the
# blackhole.  APPLY BEFORE bh_on.
# RP_FILTER KILL (proven 2026-10-09, matrix in lib.sh): strict rp_filter
# drops the INBOUND echo request while A_IP is blackholed (reverse-path of a
# blackholed src) -- without rpf0 the NEG would "pass" for the wrong reason
# and the POS would be structurally unreachable.  That is exactly the trap
# the 2026-10-10 02:29 run fell into (b2 0/5 mislabeled "KERNEL LIMIT").
sshguard_on || { finish FAIL "sshguard install failed"; exit 1; }
RP5_SAVE=$(rpf_snap "$D13_IF")
rpf0 "$D13_IF" || { bad "rpf0 failed"; finish FAIL "rpf0"; exit 1; }
bh_on "$A_IP" || { bad "blackhole add failed"; finish FAIL "blackhole add"; exit 1; }
BHN=$(bh_check "$A_IP")
[ "${BHN:-0}" -ge 1 ] 2>/dev/null || {
  bad "blackhole NOT effective (ip route show type blackhole: $(r "ip route show type blackhole 2>&1 | head -1"))";
  finish FAIL "blackhole premise broken"; exit 1; }
ok "premise: blackhole to $A_IP effective; guard + rpf0 in place"
sleep 0.5

# ---- b1 NEG: blackhole, no rule -----------------------------------------------
say "b1 NEG: blackhole $A_IP, no rule (MIB: request arrives, reply NOT generated)"
kp_arm   # arm BEFORE b1: trace cleared at arm; expr probes stay silent in b1
IE0=$(num "$(m13ie)"); ORE0=$(num "$(m13ore)")
b1=$(hping "$D13_IP" 5)
IE1=$(num "$(m13ie)"); ORE1=$(num "$(m13ore)")
dIE1=$((IE1-IE0)); dORE1=$((ORE1-ORE0))
KPB1=$(kp_count | tr '\n' ' ')
TGO1=$(sed -n 's/.* tagop=\([0-9][0-9]*\).*/\1/p' <<<"$KPB1"); TGO1=${TGO1:-0}
TG1=$(sed -n 's/.* tgmop=\([0-9][0-9]*\).*/\1/p' <<<"$KPB1"); TG1=${TG1:-0}
say "b1 ping=$b1 dInEchos=+$dIE1 dOutEchoReps=+$dORE1 tagop=$TGO1 tgmop=$TG1"
neg_ok=NO
if [ "$b1" = 0/5 ] && [ "$dIE1" -ge 5 ] && [ "$dORE1" -eq 0 ] && [ "$TGO1" -eq 0 ] && [ "$TG1" -eq 0 ]; then
  neg_ok=YES
  ok "NEG: 0/5; MIB dInEchos=+$dIE1 (request arrived), dOutEchoReps=+$dORE1 (reply NOT generated -- died in the egress FIB); expressions silent"
else
  bad "NEG: ping=$b1 dInEchos=+$dIE1 (want >=5) dOutEchoReps=+$dORE1 (want 0) tagop=$TGO1 tgmop=$TG1 (want 0)"
fi

# ---- b2 POS: blackhole still on + rule ----------------------------------------
say "b2 POS: apply rule under the same blackhole (forced oif -> on-link fallback)"
out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s5 {
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
grep -q NFT_OK <<<"$out" || { bad "nft apply failed: $(tr '\n' ' ' <<<"$out")"; finish FAIL "nft apply"; exit 1; }
ok "rules applied"

CNT0=$(nft_cnt inet "$TAB") 2>/dev/null
kp_arm   # fresh window for the b2 probe counts
IE0=$(num "$(m13ie)"); ORE0=$(num "$(m13ore)")
b2=$(hping "$D13_IP" 5)
IE1=$(num "$(m13ie)"); ORE1=$(num "$(m13ore)")
dIE2=$((IE1-IE0)); dORE2=$((ORE1-ORE0))
CNT=$(nft_cnt inet "$TAB") 2>/dev/null
dCNT=$(cnt_delta "${CNT0:-}" "${CNT:-}")
KP=$(kp_count | tr '\n' ' ')
TGO2=$(sed -n 's/.* tagop=\([0-9][0-9]*\).*/\1/p' <<<"$KP"); TGO2=${TGO2:-0}
TG2=$(sed -n 's/.* tgmop=\([0-9][0-9]*\).*/\1/p' <<<"$KP"); TG2=${TG2:-0}
KPR=$(kp_retvals retdyn4 | head -c 400 | tr '\n' ' | ')
DM=$(dm_bad | tr '\n' ' | ')
say "b2 ping=$b2 dInEchos=+$dIE2 dOutEchoReps=+$dORE2 tagop=$TGO2 tgmop=$TG2 (want 5/5, >=5, >=5, >0)"
say "b2 INFO: counter ${CNT0:-?}->${CNT:-?} (dCNT=${dCNT:-?} -- dCNT informational: counts DYNRT-positive packets of the test flow)"
say "b2 INFO: kprobes: ${KP:-?} | retdyn4: ${KPR-<none>}"
say "b2 dmesg: ${DM-<none>}"

pos_ok=NO
if [ "$b2" = 5/5 ] && [ "$dIE2" -ge 5 ] && [ "$dORE2" -ge 5 ] && [ "$TGO2" -gt 0 ] && [ "$TG2" -gt 0 ]; then
  pos_ok=YES
  ok "POS: 5/5 delivered under the blackhole; MIB +$dIE2/+$dORE2; force-oif rescued every reply (E1: 10/10 sequential, 100/100 burst)"
else
  bad "POS: ping=$b2 dInEchos=+$dIE2 dOutEchoReps=+$dORE2 tagop=$TGO2 tgmop=$TG2"
fi

# ---- verdict -------------------------------------------------------------------
if [ "$neg_ok" = YES ] && [ "$pos_ok" = YES ] && [ -z "$DM" ]; then
  finish PASS "b0=5/5 b1NEG=0/5(dIE+$dIE1/dORE+$dORE1/expr0) b2POS=5/5(dIE+$dIE2/dORE+$dORE2/tagop=$TGO2,tgmop=$TG2)"
else
  finish FAIL "b0=5/5 b1=$b1($neg_ok,dIE+$dIE1,dORE+$dORE1) b2=$b2($pos_ok,dIE+$dIE2,dORE+$dORE2) dm=${DM:-na}"
fi
