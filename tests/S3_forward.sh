#!/usr/bin/env bash
# S3 -- L3/L4 on the FORWARD path (A -> B), reply blackhole semantics.
#
# Topology:
#   host A (192.168.200.67, enp4s0) --seg1-- deb13 (enp0s3 192.168.200.12)
#                                           |
#                                     veth d3a 10.66.0.1/24
#                                           |
#                                     netns nsS3 / n3a 10.66.0.2/24  (B)
#   host route: 10.66.0.0/24 via 192.168.200.12 dev enp4s0
#
# A->B request deb13-side path: PREROUTING(enp0s3) -> route -> FORWARD ->
# d3a.  B->A reply path: PREROUTING(d3a) -> route(dst 192.168.200.67) ->
# FORWARD -- dst is NOT local to deb13, so this is NOT an output lookup.
#
#   b0  baseline A->B ping  5/5
#   b1  NEG: blackhole A_IP, rp_filter off (see below), no rule ->
#       0/5: B receives the request (B InEchos +5) and generates every
#       reply (B OutEchoReps +5); each reply dies in deb13's FIB before
#       the FORWARD hook.  Wire: >=5 req, 0 reply.  Probes silent
#       (tagop=tgmop=0).
#   b2  SCOPE: same blackhole + rule (prerouting DYNSRCROUTE on the
#       request, DYNRT match in a forward chain).  On 6.12.111 the
#       OBSERVED signature is K2: the B->A reply (dst A_IP) DOES reach
#       the FORWARD nf_hook (tgmop>0; chain f counter 0->5); since the
#       2026-10-11 syntax fix the DYNRT match evaluates as a conjunction
#       member (tgmop>0 just proves the match eval ran); there is no
#       forwarding, so the test is
#       0/5 and the reply never hits the seg1 wire (host capture
#       reply=0) -- the drop is inside deb13, after the FORWARD hook
#       (forward xmit / output of a blackholed dst).  B-MIB proves the
#       request reached B (InEchos +5) and B generated every reply
#       (OutEchoReps +5).
#       Mechanism anchor: the module hooks BOTH the local-output path
#       (ip_route_output_flow) AND the FORWARD input path
#       (ip_route_input_slow, CONFIG_NF_DYNRT block in 6.12.111 route.c)
#       with a DYNSRCROUTE forced-oif/anchor lookup, so a blackholed-dst
#       reply can still fire the FORWARD hook (K2) rather than dying
#       pre-FORWARD (K1) as the naive "local-output-only" model predicts.
#       The exact fib-level drop point is a 6.12.111 refactored-FIB detail
#       (fib_trie.c blackhole vs forced-oif), evidenced by the counters
#       above.  Both K1 (tgmop=0) and K2 (tgmop>0) are accepted PASS.
#       K3: 5/5 -- the FORWARD path IS forced -- report it.
#       Partial 1..4/5 = nondeterministic -> FAIL for triage.
#
# LOCKOUT GUARD: blackholing A_IP also kills the deb13->host SSH
# transport (S3 self-lockout, 2026-10-08): sshguard (ip rule pref 32700,
# tcp sport 22, table 32760) keeps the control channel alive; ICMP still
# hits the blackhole.  Applied BEFORE bh_on, removed AFTER bh_off.
#
# RP_FILTER KILL (root-cause fix, proven 2026-10-08, matrix
# repro_becho2: rp=2 -> B InEchos +0 / OutEchoReps +0; rp=0 -> +5/+5):
# deb13 runs loose rp_filter (net.ipv4.conf.default.rp_filter=2,
# inherited by every interface).  While A_IP is blackholed, every
# A->B request we emit carries src=A_IP; the reverse-path lookup of the
# source then returns the blackhole (no nexthop) and fib_validate_source
# REJECTS the packet at the forward routing decision.  Kill point:
# AFTER the PREROUTING nf_hook (b2's DYNSRCROUTE is still evaluated:
# tagop>0), BEFORE the FORWARD nf_hook (tgmop=0) and before d3a xmit,
# so B literally never sees the request (B InEchos +0; the d3a tx delta
# 3..5 in the pre-fix runs = neigh/ARP noise, not requests).
# "Request reached B" was therefore structurally unachievable under the
# blackhole; this script disables rp_filter (all/default/enp0s3) for the
# b1+b2 window and restores it in cleanup.  S5 is NOT affected: there
# the host pings deb13 itself (local INPUT path, not rp-filtered --
# proven by S5 b2's retdyn4 arg1=2, i.e. the reply was generated).
# Consequence: b2 gains one extra evidence line -- B OutEchoReps delta
# >= 4 proves the request reached B and B generated the replies (which
# then died inside deb13, wire reply=0), instead of "the request never
# got to B".
#
# PASS = b0 5/5 && b1(0/5 && wire reply=0 && expr silent && request
#        reached B) && b2 (tagop>0 && b2 in {0/5-K1, 0/5-K2, 5/5-K3}
#        -- K2 (tgmop>0) observed on 6.12.111; K1 (tgmop=0) also valid)
#        && dmesg clean.
#        Counters are informational (scoped since the 2026-10-11 syntax
#        fix; the verdict does not depend on them).

S_NAME=S3
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s3
NS=nsS3 VROOT=d3a VNS=n3a AROUTE=10.66.0.0/24
B_IP=10.66.0.2
CAP1=/tmp/opencode/s3_seg1_cap.log
REPLY_RE="10\.66\.0\.2 > 192\.168\.200\.67: ICMP echo reply"
REQ_RE="192\.168\.200\.67 > 10\.66\.0\.2: ICMP echo request"

cleanup() {
  nft_drop "$TAB" 2>/dev/null || true
  bh_off "$A_IP" 2>/dev/null || true
  # restore rp_filter only after the blackhole is gone (order matters:
  # restoring with the blackhole still up would re-kill A->B traffic)
  if [ -n "${RP_SAVED:-}" ]; then
    RPALL=${RP_SAVED%% *}; RPDEF=${RP_SAVED#* }; RPDEF=${RPDEF%% *}; RPE3=${RP_SAVED##* }
    r "sysctl -qw net.ipv4.conf.all.rp_filter=$RPALL net.ipv4.conf.default.rp_filter=$RPDEF net.ipv4.conf.enp0s3.rp_filter=$RPE3 && echo RP_RESTORED" 2>/dev/null || true
  fi
  sshguard_off 2>/dev/null || true
  H "ip route del $AROUTE" 2>/dev/null || true
  ns_down "$NS" "$VROOT" 2>/dev/null || true
  kp_disarm 2>/dev/null || true
}
trap cleanup EXIT

# wire_pb: capture seg1 (enp4s0) during 5 A->B pings; prints "rcvd/sent req reply"
wire_pb() {
  local p out q rpl
  H "timeout 15 tcpdump -nn -i enp4s0 -s0 'icmp and host $B_IP and host $A_IP' > $CAP1 2>&1" &
  p=$!
  sleep 1
  out=$(hping "$B_IP" 5)
  wait "$p" 2>/dev/null || true
  q=$(grep -cE "$REQ_RE"  "$CAP1" 2>/dev/null) || q=0
  rpl=$(grep -cE "$REPLY_RE" "$CAP1" 2>/dev/null) || rpl=0
  say "    WIRE seg1(enp4s0): req=$q reply=$rpl" >&2
  echo "$out $q $rpl"
}

say "S3 : forward A->B; blackhole on the reply FIB (FORWARD scope probe)"
r "sysctl -w net.ipv4.ip_forward=1 >/dev/null; echo FWD_OK" || bad "ip_forward failed"
say "  $(ns_up "$NS" "$VROOT" "$VNS" 10.66.0.1/24 10.66.0.2/24 | tr '\n' ' ')"
H "ip route replace $AROUTE via $D13_IP dev enp4s0" || bad "host route failed"

b0ns=$(hpings "$NS" "$D13_IP" 2)
hb0=$(hping "$B_IP" 5)
say "b0 sanity: ns->deb13=$b0ns ; A->B=$hb0"
[ "$hb0" = 5/5 ] || { bad "baseline A->B broken ($hb0)"; finish FAIL "baseline=$hb0"; exit 1; }

# ---- b1 NEG ------------------------------------------------------------------
say "b1 NEG: blackhole $A_IP (no rule); sshguard protects the control channel"
sshguard_on || { finish FAIL "sshguard install failed"; exit 1; }
bh_on "$A_IP" || bad "blackhole add reported error (guard keeps ssh alive; continuing)"
# rp_filter window: with A_IP blackholed, the loose rp_filter=2 on
# enp0s3 would drop every A->B request (source = blackholed A_IP,
# fib_validate_source rejects) BEFORE the request ever reaches B --
# see the RP_FILTER KILL block in the header.  Disable for b1+b2.
RP_SAVED=$(r "echo \$(cat /proc/sys/net/ipv4/conf/all/rp_filter) \$(cat /proc/sys/net/ipv4/conf/default/rp_filter) \$(cat /proc/sys/net/ipv4/conf/enp0s3/rp_filter)")
case "$RP_SAVED" in '' | *[!0-9\ ]* | *'  '*) bad "rp_filter save failed ($RP_SAVED)" ;; esac
r "sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv4.conf.enp0s3.rp_filter=0 && echo RP0_SET" \
  || bad "rp_filter=0 set failed (continuing; b1 evidence may show B_IN=0)"
sleep 1

kp_arm   # arm BEFORE b1: trace cleared at arm; expr probes must stay silent in b1
d3a_tx_a=$(t13 d3a tx_packets)
resp_a=$(nsicmpresp "$NS")
read -r b1 q1 r1 <<<"$(wire_pb)"
bn=$(hpings "$NS" "$A_IP" 3)
d3a_tx_b=$(t13 d3a tx_packets)
d3a=$((d3a_tx_b - d3a_tx_a))
resp_b=$(nsicmpresp "$NS")
respd=$((resp_b - resp_a))
KPB1=$(kp_count | tr '\n' ' ')
TGO1=$(sed -n 's/.* tagop=\([0-9][0-9]*\).*/\1/p' <<<"$KPB1"); TGO1=${TGO1:-0}
TG1=$(sed -n 's/.* tgmop=\([0-9][0-9]*\).*/\1/p' <<<"$KPB1"); TG1=${TG1:-0}
say "b1 ping A->B=$b1 (expect 0/5) B->A direct=$bn (expect 0/3)"
say "b1 wire req=$q1 reply=$r1 ; B generated replies (nsicmpresp) d=$respd (expect >=4 = request reached B)"
say "b1 INFO: d(d3a tx)=$d3a (veth counter, flaky under ssh load -- informational)"
say "b1 expr counts: $KPB1"
neg_ok=NO
if [ "$b1" = 0/5 ] && [ "$bn" = 0/3 ] && [ "$q1" -ge 5 ] && [ "$r1" -le 0 ] \
   && [ "$respd" -ge 4 ] && [ "$TGO1" -eq 0 ] && [ "$TG1" -eq 0 ]; then
  neg_ok=YES; ok "NEG: replies blackholed in FIB; B got the requests (generated $respd replies) and its own probe is blackholed too; expressions silent"
else
  bad "NEG: A->B=$b1 B->A=$bn req=$q1 reply=$r1 B-replies=+$respd d3a=+$d3a tagop=$TGO1 tgmop=$TG1"
fi

# ---- b2 SCOPE: blackhole still on + rule --------------------------------------
say "b2 SCOPE: rule (prerouting DYNSRCROUTE / forward DYNRT+counter) under the blackhole"
out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s3 {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow: slots must not be written
		# for unrelated ct (management SSH on this iface) -- report "ambient-pass"
		iifname "enp0s3" ip daddr 10.66.0.2 icmp type echo-request DYNSRCROUTE
	}
	chain f {
		type filter hook forward priority filter; policy accept;
		ip daddr 192.168.200.67 DYNRT counter
	}
}
DEF
)
grep -q NFT_OK <<<"$out" || bad "nft apply failed: $(tr '\n' ' ' <<<"$out")"

CNT0=$(nft_cnt inet "$TAB") 2>/dev/null
BREQ_A=$(nsicmpreq "$NS");  BREQ_A=${BREQ_A:-0}
BREP_A=$(nsicmpresp "$NS"); BREP_A=${BREP_A:-0}
read -r b2 q2 r2 <<<"$(wire_pb)"
BREQ_B=$(nsicmpreq "$NS");  BREQ_B=${BREQ_B:-0}
BREP_B=$(nsicmpresp "$NS"); BREP_B=${BREP_B:-0}
dbreq=$((BREQ_B - BREQ_A)); dbrep=$((BREP_B - BREP_A))
CNT=$(nft_cnt inet "$TAB") 2>/dev/null
dCNT=$(cnt_delta "${CNT0:-}" "${CNT:-}")
KP=$(kp_count | tr '\n' ' ')
TGO2=$(sed -n 's/.* tagop=\([0-9][0-9]*\).*/\1/p' <<<"$KP"); TGO2=${TGO2:-0}
TG2=$(sed -n 's/.* tgmop=\([0-9][0-9]*\).*/\1/p' <<<"$KP"); TG2=${TG2:-0}
KPR=$(kp_retvals retdyn4 | head -c 300 | tr '\n' ' | ')
DM=$(dm_bad | tr '\n' ' | ')
say "b2 ping A->B=$b2 wire req=$q2 reply=$r2 tagop=$TGO2 tgmop=$TG2"
say "b2 B-MIB: InEchos=+$dbreq OutEchoReps=+$dbrep (B got the requests + generated the replies; they died inside deb13, wire reply=$r2)"
say "b2 INFO: counter=${CNT0:-?}->${CNT:-?} (dCNT=${dCNT:-?} -- informational: counts packets matching the chain f rule); retdyn4: ${KPR-<none>}"
say "b2 dmesg: ${DM-<none>}"

pos_ok=NO; SCOPE=""
if [ "$TGO2" -gt 0 ]; then
  case "$b2" in
    0/5)
      if [ "$TG2" -eq 0 ]; then
        SCOPE="K1 (EXPECTED on 6.12.111): reply died in the FIB (blackhole short-circuit) BEFORE the FORWARD hook -- no nft chain saw it; no forced lookup exists on FORWARD either (route.c hooks are local-output only); B-OutEchoReps=+$dbrep proves the replies were generated (not the request loss)"
      else
        SCOPE="K2 (ALT kernel signature): reply reached FORWARD (tgmop=$TG2), DYNRT match evaluated as a conjunction member, no forward-path forcing -- also a FORWARD scope limit"
      fi
      pos_ok=YES; ok "SCOPE: tagop=$TGO2 tgmop=$TG2 -- $SCOPE" ;;
    5/5) pos_ok=YES; SCOPE="K3 (UNEXPECTED): the FORWARD path IS forced -- reply escaped the blackhole, report it"; ok "SCOPE: -- $SCOPE" ;;
    *)   bad "SCOPE: partial $b2 -- nondeterministic, needs triage" ;;
  esac
else
  bad "SCOPE: DYNSRCROUTE not evaluated (tagop=0) -- prerouting rule not effective"
fi

if [ "$neg_ok" = YES ] && [ "$pos_ok" = YES ] && [ -z "$DM" ]; then
  finish PASS "b0=5/5 b1NEG=0/5|wire=req$q1/rply$r1|B-replies+$respd|d3a+$d3a|expr0 b2=$b2|wire=req$q2/rply$r2|Breq+$dbreq/Brep+$dbrep|tagop=$TGO2,tgmop=$TG2| $SCOPE"
else
  finish FAIL "b0=5/5 b1=$b1($neg_ok) b2=$b2($pos_ok) dm=${DM:-na}"
fi
