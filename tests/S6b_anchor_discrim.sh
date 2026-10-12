#!/usr/bin/env bash
# S6b ANCHOR DISCRIMINATION (2026-10-11) -- the prime matrix, corrected.
#
# Background
# ----------
# The S6b NEG inversion (ok=5 bad=0 instead of ok=0 bad>=4) correlates with
# the module-global reverse-flow ANCHOR (srcdynroute.c:
# dynrt_srcroute_eval -> dynrt_anchor_update, reader dynrt_op_mac ->
# dynrt_anchor_mac): written on the DYNSRCROUTE request, exact reverse 5-tuple
# (ICMP ports 0/0) + peer L2 (FAKEA in this topology), TTL 60s
# (DYNRT_ANCHOR_TTL_MS), invisible and unflushable from userspace.  The
# 0005 neighbour.c glue (neigh_resolve_output / neigh_connected_output ->
# dynrt_force_mac -> ops->mac) applies the reader's MAC OVER neigh->ha --
# independent of neigh state.
#
# WHY THE FIRST MATRIX (run1, 2026-10-10) WAS INVALID AS A DISCRIMINATOR
# ----------------------------------------------------------------------
#  (a) its prime used a DIFFERENT 4-tuple (the S6a veth flow 172.30.10.x):
#      the anchor key is the exact reverse tuple (dynrt_anchor_mac()), so a
#      172.30.10.x anchor can never serve the 172.31.10.x NEG reply tuple.
#      run1's 4x CLEAN is consistent with the mechanism (cross-tuple anchors
#      are inert) but does not test it;
#  (b) harness defect: `rs` pipes the script into `bash -s` with NO
#      arguments, so `PH=$1` inside the neg phase was empty and canary/pcap
#      went to /tmp/pm_.* instead of /tmp/pm_E1.* (missing evidence files).
#
# THIS RUN -- primes the EXACT battery S6b flow (t6a, 172.31.10.67 ->
# 172.31.10.1 ICMP echo-request, L2-src FAKEA), with the DYNSRCROUTE rule
# active (the battery POS itself) and proves the writer fired (rule counter
# >=5 AND tagop kprobe >=5), then runs the battery's untouched NEG
# (same /tmp/t6in.py injector, rule verified-dropped) in three controlled
# variants.  The SINGLE tested variable is anchor freshness/liveness:
#
#   D0  no prime, anchor epoch proven expired   -> CLEAN, macretNZ=0 (control)
#   D1  prime + NEG within TTL (~15s)           -> INVERTED ok>=4 bad<=1 AND
#        macretNZ>0 -- THE PROOF: the dynrt_op_mac RET-PROBE is non-zero,
#        i.e. the module handed the xmit path a MAC while NO rule existed
#   D2  prime + TTL lapse (72s) + NEG           -> CLEAN, macretNZ=0 (TTL)
#   D3  prime + rmmod/modprobe (store wipe)     -> CLEAN, macretNZ=0
#   + immediate NEG                             (the carrier is MODULE STATE:
#                                                 wiped by rmmod)
#
# If D1 is INVERTED+macretNZ>0 while D0/D2/D3 are CLEAN+macretNZ=0, the
# inversion carrier is PROVEN to be the module-global anchor store (not a
# residual writer table, not conntrack, not neigh state).
#
# Per-phase instrumentation (tracefs kprobes, lib.sh kp_*):
#   tagop   p dynrt_srcroute_eval   -- writer fires (>=5 in prime, 0 in NEG)
#   tgmop   p dynrt_match_eval      -- DYNRT match evaluations
#   macret  r dynrt_op_mac $retval  -- THE reader; arg1!=0 => MAC served
#   canary  `nft list tables` md5 every 0.25s (any foreign writer activity)
#   pcap    tcpdump -i t6a (WIRE ground truth: reply L2 dst = FAKEA/WRONG)
#   neigh   `ip neigh show dev t6a` snapshots
#   dmesg   dm_bad error/WARN scan
#
# Denoise: p-probes dyn4/dyn6/dynsk/macop disabled (background v4 traffic
# ~100/s per the lib.sh kp_arm note); buffer 4 MB; per-phase trace clearing.
#
# Evidence standard: injector ok/bad/arp counts are the verdict (same as the
# battery); the macret retval (module-internal), the wire (pcap) and the
# neigh timeline are independent corroborating layers.  Every phase prints
# its EXPECTED vs OBSERVED result; the run summary states the mechanism
# verdict explicitly.

set -u
cd "$(dirname "$0")"
S_NAME=S6D
. ./lib.sh

TAB_D=dynrt_s6b_d

# ------------------------------------------------------------------ helpers
verdict_of() { # from the matrix; identical criteria
  local okv bdv
  okv=$(sed -n 's/.*ok=\([0-9-]*\).*/\1/p' <<<"$1")
  bdv=$(sed -n 's/.*bad=\([0-9-]*\).*/\1/p' <<<"$1")
  if [ "${okv:-X}" = 0 ] && [ -n "${bdv:-}" ] && [ "$bdv" -ge 4 ] 2>/dev/null; then
    printf 'CLEAN (ok=0 bad=%s -- kernel used poisoned WRONG)' "$bdv"
  elif [ -n "${okv:-}" ] && [ "$okv" -ge 4 ] 2>/dev/null; then
    printf 'INVERTED (ok=%s bad=%s -- replies left with FAKEA dst)' "$okv" "${bdv:--}"
  else
    printf 'MIXED/OTHER (ok=${okv:--} bad=${bdv:--})'
  fi
}

macret_stats() { # calls=<n> nonzero=<n> of dynrt_op_mac retvals in the trace
  r "grep -cE ' macret:' /sys/kernel/tracing/trace 2>/dev/null | sed 's/^/calls=/'
grep -E ' macret:' /sys/kernel/tracing/trace 2>/dev/null | grep -cE 'arg1=0x[1-9a-f]' | sed 's/^/nonzero=/'"
}

clear_trace() {
  r "printf '' > /sys/kernel/tracing/trace 2>/dev/null
echo 1 > /sys/kernel/tracing/tracing_on 2>/dev/null && echo TRACE_CLEARED" >/dev/null 2>&1
}

arm_all() { # base kprobes + macret retprobe + denoise + 4MB buffer
  local ka mr
  ka=$(kp_arm 2>/dev/null) || true
  [ -n "${ka:-}" ] && say "discrim: kprobes: $ka"
  mr=$(r "T=/sys/kernel/tracing
sed -i '/macret/d' \$T/kprobe_events 2>/dev/null
if printf 'r:macret dynrt_op_mac \$retval\n' >> \$T/kprobe_events 2>/dev/null; then
  echo 1 > \$T/events/kprobes/macret/enable 2>/dev/null && echo MACRET_ARMED || echo MACRET_ENABLE_FAIL
else
  echo MACRET_ARM_FAIL
fi
echo 4096 > \$T/buffer_size_kb 2>/dev/null
for e in dyn4 dyn6 dynsk macop; do echo 0 > \$T/events/kprobes/\$e/enable 2>/dev/null; done
printf '' > \$T/trace 2>/dev/null
echo 1 > \$T/tracing_on 2>/dev/null && echo TRACE_ON")
  say "discrim: macret retprobe: ${mr:-NO_RESPONSE} (denoised p-probes: dyn4/dyn6/dynsk/macop)"
}

baseline() { # $1=phase ; returns 1 on any confounder (fail open)
  local ph=$1 t
  t=$(rs <<'PRE'
for p in /proc/[0-9]*; do
  if ls -l "$p/fd" 2>/dev/null | grep -q '/dev/net/tun'; then
    printf 'pid=%s cmd=%s\n' "${p##*/}" "$(tr -d '\0' < "$p/cmdline" 2>/dev/null | head -c 48)"
  fi
done
PRE
)
  if [ -n "${t:-}" ]; then
    bad "[$ph] baseline: a process holds /dev/net/tun: $(tr '\n' ' ' <<<"$t")"
    return 1
  fi
  if [ -n "$(r "ip -4 neigh show to 172.31.10.67 2>/dev/null")" ]; then
    bad "[$ph] baseline: stale neigh 172.31.10.67: $(r "ip -4 neigh show to 172.31.10.67 2>/dev/null" | tr '\n' ' ')"
    return 1
  fi
  if [ -n "$(r "$NFT list tables 2>/dev/null | awk '\$3 ~ /^dynrt_/ {print}'")" ] || [ -n "$(foreign_module_tables)" ]; then
    bad "[$ph] baseline: a live DYNSRCROUTE-writer table exists -- it would fire on the phase traffic; abort"
    return 1
  fi
  say "[$ph] baseline ok: no /dev/net/tun holder, no stale neigh 172.31.10.67, no dynrt_*/foreign writer tables"
  say "[$ph] ct(172.31.10)=$(r "awk '/172\.31\.10/ {n++} END {print n+0}' /proc/net/nf_conntrack 2>/dev/null" | tr -d ' ') (informational; ct-slot path is empirically non-carrier on deb13 -- lazy nf_ct_netns_get, no active ct expression)"
  return 0
}

# Wait out a possibly-live battery/matrix anchor (bounded; zero overhead
# when the epoch marker is absent or already >65s old).
epoch_wait_if_live() {
  local ep now age need
  ep=$(r "cat /tmp/dynrt_s6b_pos_epoch 2>/dev/null" | tr -cd '0-9')
  [ -n "${ep:-}" ] || { say "epoch marker absent (no live anchor bookkeeping)"; return 0; }
  now=$(r "date +%s" | tr -cd '0-9')
  age=$(( now - ep ))
  if [ "$age" -lt 65 ] 2>/dev/null; then
    need=$(( 65 - age ))
    say "pos-epoch age=${age}s (<65s, anchor MAY be live) -- waiting ${need}s for DYNRT_ANCHOR_TTL_MS expiry"
    sleep "$need"
  else
    say "pos-epoch age=${age}s (>=65s -> anchor DEAD per TTL)"
  fi
}

# PRIME = the battery S6b POS itself: same rule, same flow, same injector.
# Proof of the writer fire: rule counter (packets>=5) AND tagop p-probe
# (dynrt_srcroute_eval calls >=5).  Leaves ONLY the module-internal anchor
# (TTL 60s) as surviving state; verifies the drop.
prime_flow() {
  local out OUT inj C_TR tgo
  out=$(nft_apply "$TAB_D" <<'DEF'
table ip dynrt_s6b_d {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		iifname "t6a" ip daddr 172.31.10.1 icmp type echo-request counter DYNSRCROUTE
	}
}
DEF
)
  if ! grep -q NFT_OK <<<"$out"; then
    bad "PRIME: nft_apply: $(tr '\n' ' ' <<<"$out")"
    return 1
  fi
  clear_trace
  OUT=$(rs <<'PRIMEOF'
rm -f /tmp/t6stat.txt /tmp/t6neigh.log
timeout 25 python3 /tmp/t6in.py >/dev/null 2>&1 &
PJ=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.5
  { echo "snap_t=$i"; ip neigh show dev t6a; } >> /tmp/t6neigh.log 2>&1
done
wait $PJ 2>/dev/null
INJRC=$?
date +%s > /tmp/dynrt_s6b_pos_epoch 2>/dev/null
echo PRIME_INJ_BEGIN
cat /tmp/t6stat.txt 2>/dev/null || echo 'ok=- bad=- other=- arp=- req=-'
echo PRIME_INJRC=$INJRC
echo PRIME_INJ_END
PRIMEOF
)
  inj=$(sed -n '/PRIME_INJ_BEGIN/,/PRIME_INJ_END/p' <<<"$OUT" | sed '1d;$d' | head -1)
  C_TR=$(nft_cnt ip "$TAB_D" | tr -d ' ')
  tgo=$(kp_count 2>/dev/null | sed -n 's/^tagop=//p')
  say "PRIME injector: ${inj:-(no stats)}   rule_counter=${C_TR:--} tagop=${tgo:--}"
  say "PRIME macret during prime (reader serving replies, expected nonzero): $(macret_stats | tr '\n' ' ')"
  say "PRIME neigh timeline:"
  r "sed -n '1,10p' /tmp/t6neigh.log 2>/dev/null" | sed 's/^/    neigh| /' || true
  nft_drop "$TAB_D" ip || { bad "PRIME: nft_drop UNVERIFIED (table state unknown)"; return 1; }
  say "PRIME table dropped (verified).  Surviving state: ONLY the module-internal anchor {172.31.10.1 -> 172.31.10.67, ICMP 0/0, hw=FAKEA, oif, TTL 60s}"
  if [ -n "${C_TR:-}" ] && [ "$C_TR" -ge 5 ] 2>/dev/null && [ -n "${tgo:-}" ] && [ "$tgo" -ge 5 ] 2>/dev/null; then
    ok "PRIME writer PROVEN: rule fired ${C_TR}x (tagop=${tgo}) -- the FAKEA anchor for the NEG reply tuple is LIVE"
    return 0
  fi
  bad "PRIME writer NOT proven (rule_counter=${C_TR:--} tagop=${tgo:--}, want both >=5) -- following NEG would be invalid"
  return 1
}

# NEG phase = the battery S6b NEG itself (same /tmp/t6in.py injector), with
# the canary+pcap+injector in ONE remote shell and the per-phase paths
# expanded HOST-side (run1's $1-empty bug class is structurally avoided).
LAST_STATS="" ; LAST_MR="" ; LAST_VERDICT=""
neg_phase() { # $1=phase label
  local ph=$1 LP=/tmp/sd_$1 OUT T V
  r "pkill -f 't6in[.]py' 2>/dev/null || true"
  r "ip link del t6a 2>/dev/null || true"
  sleep 0.3
  LAST_STATS=""; LAST_MR=""; LAST_VERDICT=""
  OUT=$(rs <<EOF
NFT=$NFT
LP=$LP
( for i in \$(seq 1 40); do
    printf '%s %s\n' "\$(date +%s.%3N)" "\$(\$NFT list tables 2>/dev/null | md5sum | cut -d' ' -f1)"
    sleep 0.25
  done ) > \$LP.canary 2>/dev/null &
CANY=\$!
( DUE=\$(( \$(date +%s) + 12 ))
  while [ "\$(date +%s)" -lt "\$DUE" ] && [ ! -e /sys/class/net/t6a ]; do sleep 0.1; done
  if [ -e /sys/class/net/t6a ]; then
    DUE2=\$(( \$(date +%s) + 18 ))
    while [ -e /sys/class/net/t6a ] && [ "\$(date +%s)" -lt "\$DUE2" ]; do
      timeout 10 tcpdump -i t6a -s0 -c 64 -w \$LP.pcap -Z root 2>/dev/null
    done
  fi
) &
PCAP=\$!
rm -f /tmp/t6stat.txt /tmp/t6neigh.log
timeout 25 python3 /tmp/t6in.py >/dev/null 2>&1 &
PJ=\$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.5
  { echo "snap_t=\$i"; ip neigh show dev t6a; } >> /tmp/t6neigh.log 2>&1
done
wait \$PJ 2>/dev/null
INJRC=\$?
echo NEG_INJ_BEGIN
cat /tmp/t6stat.txt 2>/dev/null || echo 'ok=- bad=- other=- arp=- req=-'
echo NEG_INJRC=\$INJRC
echo NEG_INJ_END
kill \$CANY 2>/dev/null
wait \$PCAP 2>/dev/null
echo PHASE_DONE
EOF
)
  T=$(sed -n '/NEG_INJ_BEGIN/,/NEG_INJ_END/p' <<<"$OUT" | sed '1d;$d')
  LAST_STATS="${T:-(no stats)}"
  V=$(verdict_of "$T")
  LAST_VERDICT="$V"
  say "[$ph] NEG injector: $LAST_STATS  =>  $V"
  LAST_MR=$(macret_stats 2>/dev/null | tr '\n' ' ')
  say "[$ph] macret retprobe (nonzero>0 => the MODULE served a MAC at xmit): ${LAST_MR:-NO_RESPONSE}"
  r "grep -E ' macret:' /sys/kernel/tracing/trace 2>/dev/null | grep -E 'arg1=0x[1-9a-f]' | tail -6" | sed "s/^/    macretNZ| /" || true
  say "[$ph] kprobe counts (NEG expectation tagop=0: there is NO rule in this window): $(kp_count 2>/dev/null | tr '\n' ' ')"
  local CHX CHN
  CHN=$(r "wc -l < $LP.canary 2>/dev/null" | tr -d ' ')
  CHX=$(r "awk 'NR==1{h=\$2} NR>1 && \$2!=h {print \$2}' $LP.canary 2>/dev/null | sort -u | tr '\n' ' '")
  if [ -n "${CHX:-}" ]; then
    say "[$ph] CANARY CHANGED DURING THE WINDOW: $CHX (a foreign writer was active!)"
  else
    say "[$ph] canary: ${CHN:-0} samples, table set static (no foreign writer)"
  fi
  say "[$ph] neigh timeline (poison=02:aa:bb:cc:dd:99, FAKEA=02:aa:bb:cc:dd:06):"
  r "sed -n '1,12p' /tmp/t6neigh.log 2>/dev/null" | sed 's/^/    neigh| /' || true
  if [ -n "$(r "ls $LP.pcap 2>/dev/null")" ]; then
    say "[$ph] pcap WIRE evidence (reply = 172.31.10.1 -> 172.31.10.67):"
    r "tcpdump -r $LP.pcap -nn -e 2>/dev/null | head -24" | sed 's/^/    pcap| /' || true
    say "[$ph] pcap: FAKEA-dst frames=$(r "tcpdump -r $LP.pcap -nn -e 2>/dev/null | grep '172\.31\.10' | sed -n 's/^[0-9:.]* \(02:aa:bb:cc:dd:06\) >.*/1/p' | wc -l" | tr -d ' ') ; WRONG-dst frames=$(r "tcpdump -r $LP.pcap -nn -e 2>/dev/null | grep '172\.31\.10' | sed -n 's/^[0-9:.]* \(02:aa:bb:cc:dd:99\) >.*/1/p' | wc -l" | tr -d ' ')"
  else
    say "[$ph] pcap: NOT CAPTURED"
  fi
  say "[$ph] nft tables now: $(r "$NFT list tables 2>/dev/null" | tr '\n' ' ')"
  say "[$ph] ct(172.31.10) after: $(r "awk '/172\.31\.10/ {n++} END {print n+0}' /proc/net/nf_conntrack 2>/dev/null" | tr -d ' ')"
  dm_bad | sed 's/^/    dmesg| /' || true
  return 0
}

# check_phase <phase> INVERTED|CLEAN -- EXPECTED vs OBSERVED, using the
# LAST_* captured by neg_phase.
PHRASE_OK=()
check_phase() { # $1=phase $2=expect
  local ph=$1 exp=$2 okv bdc nvzv res
  okv=$(sed -n 's/.*ok=\([0-9-]*\).*/\1/p' <<<"$LAST_STATS")
  bdc=$(sed -n 's/.*bad=\([0-9-]*\).*/\1/p' <<<"$LAST_STATS")
  nvzv=$(sed -n 's/.*nonzero=\([0-9-]*\).*/\1/p' <<<"$LAST_MR")
  if [ "$exp" = INVERTED ]; then
    if [ -n "${okv:-}" ] && [ "$okv" -ge 4 ] 2>/dev/null && [ "${bdc:-9}" -le 1 ] 2>/dev/null && [ "${nvzv:-0}" -ge 1 ] 2>/dev/null; then
      res="MATCH (INVERTED + macretNZ>0 -- module served the FAKEA MAC with no rule present)"
      ok "[$ph] EXPECTED=INVERTED  OBSERVED=$LAST_VERDICT  macretNz=${nvzv}  => $res"
      return 0
    fi
    bad "[$ph] EXPECTED=INVERTED  OBSERVED=$LAST_VERDICT  macretNz=${nvzv:--}  => MISMATCH"
    return 1
  fi
  if [ "${okv:-9}" = 0 ] && [ -n "${bdc:-}" ] && [ "$bdc" -ge 4 ] 2>/dev/null && [ "${nvzv:-9}" -eq 0 ] 2>/dev/null; then
    res="MATCH (CLEAN + macretNZ=0 -- no MAC served by the module)"
    ok "[$ph] EXPECTED=CLEAN  OBSERVED=$LAST_VERDICT  macretNz=${nvzv}  => $res"
    return 0
  fi
  bad "[$ph] EXPECTED=CLEAN  OBSERVED=$LAST_VERDICT  macretNz=${nvzv:--}  => MISMATCH"
  return 1
}

# ------------------------------------------------------------------ cleanup
cleanup_trap() {
  nft_drop "$TAB_D" ip >/dev/null 2>&1 || true
  kp_disarm >/dev/null 2>&1 || true
  r "pkill -f 't6in[.]py' 2>/dev/null; ip link del t6a 2>/dev/null || true" >/dev/null 2>&1 || true
}
trap 'cleanup_trap' EXIT

# --------------------------------------------------------------------- main
main() {
  local R1 R2 R3 R4=SKIP
  say "=== S6b ANCHOR DISCRIMINATION start $(date '+%F %T') ==="
  say "deb13: $(r "uname -r")  tables=[$(r "$NFT list tables 2>/dev/null" | tr '\n' ' ')]"
  say "module: $(r "lsmod 2>/dev/null | grep -w srcdynroute" || echo MISSING)"
  if ! r "lsmod 2>/dev/null | grep -qw srcdynroute"; then
    bad "module srcdynroute not loaded -- kprobe targets missing; aborting"
    exit 1
  fi
  say "epoch marker: $(r "cat /tmp/dynrt_s6b_pos_epoch 2>/dev/null || echo absent") (now: $(r "date +%s"))"
  arm_all

  # ------------------------------------------------------------------- D0
  say "---------- D0: control -- no prime, anchor epoch dead, NEG (expect CLEAN, macretNZ=0) ----------"
  epoch_wait_if_live
  if baseline D0; then
    clear_trace
    neg_phase D0
    if check_phase D0 CLEAN; then R1=PASS; else R1=FAIL; fi
  else
    R1=FAIL; bad "D0 aborted (baseline)"
  fi
  sleep 2

  # ------------------------------------------------------------------- D1
  say "---------- D1: PRIME(exact flow) + NEG within TTL -- expect INVERTED + macretNZ>0 ----------"
  if baseline D1; then
    clear_trace
    if prime_flow; then
      clear_trace
      neg_phase D1
      if check_phase D1 INVERTED; then R2=PASS; else R2=FAIL; fi
    else
      bad "D1 invalid (prime not proven) -- aborting: the proof is the precondition of the whole test"
      R2=ABORT
    fi
  else
    R2=FAIL; bad "D1 aborted (baseline)"
  fi
  sleep 2

  # ------------------------------------------------------------------- D2
  if [ "$R2" != ABORT ]; then
    say "---------- D2: PRIME + TTL lapse (72s) + NEG -- expect CLEAN + macretNZ=0 ----------"
    if baseline D2; then
      clear_trace
      if prime_flow; then
        say "D2: sleeping 72s > DYNRT_ANCHOR_TTL_MS (60s) for the anchor to expire"
        sleep 72
        clear_trace
        neg_phase D2
        if check_phase D2 CLEAN; then R3=PASS; else R3=FAIL; fi
      else
        R3=ABORT; bad "D2 invalid (prime not proven)"
      fi
    else
      R3=FAIL; bad "D2 aborted (baseline)"
    fi
  fi

  # ------------------------------------------------------------------- D3
  if [ "$R2" != ABORT ] && [ "$R3" != ABORT ]; then
    say "---------- D3: PRIME + rmmod/modprobe (anchor-store WIPED) + NEG -- expect CLEAN + macretNZ=0 ----------"
    if baseline D3; then
      clear_trace
      if prime_flow; then
        kp_disarm >/dev/null 2>&1 || true
        local RM
        RM=$(r "rmmod srcdynroute 2>&1 && echo RM_OK || echo RM_FAIL; sleep 1; modprobe srcdynroute 2>&1 && echo MOD_OK || echo MOD_FAIL; sleep 1; lsmod | grep -w srcdynroute || echo MOD_MISSING")
        say "D3: $RM"
        if grep -q RM_OK <<<"$RM" && grep -q MOD_OK <<<"$RM"; then
          arm_all
          clear_trace
          neg_phase D3
          if check_phase D3 CLEAN; then R4=PASS; else R4=FAIL; fi
          # the wipe is proven (rmmod) -> the bookkeeping marker is void
          r "rm -f /tmp/dynrt_s6b_pos_epoch 2>/dev/null" >/dev/null 2>&1 || true
        else
          R4=FAIL; bad "D3: rmmod/modprobe cycle failed -- phase invalid"
        fi
      else
        R4=FAIL; bad "D3 invalid (prime not proven)"
      fi
    else
      R4=FAIL; bad "D3 aborted (baseline)"
    fi
  fi
  kp_disarm >/dev/null 2>&1 || true
  sleep 1

  # ---------------------------------------------------------------- summary
  say "================ SUMMARY ================"
  say "D0 control (no prime)          : $R1   (want CLEAN, macretNZ=0)"
  say "D1 prime + NEG within TTL      : $R2   (want INVERTED, macretNZ>0)  <-- the discriminating proof"
  say "D2 prime + TTL-lapsed NEG      : $R3   (want CLEAN, macretNZ=0)"
  say "D3 prime + rmmod-wiped NEG     : $R4   (want CLEAN, macretNZ=0)"
  if [ "$R1" = PASS ] && [ "$R2" = PASS ] && [ "$R3" = PASS ] && [ "$R4" = PASS ]; then
    finish PASS "ANCHOR MECHANISM CONFIRMED: the NEG inversion carrier is the module-global FAKEA anchor (exact reverse tuple, TTL 60s, userspace-invisible); macret retprobe non-zero only in D1"
  else
    bad "mechanism NOT fully confirmed (see per-phase MISMATCH lines above)"
    finish FAIL "discrim run inconclusive: D0=$R1 D1=$R2 D2=$R3 D3=$R4"
  fi
}

main
