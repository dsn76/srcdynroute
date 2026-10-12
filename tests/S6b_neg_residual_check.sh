#!/usr/bin/env bash
# S6b NEG residual-check -- FALSIFICATION test for the residual-writer-rule
# theory (2026-10-10, sequel to s6b_discrim_2026-10-10_run1.log).
#
# Context (run9, 2026-10-10 19:25-19:26):
#   battery NEG INVERTED (ok=5 bad=0) ~19 min after the last KNOWN writer
#   fire (19:05 discrim P2).  The module anchor (TTL 60s, proven by the
#   discrim P1/P3/P4 A/B) and any ICMP conntrack entry are long dead at
#   that time; `nft list ruleset` post-run9 shows ZERO DYNSRCROUTE.
#   Two consistent explanations remain:
#     A) RESIDUAL: a DYNSRCROUTE table left by an earlier session fired the
#        writer DURING the run9 NEG window (requests hit iifname t6a,
#        daddr 172.31.10.1, ICMP echo-request) and was later removed by
#        run9's OWN cleanup  => the battery never asserts writer-absence
#        before NEG; the discrim script did (nft_drop verified + foreign
#        table check), which is why its P4 was clean.
#     B) UNKNOWN CARRIER: something else in the module serves FAKEA
#        long-term => theory A falsified: escalate to kprobe/ftrace on
#        dynrt_op_mac (R6).
#
# This script ASSERTS (not remediates) the strict clean baseline used by
# S6b_neg_ttl_discrim.sh, snapshots the module-visible state, and runs ONE
# NEG phase.  If the baseline is not clean it ABORTS (that abort is itself
# evidence for A).
#
#   Expected under A: CLEAN  (ok=0, bad>=4, kernel uses poisoned WRONG).
#   Result INVERTED:   B -- carrier unknown, kprobe escalation required.
set -u
cd "$(dirname "$0")"
. ./lib.sh

# --- copied verbatim from S6b_neg_ttl_discrim.sh -------------------------
run_inj() {
  r "rm -f /tmp/t6stat.txt /tmp/t6neigh.log"
  r "timeout 25 python3 /tmp/t6in.py >/dev/null 2>&1 &
PJ=\$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.5
  { echo \"snapshot_t=\$i\"; ip neigh show dev t6a; } >> /tmp/t6neigh.log 2>&1
done
wait \"\$PJ\" 2>/dev/null
INJRC=\$?
cat /tmp/t6stat.txt 2>/dev/null || echo 'ok=- bad=- other=- arp=- req=-'
[ \"\$INJRC\" -ne 0 ] && echo \"INJ_RC=\$INJRC (injector exited non-zero; stats above may be stale/absent -- audit B-02.4)\""
}

clean_base() {
  local t
  r "pkill -f 't6in[.]py' 2>/dev/null || true"
  sleep 0.3
  r "ip link del t6a 2>/dev/null || true"
  sleep 0.2
  # (a) no /dev/net/tun holder (phantom-responder class)
  t=$(rs <<'PRE'
for p in /proc/[0-9]*; do
  if ls -l "$p/fd" 2>/dev/null | grep -q '/dev/net/tun'; then
    printf 'pid=%s cmd=%s\n' "${p##*/}" "$(tr -d '\0' < "$p/cmdline" 2>/dev/null | head -c 48)"
  fi
done
PRE
)
  if [ -n "${t:-}" ]; then
    bad "clean_base: tun-holder present: $(tr '\n' ' ' <<<"$t")"
    return 1
  fi
  # (b) no stale 172.31.10.67 neigh entry
  if [ -n "$(r "ip -4 neigh show to 172.31.10.67 2>/dev/null")" ]; then
    bad "clean_base: stale neigh 172.31.10.67: $(r "ip -4 neigh show to 172.31.10.67" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  # (c) t6a gone
  if [ -n "$(r "ip link show t6a 2>/dev/null")" ]; then
    bad "clean_base: t6a still present: $(r "ip link show t6a" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  # (d) NO DYNSRCROUTE-bearing writer anywhere (dynrt_* or foreign)
  if [ -n "$(r "$NFT list tables 2>/dev/null | awk '\$3 ~ /^dynrt_/ {print \$2\" \"\$3}'")" ]; then
    bad "clean_base: dynrt_* table(s) present: $(r "$NFT list tables" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  if [ -n "$(foreign_module_tables)" ]; then
    bad "clean_base: foreign table with DYNSRCROUTE/DYNRT: $(foreign_module_tables | tr '\n' ' ')"
    return 1
  fi
  return 0
}

verdict_of() {
  local okv bdv
  okv=$(sed -n 's/.*ok=\([0-9-]*\).*/\1/p' <<<"$1")
  bdv=$(sed -n 's/.*bad=\([0-9-]*\).*/\1/p' <<<"$1")
  if [ "${okv:-X}" = 0 ] && [ -n "${bdv:-}" ] && [ "$bdv" -ge 4 ] 2>/dev/null; then
    printf 'CLEAN (ok=0 bad=%s -- kernel used poisoned WRONG)' "$bdv"
  elif [ -n "${okv:-}" ] && [ "$okv" -ge 4 ] 2>/dev/null; then
    printf 'INVERTED (ok=%s bad=%s -- replies left with FAKEA dst)' "$okv" "$bdv"
  else
    printf 'MIXED/OTHER (ok=%s bad=%s)' "$okv" "$bdv"
  fi
}

main() {
  say "=== S6b NEG residual-check start $(date '+%F %T') ==="

  # state evidence (artifacts, no mutation)
  say "nft tables now      : $(r "$NFT list tables" 2>/dev/null | tr '\n' ' ')"
  say "ct entries (17.31.x): $(r "grep -c '172.31.10' /proc/net/nf_conntrack 2>/dev/null" | tr -cd '0-9') of $(r "wc -l < /proc/net/nf_conntrack 2>/dev/null" | tr -cd '0-9') total"
  local ep age
  ep=$(r "cat /tmp/dynrt_s6b_pos_epoch 2>/dev/null" | tr -cd '0-9')
  if [ -n "${ep:-}" ]; then
    age=$(( $(r "date +%s" | tr -cd '0-9') - ep ))
    say "last battery POS epoch: age ${age}s (anchor TTL 60s $([ "$age" -ge 65 ] && echo DEAD || echo MAYBE-LIVE))"
    if [ "$age" -lt 65 ]; then
      say "waiting $(( 65 - age ))s for the battery-POS anchor to expire before asserting"
      sleep $(( 65 - age ))
    fi
  else
    say "last battery POS epoch: no marker"
  fi

  clean_base || { bad "baseline NOT clean -- aborting (this abort is itself evidence of theory A: residual writer state present)"; return 1; }
  say "baseline clean: no tun-holder, no stale neigh, no t6a, no DYNSRCROUTE table"
  r "ip neigh flush dev t6a 2>/dev/null || true"

  T=$(run_inj)
  V=$(verdict_of "$T")
  say "NEG: $T  =>  $V"
  r "sed -n '1,14p' /tmp/t6neigh.log 2>/dev/null" | sed 's/^/    neigh| /'

  case "$V" in
    CLEAN*)
      ok "VERDICT A: no live writer + long-expired anchor => NEG is CLEAN, as the discrim P1/P4 showed"
      ok "=> run9's 19:26 inversion REQUIRES a live DYNSRCROUTE writer in that window: a RESIDUAL"
      ok "   table (left by an earlier session; run9's own cleanup removed it -- hence 0 matches now)."
      ok "=> battery fix: s6b_precond must ASSERT + drop writer-absence before NEG (as the discrim clean_base does)."
      ;;
    INVERTED*)
      bad "VERDICT B: NEG INVERTED with no writer rule and long-expired anchor -- carrier UNKNOWN."
      bad "Residual-writer theory FALSIFIED. Escalate: kprobe/ftrace on dynrt_op_mac / dynrt_slot_pick / dynrt_anchor_mac (R6 plan)."
      ;;
    *)
      bad "MIXED/OTHER: neither signature -- treat as B-equivalent, escalate to kprobe (R6 plan)."
      ;;
  esac
  say "=== end $(date '+%F %T') ==="
}

main
