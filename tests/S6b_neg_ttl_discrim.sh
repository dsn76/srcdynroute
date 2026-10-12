#!/usr/bin/env bash
# S6b NEG-TTL discrimination (root-cause of the ok=5/bad=0 inversion).
#
# Hypothesis under test (code-grounded, 2026-10-10 D-phase):
#   The DYNSRCROUTE target (dynrt_srcroute_eval, srcdynroute.c L1075-1093)
#   writes a module-global ANCHOR for the reverse flow (exact 4-tuple, ports
#   0/0 for ICMP, peer L2 = FAKEA), TTL DYNRT_ANCHOR_TTL_MS = 60s, refreshed
#   on every write.  The reader (dynrt_op_mac, L975-989) serves that anchor
#   for the exact reply tuple at xmit time, independent of neighbour state,
#   and patch 0005 applies it over neigh->ha.  The anchor list is invisible
#   and unflushable from user space; an nft table drop does NOT clear it.
#   => a NEG phase that runs within 60s of any prior POS phase (same or
#      earlier battery run) gets FAKEA forced despite "no rules": ok=5 bad=0.
#   A clean NEG (anchor expired/never written) must show the kernel using
#   the poisoned WRONG: ok=0 bad>=4 (the original S6b contract).
#
# Design: ONE controlled variable = anchor freshness (time since the last
# DYNSRCROUTE write on the 172.31.10.67 flow).  All other preconds
# (no /dev/net/tun holder, no stale neigh, no DYNSRCROUTE/DYNRT table,
# fresh t6a per phase, neigh flushed) are held identical across phases.
#
#   P0 clean + wait 75s  -> guarantees no live anchor from prior runs
#   P1 NEG (clean)       -> want ok=0, bad>=4   (kernel uses poisoned WRONG)
#   P2 POS               -> want ok>=4          (writes the FAKEA anchor)
#   P3 NEG (dirty)       -> prediction ok>=4    (inversion reproduced:
#                              the module anchor, not the kernel, is the
#                              FAKEA source -- neigh timeline proves it)
#   P4 NEG (clean, +75s) -> want ok=0, bad>=4   (inversion gone: TTL did it)
#
# Confirmation signature: P1 clean-OK, P3 inverted, P4 clean-OK.
# Any other pattern => hypothesis falsified or confounded: escalate to
# kprobe/ftrace on dynrt_op_mac / dynrt_anchor_mac (R6 plan).

set -u
cd "$(dirname "$0")"
. ./lib.sh

TAB_B=dynrt_s6b

# --- copied verbatim from S6_ifacct_types.sh (incl. the L286 quote fix) ---
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

# --- clean baseline, STRICT: any candidate confounder fails the phase ---
clean_base() {
  local t
  r "pkill -f 't6in[.]py' 2>/dev/null || true"
  sleep 0.3
  r "ip link del t6a 2>/dev/null || true"
  sleep 0.2
  # (a) no process may hold a /dev/net/tun fd (a stray responder answers
  # the kernel's who-has for PEER -- the R5 "phantom" class)
  t=$(rs <<'PRE'
for p in /proc/[0-9]*; do
  if ls -l "$p/fd" 2>/dev/null | grep -q '/dev/net/tun'; then
    printf 'pid=%s cmd=%s\n' "${p##*/}" "$(tr -d '\0' < "$p/cmdline" 2>/dev/null | head -c 48)"
  fi
done
PRE
)
  if [ -n "${t:-}" ]; then
    bad "clean_base: process holding /dev/net/tun: $(tr '\n' ' ' <<<"$t")"
    return 1
  fi
  # (b) no stale 172.31.10.67 neigh entry (stale FAKEA neigh = mechanism-1
  # confounder: the kernel itself could serve FAKEA)
  if [ -n "$(r "ip -4 neigh show to 172.31.10.67 2>/dev/null")" ]; then
    bad "clean_base: stale neigh 172.31.10.67: $(r "ip -4 neigh show to 172.31.10.67" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  # (c) t6a must be gone (the injector recreates it fresh per phase)
  if [ -n "$(r "ip link show t6a 2>/dev/null")" ]; then
    bad "clean_base: t6a still present after del: $(r "ip link show t6a" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  # (d) NO DYNSRCROUTE-bearing table anywhere (dynrt_* or foreign, the
  # 2026-10-10 `table ip cx` class) -- a live writer could re-anchor at any
  # moment and would re-contaminate mid-experiment
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

# classify an injector stats line by the S6b contract
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

show_neigh() { # $1 label
  r "sed -n '1,14p' /tmp/t6neigh.log 2>/dev/null" | sed "s/^/    $1| /"
}

main() {
  say "=== S6b NEG-TTL discrimination start $(date '+%F %T') ==="
  say "single controlled variable: anchor freshness (DYNRT_ANCHOR_TTL_MS=60000)"

  # ---------------- P0: global clean + TTL-kill for prior-run anchors ------
  nft_flush_dynrt >/dev/null 2>&1 || true
  sleep 2
  clean_base || { bad "P0 baseline unenforceable -- aborting"; return 1; }
  say "P0: sleeping 75s (> 60s anchor TTL) so any prior-run anchor is dead"
  sleep 75
  clean_base || { bad "P0 baseline unenforceable after wait -- aborting"; return 1; }
  r "ip neigh flush dev t6a 2>/dev/null || true"

  # ---------------- P1: NEG, anchor must be absent -------------------------
  T1=$(run_inj)
  V1=$(verdict_of "$T1")
  say "P1 NEG-clean          : $T1  =>  $V1"
  show_neigh "P1-neigh"

  # ---------------- P2: POS (writes the FAKEA anchor for .1->.67) ---------
  if ! nft_apply "$TAB_B" <<'DEF'
table ip dynrt_s6b {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		iifname "t6a" ip daddr 172.31.10.1 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 172.31.10.67 DYNRT counter
	}
}
DEF
  then
    bad "P2 POS: table apply/verify failed -- aborting (no contaminant made)"
    return 1
  fi
  r "ip neigh flush dev t6a 2>/dev/null || true"
  sleep 0.3
  CNB0=$(nft_cnt ip "$TAB_B")
  T2=$(run_inj)
  CNB=$(nft_cnt ip "$TAB_B")
  say "P2 POS                : $T2  (DYNRT cnt $CNB0 -> $CNB, dCNT=$(cnt_delta "$CNB0" "$CNB"))"
  say "   P2 writer fires => ANCHOR {172.31.10.1 -> 172.31.10.67, ICMP 0/0, hw=FAKEA, TTL 60s} is now LIVE in the module"

  # ---------------- P3: NEG within anchor TTL (the 17:37 signature) -------
  nft_drop "$TAB_B" ip || { bad "P3: TAB_B drop UNVERIFIED -- aborting"; return 1; }
  T3=$(run_inj)
  V3=$(verdict_of "$T3")
  say "P3 NEG-dirty (<=60s)  : $T3  =>  $V3"
  show_neigh "P3-neigh"

  # ---------------- P4: NEG after anchor TTL expires ----------------------
  say "P4: sleeping 75s for the anchor TTL to expire (only mechanism that can clear it)"
  sleep 75
  clean_base || { bad "P4 baseline unenforceable -- skipping P4"; return 1; }
  r "ip neigh flush dev t6a 2>/dev/null || true"
  T4=$(run_inj)
  V4=$(verdict_of "$T4")
  say "P4 NEG-clean (after)  : $T4  =>  $V4"
  show_neigh "P4-neigh"
  nft_drop "$TAB_B" ip >/dev/null 2>&1 || true

  # ---------------- verdict -------------------------------------------------
  say "=== DISCRIMINATION VERDICT ==="
  case "$V1|$V3|$V4" in
    CLEAN*|INVERTED*|CLEAN*)
      ok "HYPOTHESIS CONFIRMED: anchor freshness ALONE flips the NEG baseline"
      ok "  P1 (no anchor) = CLEAN, P2 (POS writes anchor), P3 (anchor live) = INVERTED, P4 (anchor expired) = CLEAN"
      ok "=> 17:37 R6-replay#2 NEG inversion (ok=5 bad=0) = module anchor written by a"
      ok "   prior POS survived the nft drop; the kernel itself was NOT the FAKEA source"
      ;;
    INVERTED*|*|*)
      bad "HYPOTHESIS FALSIFIED: P1 (clean, pre-anchor) already inverted -- a confounder"
      bad "   outside the anchor (stale state or phantom responder) is serving FAKEA. Escalate: kprobe/ftrace."
      ;;
    *)
      bad "PATTERN NOT EXPLAINED by the anchor-TTL hypothesis: P1=${V1%% *}, P3=${V3%% *}, P4=${V4%% *}"
      bad "  Escalate: kprobe on dynrt_op_mac / dynrt_anchor_mac (R6 plan) + full nft dumps."
      ;;
  esac
  say "=== end $(date '+%F %T') ==="
}

main
