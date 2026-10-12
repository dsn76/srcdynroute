#!/usr/bin/env bash
# run_all.sh -- run the S1..S8 battery against deb13.
#
# Precondition (checked here):
#   - deb13 is up on the 6.12.111 custom kernel
#   - the srcdynroute.ko module is loaded
#   - a reference ruleset with DYNSRCROUTE/DYNRT parses and commits
#
# Each test is independent; a failure in one does not stop the rest.
# Results are also appended to /tmp/dynrt_results.log (by lib.sh finish).

cd "$(dirname "$0")"
source ./lib.sh

fail=0

say "==================== pre-flight on deb13 ===================="
pre_ok=YES
KER=$(r "uname -r")
say "deb13 kernel: $KER"
case "$KER" in
  6.12.111) ok "custom kernel running" ;;
  *) bad "expecting 6.12.111, got $KER"; pre_ok=NO ;;
esac

MOD=$(rs <<'EOF'
modprobe srcdynroute 2>/dev/null || true
lsmod | awk '$1=="srcdynroute"{print "LOADED"}'
EOF
)
[ "$MOD" = LOADED ] && ok "module loaded" || { bad "module not loaded"; pre_ok=NO; }

ALIA=$(r "$NFT list ruleset 2>/dev/null | grep -cE 'DYNSRCROUTE|DYNRT' || true")
say "existing dynrt rules in ruleset: ${ALIA:-0} (stale ones are flushed per-test)"

# Stale-state hygiene (2026-10-10 run-2 post-mortem): the S8 b1/b4 inversion
# was caused by a foreign table carrying a DYNSRCROUTE chain that the old
# pre-flight (dynrt_* counting only) could not see.  The module's expressions
# are only ever used by this battery's tables, so ANY table referencing them
# is test state: flush dynrt_* names AND any foreign table using the module's
# expressions.  Record the surviving ruleset for the report.
FL1=$(nft_flush_dynrt || true)
FOREIGN=$(foreign_module_tables || true)
if [ -n "${FOREIGN:-}" ]; then
  bad "foreign module-expression tables present -- deleting: $(tr '\n' ' ' <<<"$FOREIGN")"
  for ft in $FOREIGN; do
    set -- $ft
    r "$NFT delete table $1 $2 2>/dev/null || true"
  done
fi
say "ruleset now: $(rs 'NFT=/usr/local/sbin/nft; [ -x $NFT ] && $NFT list tables 2>/dev/null; echo <end>' | tr '\n' ' ')"

# Anchor hygiene (fix 2026-10-11): the module's anchor table drains only via
# the 60s TTL sweep, EXCEPT on module exit (srcdynroute_exit ->
# dynrt_anchor_flush).  A live anchor forces the reply oif even with NO rule
# loaded -- observed: S1 b1 answered seg1=5/seg2=0 with tagop=0 because the
# anchor written by a manual run 22s earlier was still inside its TTL.  The
# rules are already flushed above (nft_flush_dynrt/foreign tables), so rmmod
# has no expr references; reload resets the module to a provably anchor-free
# state.  modprobe re-loads it from /lib/modules/6.12.111/updates.
ANCH=$(rs <<'EOF'
rmmod srcdynroute 2>/dev/null || true
modprobe srcdynroute 2>/dev/null || true
lsmod | awk '$1=="srcdynroute"{print "RELOADED"}'
EOF
)
case "$ANCH" in
  *RELOADED*) ok "module reloaded -- anchor table flushed (module exit hook)" ;;
  *) bad "module reload FAILED -- a live anchor from a previous run may survive (S1 b1 risk)"; pre_ok=NO ;;
esac

# Conntrack hygiene (fix 2026-10-11): the ct-ext slot data (patch 0002) is
# PERSISTENT -- it lives in the ct entry and survives rmmod/reboot-adjacent
# module reloads and table drops, so a stale slot from an earlier run makes
# DYNRT match and the chain-m counter count non-test traffic (observed:
# counter=32 for a 5-ping window -- ssh ct still carried a slot written by
# the old unconditional-writer rules).  Flush conntrack so every NEG starts
# from a provably slot-free state; ssh re-creates its ct on the next packet.
r "conntrack -F >/dev/null 2>&1 || true" >/dev/null 2>&1 || true
say "conntrack flushed (persistent ct-ext slots cleared for a clean baseline)"

if [ "$pre_ok" = NO ]; then
  say "pre-flight FAILED -- refusing to run the battery"
  exit 1
fi
say "pre-flight OK"

for t in S1_v4_inout.sh S2_v6_inout.sh S3_forward.sh S4_masq.sh \
         S5_blackhole.sh S6_ifacct_types.sh S7_concurrency.sh S8_rule_update.sh; do
  say "==================== running $t ===================="
  LOGN=$(wc -l < /tmp/dynrt_results.log 2>/dev/null || echo 0)
  bash ./"$t" 2>&1 | tee /tmp/dynrt_last
  # find the verdict line appended (if any) by this test.
  # lib.sh finish() records "test=<S_NAME> verdict=..." where S_NAME is the
  # short form (S1, S2, ...) set by each script, NOT the file name -- so match
  # on the script name stem prefix (S1_v4_inout.sh -> S1), with a trailing
  # space guard to keep the match strict.
  case "$t" in
    S[0-9]*) nm=${t%%_*} ;;
    *) nm="${t%.sh}" ;;
  esac
  V=$(tail -n +"$((LOGN+1))" /tmp/dynrt_results.log 2>/dev/null | grep -m1 "test=${nm} " || true)
  case "$V" in
    *"verdict=PASS"*) say ">>> $t : PASS" ;;
    *) say ">>> $t : FAIL/ABORT -- last lines: $(tail -3 /tmp/dynrt_last | tr '\n' ' ')"; fail=1 ;;
  esac
  echo
done

say "==================== battery summary ===================="
tail -8 /tmp/dynrt_results.log 2>/dev/null | sed 's/\(.*\) test=/  test=/; s/ verdict=/  verdict=/'
[ $fail -eq 0 ] && say "ALL TESTS PASS" || say "SOME TESTS FAILED (see above)"
exit $fail
