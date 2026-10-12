#!/usr/bin/env bash
# m6_matrix.sh -- S6 A/B injector matrix (cur_report_01.md sec.6, audit_02 E-06)
#
# Four cells, run STANDALONE on deb13 -- no S6a/S6b context at all (no TAB_A,
# no rules, no blackhole, no rpf relaxation).  A standalone run is exactly
# what isolates the three round-1 suspects of the S6b NEG inversion
# (run-3: ok=5 with NO rules):
#   (a) the 172.31.10.x network on deb13   (hyp H5: route/policy/arp-proxy/tc)
#   (b) the instrumented injector code     (t6in2 select+log; R4 zero-frame)
#   (c) the in-run S6a/S6b state itself    (surviving rule / phantom holder)
# Cells exclude (c) by construction; (a) and (b) are isolated by the grid:
#
#   code\net       172.31.10.0/24              172.33.10.0/24
#  +--------------+----------------------------+-----------------------------+
#  | t6in  (C0)   | round-1 R1: bad=5 (base)   | C3 (round-1 cell was missing)|
#  | t6in2 (C2)   | round-1 R4: 0/0 (defect)   | C2 << audit-mandated cell >> |
#  | probe3 (C1)  | C1 << audit-mandated cell >>| round-1 V3/V4: arps=3       |
#
# Per-cell verdicts against the ruleless NEG baseline
# (S6-script expectation, confirmed by R1): ok=0, bad>=4, arp>=1
#   BASELINE     ok=0, bad>=4, arp>=1         -- variable NOT present in cell
#   INVERSION    ok>=4                        -- replies FAKEA-carried (phantom)
#   CODE-DEFECT  0/0 (R4 signature)           -- instrumented path broken
#   DEVIANT      anything else
# Global discriminator (cur_report_01 sec.7.2):
#   C1 BASELINE && C2 != BASELINE  -> CODE (t6in2 select+log) is the cause
#   C1 != BASELINE && C2 BASELINE  -> NETWORK (172.31.10.x specifics) cause
#   both BASELINE                  -> standalone cannot reproduce inversion ->
#                                    context (c) is the variable -> R6 replay
#   both non-BASELINE              -> common env factor; audit preflight again
#
# This is a DIAGNOSTIC matrix, not a PASS/FAIL gate: it runs all four cells,
# classifies them, fetches the evidence into doc/results/ and records the
# classification.  Exit 0 iff preflight clean and all four cells completed.
set -u
S_NAME=M6MAT
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

OUT=${M6_OUT:-$(cd "$(dirname "$0")/.." && pwd)/doc/results}
mkdir -p "$OUT"

say "== M6 preflight (deb13 evidence) =="
PREFLIGHT_OK=YES

# (1) no stray process may hold a /dev/net/tun fd (S6 s6b_precond(1) pattern)
TUNH=$(rs <<'PRE'
for p in /proc/[0-9]*; do
  if ls -l "$p/fd" 2>/dev/null | grep -q '/dev/net/tun'; then
    printf 'pid=%s comm=%s\n' "$(basename "$p")" "$(cat "$p/comm" 2>/dev/null)"
  fi
done
PRE
)
if [ -n "${TUNH:-}" ]; then
  bad "preflight: tun fd holders present: $(tr '\n' ' ' <<<"$TUNH")"
  PREFLIGHT_OK=NO
else
  ok "preflight: no /dev/net/tun fd holders"
fi

# (2) no leftover t6* devices / addresses / routes / neigh on the cell nets
for d in t6a t6c t6d t6e; do r "ip link del $d 2>/dev/null || true"; done
RIP=$(r "ip -4 addr show | grep -E '172\.(31|33)\.10' || true")
RRT=$(r "ip route show | grep -E '172\.(31|33)\.10' || true")
RNG=$(r "ip neigh show | grep -E '172\.(31|33)\.10' || true")
if [ -z "${RIP:-}" ] && [ -z "${RRT:-}" ] && [ -z "${RNG:-}" ]; then
  ok "preflight: no 172.31.10.x / 172.33.10.x addr, route, neigh residue"
else
  bad "preflight: residue -- addr=[$RIP] route=[$RRT] neigh=[$RNG]"
  PREFLIGHT_OK=NO
fi

# (3) H5 evidence base: arp-proxy / arp-ignore / arp-filter / forwarding /
# rp_filter / tc -- what 172.31.10.x can *do* before we even inject
r "echo ARP-CONF: \$(sysctl net.ipv4.conf.all.proxy_arp net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_filter net.ipv4.conf.all.forwarding net.ipv4.conf.enp0s3.rp_filter 2>/dev/null | tr -d '\n' | sed 's/net.ipv4.conf.//g; s/ = /=/g') \$(tc qdisc show 2>/dev/null | head -3 | tr '\n' '|')" | sed 's/^/  /'

# (4) context declaration: regime B (ctbench) + B4 module + nft state
r "echo 'CTBENCH-STATE tables:'; nft list tables 2>/dev/null; echo 'ct-entries:'; wc -l < /proc/net/nf_conntrack 2>/dev/null" | sed 's/^/  /'
r "echo MODULE: \$(cat /sys/module/srcdynroute/srcversion 2>/dev/null)" | sed 's/^/  /'

# (5) python3 present (injector dependency)
PY=$(r "python3 -V 2>&1")
ok "preflight: $PY"

# stage the injector (same pattern as S6's t6in.py heredoc)
r "rm -f /tmp/m6.py"
"${SSH[@]}" "cat > /tmp/m6.py" < ./m6.py
ST=$(r "[ -s /tmp/m6.py ] && wc -c < /tmp/m6.py")
ok "preflight: staged /tmp/m6.py (${ST:-MISSING} bytes)"
[ -n "${ST:-}" ] || PREFLIGHT_OK=NO

# --------------------------------------------------------------- one cell ---
# classify INJ line against the baseline / inversion / defect signatures
classify() {
  local l=$1 okc badc arpc
  okc=$(sed -n 's/.*ok=\([0-9]*\) .*/\1/p' <<<"$l")
  badc=$(sed -n 's/.*bad=\([0-9]*\) .*/\1/p' <<<"$l")
  arpc=$(sed -n 's/.*arp=\([0-9]*\) .*/\1/p' <<<"$l")
  if [ "${okc:-0}" -ge 4 ]; then
    echo INVERSION
  elif [ "${okc:-0}" -eq 0 ] && [ "${badc:-0}" -ge 4 ] && [ "${arpc:-0}" -ge 1 ]; then
    echo BASELINE
  elif [ "${okc:-0}" -eq 0 ] && [ "${badc:-0}" -eq 0 ]; then
    echo CODE-DEFECT
  else
    echo DEVIANT
  fi
}

CELL_VERDICTS=()
cell() { # <tag> <dev> <net> <mode>
  local tag=$1 dev=$2 net=$3 mode=$4
  local out injl verdict
  say "== $tag: mode=$mode dev=$dev net=${net}.0/24 (MINE=${net}.1 PEER=${net}.67) =="
  r "pkill -f 'm6[.]py' 2>/dev/null || true"
  r "ip link del $dev 2>/dev/null || true"
  sleep 0.4
  out=$(r "timeout 35 python3 /tmp/m6.py $dev $net $mode 2>&1" || true)
  printf '%s\n' "$out" | sed 's/^/    /'
  # evidence: neighbour timeline + wire log (select mode)
  r "cat /tmp/t6neigh_${dev}.log 2>/dev/null" > "$OUT/m6_${tag}_neigh_${dev}.log"
  if [ "$mode" = select ]; then
    r "cat /tmp/t6wire_${dev}.log 2>/dev/null" > "$OUT/m6_${tag}_wire_${dev}.log"
  fi
  # teardown of the non-persist TAP anyway
  r "pkill -f 'm6[.]py' 2>/dev/null || true"
  r "ip link del $dev 2>/dev/null || true"
  sleep 0.3
  injl=$(grep -m1 '^INJ ' <<<"$out")
  if [ -z "$injl" ]; then
    verdict=INCOMPLETE
  else
    verdict=$(classify "$injl")
  fi
  ok "$tag verdict: $verdict  ($injl)"
  CELL_VERDICTS+=("$tag=$verdict")
}

[ "$PREFLIGHT_OK" = YES ] || { bad "preflight broken -- refusing to classify cells"; exit 1; }
say "== M6 matrix execution =="
cell C0 t6a 172.31.10 plain
cell C1 t6d 172.31.10 minimal
cell C2 t6e 172.33.10 select
cell C3 t6c 172.33.10 plain

# ---------------------------------------------------------- global verdict ---
vc() { printf '%s' "$(sed -n "s/^$1=//p" <<<"$(printf '%s\n' "${CELL_VERDICTS[@]}")")"; }
C1V=$(vc C1); C2V=$(vc C2)
say "== M6 global classification =="
if [ "$C1V" = BASELINE ] && [ "$C2V" != BASELINE ]; then
  GLOBAL="CODE: t6in2 select+log plumbing is the discriminating variable (C2=$C2V on clean 172.33.10.x; C1 BASELINE on 172.31.10.x)"
elif [ "$C1V" != BASELINE ] && [ "$C2V" = BASELINE ]; then
  GLOBAL="NETWORK: 172.31.10.x-specific state on deb13 is the discriminating variable (C1=$C1V with minimal code; C2 BASELINE on 172.33.10.x)"
elif [ "$C1V" = BASELINE ] && [ "$C2V" = BASELINE ]; then
  GLOBAL="CONTEXT: standalone matrix cannot reproduce the inversion (both audit cells BASELINE) -> cause is the in-run S6a/S6b state -> R6 instrumented replay is the discriminator"
elif [ "$C1V" != BASELINE ] && [ "$C2V" != BASELINE ]; then
  GLOBAL="COMMON-ENV: both cross cells deviate (C1=$C1V C2=$C2V) -> shared deb13 env factor; re-audit preflight before concluding"
else
  GLOBAL="INCOMPLETE: cell verdicts unavailable (C1=$C1V C2=$C2V)"
fi
ok "cells: $(tr '\n' ' ' <<<"$(printf '%s\n' "${CELL_VERDICTS[@]}")")"
ok "$GLOBAL"
finish PASS "$(tr '\n' ' ' <<<"$(printf '%s\n' "${CELL_VERDICTS[@]}")") :: $GLOBAL"
exit 0
