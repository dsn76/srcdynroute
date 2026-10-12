#!/usr/bin/env bash
# S6b NEG prime matrix -- controlled experiments to localize the NEG
# inversion carrier (2026-10-10, after the run9 19:26 / run10 20:07 /
# run11 22:59 INVERTED triad vs the 19:44 / 22:27 CLEAN probes).
#
# Correlation under test: every INVERTED NEG ran within 60s (the module
# anchor TTL) of a DYNSRCROUTE writer fire; every CLEAN NEG had no such
# fire in that window.
#
#   E1  baseline NEG (fresh stand, no prime)              -> expect CLEAN
#   E2  S6a writer prime (tagop-proven) + ~25s + NEG      -> expect INVERTED
#   E3  S6a writer prime + ~75s (TTL lapsed) + NEG        -> expect CLEAN
#   E4  S6a writer prime + rmmod/modprobe (anchor-store wipe)
#       + immediate NEG                                   -> expect CLEAN
#       (if it stays INVERTED the carrier is provably not module state)
#
# Instrumentation per NEG phase (tracefs kprobes, lib.sh kp_*):
#   macop    p: dynrt_op_mac           -- module MAC-decision calls
#   macret   r: dynrt_op_mac $retval   -- retval != 0 => a carrier served a MAC
#   tagop    p: dynrt_srcroute_eval    -- writer fires (MUST be 0 during NEG)
#   tgmop    p: dynrt_match_eval       -- DYNRT match evaluations
#   retdyn4/6/retdynsk                 -- forced-oif return values
#   canary   `nft list tables` md5 every 0.25s (catches any rule add/del
#            by anything, incl. foreign writers, inside the window)
#   pcap     tcpdump -i t6a ground truth (independent of the injector)
#
# The prime proves the writer fired via the tagop kprobe count and the
# TAB_A DYNRT counter delta (same evidence standard as the battery S6a).

set -u
cd "$(dirname "$0")"
. ./lib.sh

NSA6=nsA6 ; A6R=a6r ; A6V=a6v ; TIP=172.31.10.67 ; TAB_A=dynrt_s6a

# ------------------------------------------------------------- prime (S6a)
# Fires the writer on the 172.30.10.x flow and proves it with the tagop
# kprobe + DYNRT counter, then removes all of its own state (table, netns,
# rp_filter).  The only thing that must survive is the MODULE-INTERNAL
# anchor entry (TTL 60s) -- exactly the correlation the matrix tests.
prime_s6a() { # prints: fires=<tagop count> pings=<rcvd/sent> dCNT=<n>
  local RP_SAVE out pings fires dCNT c0 c1 tgc
  ns_up "$NSA6" "$A6R" "$A6V" "172.30.10.1/24" "172.30.10.67/24" \
    || { say "PRIME: ns_up FAILED"; return 1; }
  RP_SAVE=$(rpf_snap "$A6R")
  rpf0 "$A6R"
  rpf0ns "$NSA6" "$A6V"
  nft_drop "$TAB_A" ip >/dev/null 2>&1 || true
  out=$(nft_apply "$TAB_A" <<'DEF'
table ip dynrt_s6a {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		iifname "a6r" ip daddr 172.30.10.1 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 172.30.10.67 DYNRT counter
	}
}
DEF
)
  grep -q NFT_OK <<<"$out" || { say "PRIME: nft_apply FAILED: $(tr '\n' ' ' <<<"$out")"; return 1; }

  kp_arm >/dev/null 2>&1 || true
  c0=$(nft_cnt ip "$TAB_A")
  pings=$(hpings "$NSA6" "172.30.10.1" 5)
  tgc=$(kp_count | awk '/^tagop=/ {print $1}')
  c1=$(nft_cnt ip "$TAB_A")
  kp_disarm >/dev/null 2>&1 || true

  nft_drop "$TAB_A" ip >/dev/null 2>&1 || true
  [ -n "${RP_SAVE:-}" ] && rpf_put "$RP_SAVE"
  ns_down "$NSA6" "$A6R" >/dev/null 2>&1 || true
  fires=${tgc#tagop=}
  dCNT=$(( ${c1:-0} - ${c0:-0} ))
  echo "fires=${fires:-?} pings=${pings:-0/0} dCNT=${dCNT}"
}

# ---------------------------------------------------- NEG phase (one run)
# NOTE: `r` is one ssh per call (no shell variable persists between calls),
# so the canary + pcap-waiter + injector + kills live in ONE rs invocation.
neg_phase() { # $1 = phase label
  local ph=$1 OUT T V KA MR ctpre ep age
  local LOGD=/tmp/pm_$ph

  r "pkill -f 't6in[.]py' 2>/dev/null || true"
  r "ip link del t6a 2>/dev/null || true"
  sleep 0.4

  # strict clean baseline (same assertions as S6b_neg_residual_check.sh)
  if [ -n "$(r "for p in /proc/[0-9]*; do ls -l \$/p/fd 2>/dev/null | grep -q '/dev/net/tun' && echo X; done")" ]; then
    bad "[$ph] tun-holder present -- phase aborted"; return 2
  fi
  if [ -n "$(r "ip -4 neigh show to $TIP 2>/dev/null")" ]; then
    bad "[$ph] stale neigh $TIP: $(r "ip -4 neigh show to $TIP 2>/dev/null" | tr '\n' ' ')"
  fi
  if [ -n "$(r "$NFT list tables 2>/dev/null | awk '\$3 ~ /^dynrt_/ {print}')")" ]; then
    bad "[$ph] dynrt_* table present: $(r "$NFT list tables 2>/dev/null" | tr '\n' ' ')"
  fi
  if [ -n "$(foreign_module_tables)" ]; then
    bad "[$ph] foreign writer table: $(foreign_module_tables | tr '\n' ' ')"
  fi
  ctpre=$(r "awk '/172\.31\.10/ {n++} END {print n+0}' /proc/net/nf_conntrack 2>/dev/null" | tr -d ' ')
  say "[$ph] baseline OK: no tun-holder, no stale neigh, no DYNSRCROUTE table, ct(172.31.10)=${ctpre:-?}"
  if [ "${ctpre:-0}" -ge 1 ] 2>/dev/null; then
    bad "[$ph] ct(172.31.10)=$ctpre -- stale ct with possible dynrt ext slot (a legitimate carrier!)"
  fi

  # report -- never block -- the battery-POS epoch (a known .31/FAKEA carrier if live)
  ep=$(r "cat /tmp/dynrt_s6b_pos_epoch 2>/dev/null" | tr -cd '0-9')
  if [ -n "${ep:-}" ]; then
    age=$(( $(r "date +%s" | tr -cd '0-9') - ep ))
    say "[$ph] last battery-POS epoch age=${age}s ($([ "$age" -ge 65 ] && echo DEAD || echo MAYBE-LIVE anchor))"
  fi

  # kprobe arm (module must be loaded) + macret retprobe + buffer + denoise
  KA=$(kp_arm)
  say "[$ph] kprobes: $KA"
  MR=$(r "T=/sys/kernel/tracing
sed -i '/macret/d' \$T/kprobe_events 2>/dev/null
if printf 'r:macret dynrt_op_mac \$retval\n' >> \$T/kprobe_events 2>/dev/null; then
  echo 1 > \$T/events/kprobes/macret/enable 2>/dev/null && echo MACRET_ARMED || echo MACRET_ENABLE_FAIL
else
  echo MACRET_ARM_FAIL
fi
echo 1024 > \$T/buffer_size_kb 2>/dev/null
for e in dyn4 dyn6 dynsk; do echo 0 > \$T/events/kprobes/\$e/enable 2>/dev/null; done
printf '' > \$T/trace 2>/dev/null
echo 1 > \$T/tracing_on 2>/dev/null")
  say "[$ph] macret retprobe: ${MR:-NO_RESPONSE} (denoised: dyn4/dyn6/dynsk p-probes disabled)"

  # THE phase: canary + pcap + injector + kills in ONE remote bash
  OUT=$(rs <<'PHASEOF'
PH=$1
NFT=/usr/local/sbin/nft
LOGD=/tmp/pm_$PH
( for i in $(seq 1 100); do
    printf '%s %s\n' "$(date +%s.%3N)" "$($NFT list tables 2>/dev/null | md5sum | cut -d' ' -f1)"
    sleep 0.25
  done ) > $LOGD.canary 2>/dev/null &
CANY=$!
( DUE=$(( $(date +%s) + 24 ))
  while [ "$(date +%s)" -lt "$DUE" ] && [ ! -e /sys/class/net/t6a ]; do sleep 0.1; done
  if [ -e /sys/class/net/t6a ]; then
    DUE2=$(( $(date +%s) + 20 ))
    while [ -e /sys/class/net/t6a ] && [ "$(date +%s)" -lt "$DUE2" ]; do
      timeout 12 tcpdump -i t6a -s0 -c 64 -w $LOGD.pcap -Z root 2>/dev/null
    done
  fi
) &
PCAP=$!
rm -f /tmp/t6stat.txt /tmp/t6neigh.log
timeout 25 python3 /tmp/t6in.py >/dev/null 2>&1 &
PJ=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 0.5
  { echo "snapshot_t=$i"; ip neigh show dev t6a; } >> /tmp/t6neigh.log 2>&1
done
wait "$PJ" 2>/dev/null
INJRC=$?
kill $CANY 2>/dev/null
echo INJ_STATS_BEGIN
cat /tmp/t6stat.txt 2>/dev/null || echo 'ok=- bad=- other=- arp=- req=-'
INJ_RC=$INJRC
echo INJ_STATS_END
wait $PCAP 2>/dev/null
echo PHASE_DONE
PHASEOF
) || true

  T=$(sed -n '/INJ_STATS_BEGIN/,/INJ_STATS_END/p' <<<"$OUT" | sed '1d;$d')
  V=$(verdict_of "$T")
  say "[$ph] NEG injector: ${T:-(no stats)}  =>  $V"

  # evidence bundle
  say "[$ph] neigh timeline:"
  r "sed -n '1,12p' /tmp/t6neigh.log 2>/dev/null" | sed 's/^/    neigh| /' || true
  say "[$ph] kprobe counts: $(kp_count | tr '\n' ' ')"
  say "[$ph] macret retvals (last 8; non-zero = module served a MAC):"
  r "grep -E ' +macret:' /sys/kernel/tracing/trace 2>/dev/null | tail -8" | sed 's/^/    macret| /' || true
  say "[$ph] retdyn4 (oif-fl4 output slow path) last 4:"
  r "grep -E ' +retdyn4:' /sys/kernel/tracing/trace 2>/dev/null | tail -4" | sed 's/^/    retdyn4| /' || true
  say "[$ph] canary: $(r "awk '{print \$2}' $LOGD.canary 2>/dev/null | sort -u | wc -l" | tr -d ' ') unique table-hash(es) over $(r "wc -l < $LOGD.canary 2>/dev/null" | tr -d ' ') samples"
  local CHX; CHX=$(r "awk 'NR==1{h=\$2} NR>1 && \$2!=h {print \$2}' $LOGD.canary 2>/dev/null | sort -u | tr '\n' ' '")
  [ -n "${CHX:-}" ] && say "[$ph] CANARY CHANGED DURING WINDOW: $CHX"
  say "[$ph] nft tables now: $(r "$NFT list tables 2>/dev/null" | tr '\n' ' ')"
  say "[$ph] ct 172.31.10 after: $(r "awk '/172\.31\.10/ {n++} END {print n+0}' /proc/net/nf_conntrack 2>/dev/null")"
  if [ -n "$(r "ls $LOGD.pcap 2>/dev/null")" ]; then
    say "[$ph] pcap ground truth (reply L2-dst histogram, src=172.31.10.1):"
    r "tcpdump -r $LOGD.pcap -nn -e 2>/dev/null | grep '172.31.10.1' | sed -n 's/^[0-9:.]* \\{1,\\}\\([0-9a-f]\\{2\\}\\(:[0-9a-f]\\{2\\}\\)\\{5\\}\\.\\{0,\\}\\).*/\\1/p' | sort | uniq -c" | sed 's/^/    pcap-dst| /' || true
    say "[$ph] pcap ARP frames: $(r "tcpdump -r $LOGD.pcap -nn 2>/dev/null | grep -ci 'who-has' || true")"
  else
    say "[$ph] pcap: NOT CAPTURED (t6a missed or tcpdump unavailable)"
  fi
  dm_bad | sed 's/^/    dmesg| /' || true
  kp_disarm >/dev/null 2>&1 || true
  r "ip link del t6a 2>/dev/null || true"
  return 0
}

# ------------------------------------------------------------- helpers
verdict_of() {
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

# --------------------------------------------------------------------- main
main() {
  say "=== S6b NEG prime matrix start $(date '+%F %T') ==="
  say "deb13: $(r "uname -r") tables=[$(r "$NFT list tables" 2>/dev/null | tr '\n' ' ')] ct=$(r "wc -l < /proc/net/nf_conntrack" 2>/dev/null | tr -d ' ')"
  say "module: $(r "lsmod | grep -w srcdynroute")"

  say "---------- E1: baseline NEG (no prime) ----------"
  neg_phase E1 || say "E1 phase errored"
  sleep 3

  say "---------- E2: prime + ~25s + NEG ----------"
  local P2; P2=$(prime_s6a) || say "E2 PRIME FAILED -- E2 invalid"
  say "E2 prime: $P2  (fires>0 = writer proven)"
  sleep 22
  neg_phase E2 || say "E2 phase errored"
  sleep 3

  say "---------- E3: prime + ~75s (TTL lapsed) + NEG ----------"
  local P3; P3=$(prime_s6a) || say "E3 PRIME FAILED -- E3 invalid"
  say "E3 prime: $P3"
  sleep 72
  neg_phase E3 || say "E3 phase errored"
  sleep 3

  say "---------- E4: prime + rmmod/modprobe (anchor-store reset) + immediate NEG ----------"
  local P4; P4=$(prime_s6a) || say "E4 PRIME FAILED -- E4 invalid"
  say "E4 prime: $P4"
  say "E4: rmmod srcdynroute (anchor-store WIPED) + modprobe:"
  r "rmmod srcdynroute 2>&1 && echo RM_OK || echo RM_FAIL; sleep 1; modprobe srcdynroute 2>&1 && echo MOD_OK || echo MOD_FAIL; sleep 1; lsmod | grep -w srcdynroute"
  sleep 2
  neg_phase E4 || say "E4 phase errored"

  say "=== end $(date '+%F %T') ==="
}

main
