#!/usr/bin/env bash
# S7 -- concurrency / lock-safety: 100 simultaneous new connections, each
#       exercising the full path at once:
#         - ct lookup + direction classification (dynrt_dir_of)
#         - ct-extension write to slot[D^1] on an unconfirmed ct
#         - forced-oif FIB lookup on the reply (blackhole anomaly active)
#         - DYNRT match (ct-extension read, RCu) on every reply
#
# Topology: S5 shape (host A 192.168.200.67 <-> deb13 192.168.200.12).
# An anomaly route (blackhole to A) is in place for the whole POS phase, so
# every single reply depends on the forced-egress path taken under
# simultaneous ct/slot churn.
#
#   b0  baseline sanity 5/5 (no anomaly)
#   b1  NEG sanity: blackhole, no rules -> 0/3
#       (adaptive: if a carry-over anchor is still in its TTL window, wait
#        >=65 s and re-ping once; the re-ping must be 0/3 -- 14:22 incident)
#   b2  POS: blackhole + rules; 100 one-shot pings, 10 in parallel
#       -> every ping opens a fresh conntrack entry (fresh slot) and its
#          reply must be rescued by the forced lookup.
#
# PASS = b0 5/5 && b1 0/3 && b2 100/100 + DYNRT counter >= 100 + dmesg
#        clean.  ftrace kprobe counts (dyn4/dynsk) are auxiliary and are
#        reported, not required (module symbols may be absent from
#        kallsyms without CONFIG_KALLSYMS_ALL).

S_NAME=S7
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s7
P=100

cleanup() {
  nft_drop "$TAB" || true
  bh_off "$A_IP" 2>/dev/null || true
  # rp_filter restore AFTER bh_off (S3 lesson)
  if [ -n "${RP7_SAVE:-}" ]; then rpf_put $RP7_SAVE; fi
  sshguard_off || true
  kp_disarm || true
}
trap cleanup EXIT

say "== S7 setup: anomaly + rules =="
nft_drop "$TAB"
b0=$(hping "$D13_IP" 5)
say "b0 baseline=$b0 (want 5/5)"
[ "$b0" = 5/5 ] || { bad "b0 $b0"; finish FAIL "b0 $b0"; exit 1; }

# LOCKOUT GUARD (S3/S5 lesson): blackholing A_IP kills the deb13->host SSH
# transport (replies are destined to blackholed A_IP) -> deadlock.  sshguard
# routes deb13-originated TCP sport 22 back out enp0s3, bypassing the
# blackhole; ICMP (the test pings) still hits it.  APPLY BEFORE bh_on.
sshguard_on || { bad "sshguard install failed"; }
# RP_FILTER KILL (proven 2026-10-09): b1/b2 blackhole A_IP (192.168.200.67).
# Strict rp_filter (deb13 default=2) drops the INBOUND request on enp0s3
# (reverse-path of blackholed src) BEFORE deb13 generates any reply -- b2
# structurally unachievable.  Relax enp0s3 (+all/default); restore after
# bh_off in cleanup.
RP7_SAVE=$(rpf_snap "$D13_IF")
rpf0 "$D13_IF"
bh_on "$A_IP" || { bad "blackhole add"; }

# ---- b1 NEG, hardening (carry-over anchor hazard, 2026-10-10 14:22) -------
# E-07 / audit_02: the 14:22 battery run FAILED b1=3/3 -- S5's b2 anchor
# (B4, TTL 60 s) was still ALIVE: S7's ping is the SAME 4-tuple
# (A->deb13 ICMP, ports 0/0), so the built-in READER (always on) found the
# surviving anchor and RESCUED all 3 pings despite blackhole + no rules.
# The 14:25 re-run passed only because the TTL had expired by then.  An
# anchor cannot be flushed by ANY ruleset operation (it lives in the module
# hash, not in nft) -- only the TTL wait resolves it.  Hence: fast first
# ping; if ANY reply arrives (carry-over window still open), wait >=65 s
# (TTL 60 s + margin) and re-ping ONCE; the re-ping MUST be 0/3.
# NEG premise (S8 pattern): no foreign table may run module expressions on
# this flow either (they would write slots and rescue the pings).
fdm=$(foreign_module_tables)
if [ -n "${fdm:-}" ]; then
  bad "b1: foreign tables with DYNSRCROUTE/DYNRT chains: $(tr '\n' ' ' <<<"$fdm")"
  finish FAIL "b1 premise broken (foreign module tables)"
  exit 1
fi
b1=$(hping "$D13_IP" 3)
say "b1 NEG(blackhole,no rule) 1st=$b1 (want 0/3)"
neg_ok=NO
case "$b1" in
  0/3)
    neg_ok=YES; ok "b1 NEG discriminates (no carry-over anchor present)" ;;
  *)
    say "b1=$b1 -- carry-over anchor window plausibly still open; waiting >=65 s (anchor TTL 60 s + margin) and re-pinging"
    say "     (incident 2026-10-10 14:22: same signature -- b1=3/3; 14:25 PASS only after TTL expiry)"
    WAIT=65
    sleep "$WAIT"
    b1=$(hping "$D13_IP" 3)
    say "b1 NEG re-ping after ${WAIT}s = $b1 (want 0/3)"
    case "$b1" in
      0/3) neg_ok=YES; ok "b1 NEG after carry-over expiry (re-ping 0/3)" ;;
      *)   bad "b1 still $b1 after ${WAIT}s carry-over wait -- not a TTL window; abort" ;;
    esac
    ;;
esac

out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s7 {
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

# ---- b2 POS: 100 concurrent single-packet pings (10 parallel) ------------
say "== b2 POS: $P concurrent new connections =="
say "arming kprobes (auxiliary): $(kp_arm | tr '\n' ' ')"

T0=$(date +%s)
# xargs appends each seq number AFTER the fixed args: sh -c '<script>' D13_IP N
# -> $0=D13_IP (the ping target), $1=N (unused).  The classic '... _ D13_IP'
# form puts N into $0 and the host into $1, so every ping went to the
# hostname "_" (2026-10-10 run-2 S7 b2 = 0/100 was exactly that script bug,
# not a module/kernel limit -- the fixed form verifies 100/100 under the
# identical blackhole+rules state, E1/E2).
ok=$(seq "$P" | xargs -P 10 -n1 sh -c \
     'ping -c 1 -W 3 "$0" >/dev/null 2>&1 && echo ok' "$D13_IP" | wc -l)
T1=$(date +%s)
CNT=$(nft_cnt inet "$TAB")
KPC=$(kp_count | tr '\n' ' ')
say "b2 POS: $ok/$P delivered in $((T1-T0))s ; DYNRT counter=$CNT (want >= $P)"
say "kprobes: $KPC"
kp_disarm || true

pos_ok=NO
if [ "${ok:-0}" -ge "$P" ] 2>/dev/null && [ -n "$CNT" ] && [ "$CNT" -ge "$P" ] 2>/dev/null; then
  pos_ok=YES; ok "b2 POS: $ok/$P concurrent connections all served via forced egress"
else
  bad "b2 ping=$ok/$P cnt=${CNT:-?}"
fi

# ---- lockdep (informational; kernel may be built without it) -------------
LK=$(r "if [ -d /sys/kernel/lockdep ] && [ \"\$(cat /sys/kernel/lockdep/lockdep_enabled 2>/dev/null)\" = 1 ]; then echo ON; else echo ABSENT_OR_OFF; fi")
say "lockdep: $LK"

DM=$(dm_bad | tr '\n' ' | ')
say "dmesg: ${DM:-<clean>}"

if [ "$neg_ok" = YES ] && [ "$pos_ok" = YES ] && [ -z "$DM" ]; then
  finish PASS "b0=5/5 b1NEG=0/3 b2POS=$ok/$P cnt=$CNT ($((T1-T0))s) lockdep=$LK"
else
  finish FAIL "b0=5/5 b1=$b1($neg_ok) b2=$ok/$P($pos_ok,cnt=${CNT:-?}) dm=${DM:-na}"
fi
