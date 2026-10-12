#!/usr/bin/env bash
# lib.sh -- shared helpers for the srcdynroute S1..S8 test scripts.
#
# The scripts run on the HOST machine; every deb13-side operation goes over
# ssh (alias "deb13" in ~/.ssh/config).  The host plays the role of endpoint
# "A" (enp4s0, 192.168.200.67; seg1 peer = deb13 enp0s3 192.168.200.12).
#
# Observability toolbox (deb13 lacks tcpdump/conntrack/perf):
#   - nft `counter` expressions            -- DYNRT match hits (primary evidence)
#   - /sys/class/net/*/statistics          -- per-iface egress/ingress deltas
#   - ftrace kprobes on module symbols     -- dynrt op invocations (auxiliary)
#   - host-side rx counters + ping loss    -- delivery verdict
#   - dmesg scan                           -- kernel error/WARN/lockdep check
#
# NOTE for every .nft body: never use a `policy ...;` statement on a plain
# (non-hook) chain -- kernel 6.12 rejects NFTA_CHAIN_POLICY on non-base chains
# (nf_tables_api.c:2871).  All test tables below use only base (hook) chains.

set -u

SSH=(ssh -o BatchMode=yes -o ConnectTimeout=15 deb13)
NFT=/usr/local/sbin/nft            # patched nftables 1.1.3 + libnftnl 1.2.9

RESULTS_LOG=${RESULTS_LOG:-/tmp/dynrt_results.log}
touch "$RESULTS_LOG" 2>/dev/null || RESULTS_LOG=/dev/null

A_IP=192.168.200.67                 # host A, enp4s0  (seg1)
D13_IP=192.168.200.12               # deb13, enp0s3  (seg1)
D13_IF=enp0s3
D13_IF2=enp0s8                     # seg2 (bridge to host brvm0 192.168.129.0/24)
HOST_IF=enp4s0
HOST_IF2=brvm0

S_NAME=${S_NAME:-S?}

say() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()  { printf '    [ok] %s\n' "$*"; }
bad() { printf '    [!!] %s\n' "$*"; }

# H CMD -- run a command on the HOST with privilege (root or sudo -n).
# Needed for link/address/route changes (S2 v6 addrs, S6 vxlan dev).
H() {
  local cmd=${1-}
  if [ "$(id -u)" = 0 ]; then bash -c "$cmd"
  else sudo -n bash -c "$cmd"; fi
}
finish() {
  local v=$1; shift || true
  echo "RESULT: ${S_NAME} ${v}: $*"
  echo "$(date -Iseconds) test=${S_NAME} verdict=${v} detail=$*" >> "$RESULTS_LOG"
}

# --------------------------------------------------------------- deb13 exec
# R_RETRY -- number of RETRIES (beyond the first attempt) for a remote call
# that hits the host<->deb13 transport wedge.  The wedge signature is a
# non-zero rc with EMPTY output (a bare command blip, or the netlink/netstack
# reply being lost while the remote work silently completes).  Observed on
# deb13 2026-10-09: an `nft -f` whose server-side commit succeeded but whose
# client reply vanished, and ssh channels stuck well past the client timeout.
# A GENUINE failure (non-zero rc WITH output) is never retried -- it is
# surfaced once so the caller can read the real error.
R_RETRY=${R_RETRY:-2}
# r CMD -- execute a single *command string* on deb13 with wedge resilience.
# The string is piped to `bash -s` on stdin so it is NEVER re-split by the
# remote login shell (ssh "sh -c x y z" would exec `sh -c x` with $0=y).
# timeout(1) bounds each attempt; a wedge (non-zero rc, empty output) is
# retried up to R_RETRY times with a small backoff, turning the blip into a
# transparent extra round-trip instead of a hard, empty failure.
r() {
  local cmd=${1-} out rc attempt total
  total=$(( R_RETRY + 1 )); rc=1; out=""
  for (( attempt=1; attempt<=total; attempt++ )); do
    out=$(printf '%s\n' "$cmd" | timeout "${SSH_TIMEOUT:-45}" "${SSH[@]}" bash -s)
    rc=$?
    if [ "$rc" -eq 0 ]; then
      # emit nothing when output is empty (no phantom newline: callers test
      # the captured string for emptiness, e.g. dm_bad + [ -z "$DM" ])
      if [ -n "$out" ]; then printf '%s\n' "$out"; fi
      return 0
    fi
    if [ -n "$out" ]; then printf '%s\n' "$out"; return "$rc"; fi
    # rc!=0 and empty output -> transport wedge: retry (bounded)
    [ "$attempt" -lt "$total" ] && sleep 1
  done
  return "$rc"
}
# rs -- remote bash script piped in on stdin (heredoc pattern:  rs <<'EOF' ... EOF).
# The heredoc is buffered first so it can be re-sent on a wedge; identical
# retry semantics (and the same no-phantom-newline rule) as r().
rs() {
  local script out rc attempt total
  script=$(cat); total=$(( R_RETRY + 1 )); rc=1; out=""
  for (( attempt=1; attempt<=total; attempt++ )); do
    out=$(printf '%s\n' "$script" | timeout "${SSH_TIMEOUT:-45}" "${SSH[@]}" bash -s)
    rc=$?
    if [ "$rc" -eq 0 ]; then
      if [ -n "$out" ]; then printf '%s\n' "$out"; fi
      return 0
    fi
    if [ -n "$out" ]; then printf '%s\n' "$out"; return "$rc"; fi
    [ "$attempt" -lt "$total" ] && sleep 1
  done
  return "$rc"
}

# t13 <iface> <counter> -- read a net sysctl counter on deb13
t13() { rs <<EOF
cat /sys/class/net/$1/statistics/$2 2>/dev/null || echo 0
EOF
}
# dh <iface> <counter> -- same, on the host
dh() { cat "/sys/class/net/$1/statistics/$2" 2>/dev/null || echo 0; }

# hping <dst> [count] -- host-side ping; prints "rcvd/sent"
hping() {
  local out sent rcvd
  out=$(ping -c "${2:-3}" -W 2 "$1" 2>&1)
  sent=$(sed -n "s/^[[:space:]]*\([0-9][0-9]*\) packets transmitted.*/\1/p" <<<"$out")
  rcvd=$(sed -n "s/.*\([0-9][0-9]*\) received.*/\1/p" <<<"$out")
  echo "${rcvd:-0}/${sent:-0}"
}
# pv6ping <dst6> [count] -- host-side ping6; prints "rcvd/sent"
pv6ping() {
  local out sent rcvd
  out=$(ping -6 -c "${2:-3}" -W 2 "$1" 2>&1)
  sent=$(sed -n "s/^[[:space:]]*\([0-9][0-9]*\) packets transmitted.*/\1/p" <<<"$out")
  rcvd=$(sed -n "s/.*\([0-9][0-9]*\) received.*/\1/p" <<<"$out")
  echo "${rcvd:-0}/${sent:-0}"
}

# hpings <ns> <dst> [count] -- ping inside a deb13 netns; prints "rcvd/sent"
hpings() {
  rs <<EOF
out=\$(ip netns exec $1 ping -c ${3:-3} -W 2 $2 2>&1) || true
p=\$(sed -n 's/.*\([0-9][0-9]*\) received.*/\1/p' <<<"\$out") || true
t=\$(sed -n 's/^[[:space:]]*\([0-9][0-9]*\) packets transmitted.*/\1/p' <<<"\$out") || true
echo "\${p:-0}/\${t:-0}"
EOF
}
# nsicmp <ns> <field> -- ICMP MIB counter of the netns (its own /proc/net/snmp),
# single awk pass, column resolved BY NAME from the header line (no hard-coded
# position).  Prints the value, or nothing on a failed lookup (caller defaults).
# Netns counters are the authoritative "B processed N requests" proof: B
# generates exactly one echo reply per request it processes at B's LOCAL output
# and the MIB is incremented there, whether or not deb13 later drops the reply
# in its FIB.  (The veth iface counters proved flaky under concurrent ssh load:
# deltas of 5, 4, 3 over three runs of the same window.)
nsicmp() {
  local ns=$1 field=$2
  rs <<EOF
ip netns exec $ns awk -v f="$field" '
  /^Icmp: InMsgs/ { for (i=2;i<=NF;i++) if (\$i==f) want=i }
  want && /^Icmp: / && \$2 ~ /^[0-9]/ { print \$want; exit }
' /proc/net/snmp 2>/dev/null
EOF
}
# nsicmpresp <ns> -- wrapper: the netns' OutEchoReps counter (replies GENERATED
# by B; one per request processed).
nsicmpresp() { nsicmp "$1" OutEchoReps; }
# nsicmpreq <ns>  -- wrapper: the netns' InEchos counter (requests RECEIVED by B).
nsicmpreq()  { nsicmp "$1" InEchos; }
# m13 <field> -- deb13 MAIN-namespace ICMP MIB counter, resolved by NAME
# (same awk pattern as nsicmp, no netns exec).  Judge-grade evidence for the
# main-NF-table tests (S5/S7):
#   InEchos     = echo requests deb13 actually processed (arrived);
#   OutEchoReps = echo replies GENERATED -- incremented only after the egress
#                 lookup succeeded (E1: blackhole/no-rule -> InEchos +N with
#                 OutEchoReps +0; blackhole+rule -> +N/+N).  This pair is
#                 what separates "request died in rp_filter" from "request
#                 arrived and the reply died in the FIB" -- the old S5
#                 0/5 of 2026-10-10 02:29 (no rpf0) was the former and
#                 passed for the wrong reason.
m13() {
  rs <<EOF
awk -v f="$1" '
  /^Icmp: InMsgs/ { for (i=2;i<=NF;i++) if (\$i==f) want=i }
  want && /^Icmp: / && \$2 ~ /^[0-9]/ { print \$want; exit }
' /proc/net/snmp 2>/dev/null
EOF
}
# m13ie / m13ore -- named shortcuts
m13ie()  { m13 InEchos; }
m13ore() { m13 OutEchoReps; }

# --------------------------------------------------------------- nft rules
# nft_apply <table> <<'DEF'
#   table inet <table> { ... }
# DEF
nft_apply() {
  local tab=$1
  local f out attempt total
  f=/tmp/dynrt_${tab}.nft
  local body
  body=$(cat)
  total=$(( R_RETRY + 1 ))
  for (( attempt=1; attempt<=total; attempt++ )); do
    # ship the body over ssh (arg form -- reliable; bounded so a wedge cannot
    # hang the caller; a short/partial write is self-healed by the next retry)
    printf '%s\n' "$body" | timeout "${SSH_TIMEOUT:-45}" "${SSH[@]}" "cat > $f" 2>/dev/null || true
    # apply, then VERIFY the table name is present in `nft list tables`
    # (family-agnostic, so it works for ip/arp/inet).  A wedged apply is
    # invisible to the exit code alone -- the name check is the real proof.
    out=$(r "$NFT -f $f >/dev/null 2>&1 && { $NFT list tables 2>/dev/null; } | grep -qwF '$tab' && echo NFT_OK || { echo NFT_ERR; $NFT -f $f; }")
    if grep -q NFT_OK <<<"$out"; then printf '%s\n' "$out"; return 0; fi
    [ "$attempt" -lt "$total" ] && sleep 1
  done
  printf '%s\n' "${out:-NFT_ERR: apply/verify failed after $total attempts (table '$tab' not present)}"
  return 1
}

# nft_drop <table> [fam] -- delete the table and VERIFY it is gone.
# The bare `delete table` returns success even when the commit never lands
# (the same wedge nft_apply guards against); the S6b NEG failure of
# 2026-10-09 was exactly this: the "rule absent" case never was, because
# a stale table kept matching.  So: delete, then assert the name is not
# in `nft list tables`; on mismatch re-delete (bounded retries).
nft_drop() {
  local tab=$1 fam=${2:-inet} out attempt total
  total=$(( R_RETRY + 1 ))
  for (( attempt=1; attempt<=total; attempt++ )); do
    r "$NFT delete table $fam $tab 2>/dev/null || true"
    # Hard guard (2026-10-10 audit fix): r() returns non-zero when the
    # command fails after all retries -- a transport wedge leaves $out EMPTY,
    # and the old bare `grep` on empty returned 0, i.e. a FALSE "table gone"
    # that every NEG baseline silently trusted (S8 L273 has always had this
    # guard; S6b's pre-NEG drop did not).  An unverified drop is an error.
    out=$(r "$NFT list tables 2>/dev/null") || {
      echo "NFT_DROP_ERR: verification failed for '$fam $tab' (transport/nft error -- table state UNKNOWN)" >&2
      return 1
    }
    if ! grep -qwF "$tab" <<<"$out"; then
      return 0
    fi
    [ "$attempt" -lt "$total" ] && sleep 1
  done
  echo "NFT_DROP_ERR: table '$fam $tab' still present after $total attempts"
  return 1
}

# nft_cnt <fam> <tab> -- read the first `packets N` counter of the given
# table (e.g. nft_cnt inet dynrt_s1).  BOTH args are required: an old
# single-arg call passed fam only, so `nft list table inet` listed a table
# that does not exist and silently returned empty -> every `CNT == 5`
# assertion failed even when the module worked.
nft_cnt() {
  local fam=${1-} tab=${2-}
  if [ -z "$fam" ] || [ -z "$tab" ]; then
    echo "nft_cnt: usage: nft_cnt <fam> <tab>" >&2
    return 1
  fi
  r "$NFT list table $fam $tab 2>/dev/null" | sed -n 's/.*packets \([0-9][0-9]*\).*/\1/p' | head -1
}

# cnt_delta <pre> <post> -- difference between two nft_cnt reads.  The
# testbed L2 domain carries ~25 pkt/s of background v4 traffic toward
# 192.168.200.67, so absolute counter values are not stable evidence; the
# delta over the ping window is.  Empty/non-numeric input counts as 0
# (visible, and cannot fake a `>= 5` pass).
cnt_delta() {
  local a=${1:-0} b=${2:-0}
  case $a in '' | *[!0-9]*) a=0 ;; esac
  case $b in '' | *[!0-9]*) b=0 ;; esac
  echo $(( b > a ? b - a : 0 ))
}

# nft_flush_dynrt -- delete every table named dynrt_* on deb13 (pre-test cleanup)
nft_flush_dynrt() {
  rs <<EOF
$NFT list tables 2>/dev/null | awk '\$3 ~ /^dynrt_/ {print \$2" "\$3}' |
while read -r fam tab; do $NFT delete table \$fam \$tab 2>/dev/null; done
echo FLUSHED
EOF
}
# foreign_dynrt <own> -- list dynrt_* tables present on deb13 OTHER than $own
# (empty output = the NEG premise "no module rule is active" holds).
# A stale dynrt_* table left by an earlier test can still run a DYNSRCROUTE
# chain on the test traffic and write the ct slot that RESCUES the flow --
# exactly the 2026-10-10 run-2 S8 b1/b4 inversion (both "no-rule" connects
# succeeded even with the blackhole up).  In a NEG phase the test must fail
# the PREMISE with a clear message instead of silently accepting a rescued
# flow and mislabeling the module's behavior.
foreign_dynrt() {
  local own=${1-}
  r "$NFT list tables 2>/dev/null | awk '\$3 ~ /^dynrt_/ && \$3 != \"${own}\" {print \$2\" \"\$3}'"
}
# foreign_module_tables -- list tables (any name) whose chains reference the
# module's expressions (DYNSRCROUTE target / DYNRT match).  The run-2
# contaminant was `table ip cx` -- NOT a dynrt_* name, invisible to both
# run_all's pre-flight (which only counts dynrt_*) and foreign_dynrt.  A
# production host would never carry a chain with a DYNSRCROUTE/DYNRT
# expression in a non-dynrt table on this dedicated testbed, so the battery
# pre-flight may delete them.
foreign_module_tables() {
  rs <<'EOF'
NFT=/usr/local/sbin/nft
$NFT list tables 2>/dev/null | awk '$2 ~ /^(ip|inet|ip6|arp)$/ && NF >= 3 {print $2" "$3}' |
while read -r fam tab; do
  case $tab in dynrt_*) continue ;; esac
  if $NFT list table "$fam" "$tab" 2>/dev/null | grep -qE 'DYNSRCROUTE|DYNRT[[:space:]]'; then
    echo "$fam $tab"
  fi
done
EOF
}

# --------------------------------------------------------------- routing
# iproute2 >= 6.x drops the legacy "ip route add <prefix> blackhole"
# ordering; type-first "ip route add blackhole <prefix>" is the only
# form that parses.
bh_on()  { r "ip route replace blackhole $1 && echo BH_ON"; }
bh_off() { r "ip route del $1 2>/dev/null || true"; }
# bh_check <ip> -- count blackhole routes for <ip>.  iproute2 1.1.3 (the
# patched build on deb13) REJECTS the legacy `ip route show blackhole`
# ("any valid prefix is expected") and `ip route get <blackholed-ip>`
# (RTNETLINK EINVAL, rc=2 -- the 2026-10-10 S5/S8 false "premise broken"
# failures: the blackhole WAS added, the verification was unreadable).
# `ip route show type blackhole` is the compatible form (verified OK).
bh_check() { r "ip route show type blackhole 2>/dev/null | grep -cF \"$1\""; }
# sshguard -- blackholing A_IP (host seg1 IP) also kills the deb13->host
# SSH transport (its replies are destined to A_IP), which deadlocks every
# subsequent remote call (the S3/S5 lockout of 2026-10-08).  A policy
# (ip rule + private table) for deb13-originated TCP from port 22 routes
# A_IP back out enp0s3 and bypasses the blackhole; ICMP (the test pings)
# keeps hitting it.  APPLY BEFORE bh_on, REMOVE AFTER bh_off.
sshguard_on() {
  r "ip rule add pref 32700 to $A_IP/32 ipproto tcp sport 22 lookup 32760 && ip route add table 32760 $A_IP/32 dev enp0s3 && echo GUARD_ON"
}
sshguard_off() {
  r "ip rule del pref 32700 2>/dev/null; ip route flush table 32760 2>/dev/null; echo GUARD_OFF"
}
# --------------------------------------------------------------- wire capture
# Host-side loopback-independent evidence: capture IF on the HOST, read the
# pcap locally.  tcpdump needs CAP_NET_RAW -> `sudo -n` (passwordless,
# verified 2026-10-10).  The capture self-bounds with `timeout $win` so NO
# pid is tracked and NO `pkill -f` pattern (which self-matches the caller's
# bash -c and kills the session -- the 2026-10-10 footgun).  `CAP_OUT` holds
# the unique per-call /tmp path (never deleted; stale files from a previous
# run are not reused because of the $$ / RANDOM suffix).
CAP_SUDO=(sudo -n)
cap_start() { # $1=iface $2=bpf-filter $3=window_seconds(default 20)
  local ifc=$1 bpf=$2 win=${3:-20}
  CAP_OUT="/tmp/cap_${RANDOM}_$$.pcap"
  CAP_WIN=$win           # deadline bookkeeping for cap_wait()
  CAP_T0=$SECONDS
  nohup "${CAP_SUDO[@]}" timeout "$win" tcpdump -ni "$ifc" -nn "$bpf" -w "$CAP_OUT" >/dev/null 2>&1 &
  disown 2>/dev/null || true
  sleep 0.8
}
cap_count() { # $1=bpf-filter  (reads CAP_OUT)
  tcpdump -r "$CAP_OUT" "$1" 2>/dev/null | wc -l
}
# cap_wait -- block until the window opened by cap_start() has fully
# expired, i.e. the capturing tcpdump (self-bounded by `timeout $win`)
# has exited and FLUSHED its -w file.  tcpdump(1) with `-w` buffers
# packets in libpcap, and a file read WHILE the writer is alive is an
# under-count -- this is the 2026-10-10 S8 b1 "SYN=0" read artifact
# (cap_count ran 1 s after the failed connect, the writer still
# alive).  Counts must only be taken after cap_wait.  Safe to call if
# no cap_start happened (caps at a 1 s grace sleep).
cap_wait() {
  local left=$(( ${CAP_T0:-0} + ${CAP_WIN:-0} - SECONDS ))
  [ "$left" -le 0 ] && left=0
  sleep "$left"
  sleep 1
}
cap_dump() { # $1=bpf-filter $2=max_lines(default 15)
  tcpdump -r "$CAP_OUT" "$1" 2>/dev/null | head -n "${2:-15}"
}
# SYN-only:  "src host X and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack = 0)"
# SYN-ACK:   "(tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack != 0)"
# --------------------------------------------------------------- rp_filter
# RP_FILTER KILL (root cause PROVEN 2026-10-09, decisive 4-case matrix on the
# S6a topology + exact S6a rule, with A's source blackholed):
#   rpf=2, no-rule -> B_in=0             (inbound request DROPPED; NEG "passes"
#                                        for the wrong reason)
#   rpf=0, no-rule -> B_in=5, B_reply=0  (true NEG: reply dies in the FIB)
#   rpf=0, +rule   -> 5/5 delivered, B_in=5, B_reply=5, DYNRT hits (true POS)
#   rpf=2, +rule   -> B_in=0             (the rule CANNOT rescue: the request
#                                        is dropped by reverse-path validation
#                                        BEFORE any reply can be generated)
# deb13 ships strict rp_filter (default.rp_filter=2, inherited by every
# interface).  While a test blackholes the PEER's source address, the
# reverse-path lookup of that source returns the blackhole and
# fib_validate_source REJECTS the inbound packet at the routing decision.
# Effective value = max(all, default, per-iface) -- so all three levels must
# be set to reliably reach 0.  Relaxing (2->0) only ever INCREASES what
# passes: it cannot turn a GREEN test RED.  Save before, restore in cleanup
# AFTER bh_off (restoring with the blackhole up would re-kill the traffic).
# rpf_snap <iface...> -- snapshot deb13-side values as "iface=val ..." words
rpf_snap() {
  r "for k in $* all default; do v=\$(cat /proc/sys/net/ipv4/conf/\$k/rp_filter 2>/dev/null); [ -n \"\$v\" ] && printf '%s=%s ' \$k \$v; done; echo SNAP"
}
# rpf0 [iface...] -- relax host-side rp_filter to 0 (all + default + ifaces)
rpf0() {
  local ifs="" i
  for i in "$@"; do ifs="$ifs net.ipv4.conf.$i.rp_filter=0"; done
  r "sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 $ifs && echo RPF0_SET"
}
# rpf0ns <ns> [iface...] -- same inside a netns (separate /proc/sys/net)
rpf0ns() {
  local ns=$1; shift
  local ifs="" i
  for i in "$@"; do ifs="$ifs net.ipv4.conf.$i.rp_filter=0"; done
  r "ip netns exec $ns sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 $ifs && echo RPF0NS_SET"
}
# rpf_put <iface name="val">... -- restore values captured by rpf_snap
rpf_put() {
  local args="" kv
  for kv in "$@"; do case "$kv" in *=*) args="$args net.ipv4.conf.${kv%%=*}.rp_filter=${kv##*=}" ;; esac; done
  if [ -n "$args" ]; then r "sysctl -qw $args >/dev/null 2>&1; echo RPF_RESTORED"; fi
}
mis()    { r "ip route replace $1 dev $2 && echo MIS_ON"; }
d6_on()  { r "ip -6 route replace blackhole $1 && echo D6_ON"; }
d6_off() { r "ip -6 route del $1 2>/dev/null || true"; }
rt_snap(){ rs <<'EOF'
ip route show
echo ---V6---
ip -6 -brief route
EOF
}

# --------------------------------------------------------------- kprobes
kp_arm() {
  rs <<'EOF'
T=/sys/kernel/tracing
[ -e $T/kprobe_events ] || { echo KP_NO_TRACEFS; exit 0; }
# clear leftovers -- *enabled* events keep the file busy
for en in $T/events/kprobes/*/enable $T/events/ret_kprobes/*/enable; do
  [ -e "$en" ] && echo 0 > "$en" 2>/dev/null
done
: > $T/kprobe_events 2>/dev/null
armed=; missed=
# entries are "symbol:shortname": SHORT name = event name, symbol = target.
# Kernel 6.12 facts (verified on deb13):
#  - kprobe_events lines read back as  p:kprobes/<name> <symbol>
#    ret-probes as                  r10:kprobes/<name> <symbol> arg1=$retval
#    (ret-probes live in the SAME kprobes/ event group);
#  - arming does NOT auto-enable an event -- it must be enabled via
#    events/kprobes/<name>/enable or it will never fire.
for s in dynrt_op_oif_skb:dynsk dynrt_op_oif_fl4:dyn4 dynrt_op_oif_fl6:dyn6 \
         dynrt_op_mac:macop dynrt_srcroute_eval:tagop dynrt_match_eval:tgmop; do
  f=${s%%:*}; n=${s##*:}
  if ! e=$(printf 'p:%s %s\n' "$n" "$f" >> $T/kprobe_events 2>&1); then
    missed="$missed $f[arm_failed: $(dmesg 2>/dev/null | tail -1)]"
  else
    echo 1 > $T/events/kprobes/$n/enable 2>/dev/null || true
    armed="$armed $n"
  fi
done
# ret-probes with return value (useful to read the forced oif of the ops;
# the print fmt is "(caller <- <symbol>) arg1=0x<retval>").
for s in dynrt_op_oif_skb:retdynsk dynrt_op_oif_fl4:retdyn4 dynrt_op_oif_fl6:retdyn6; do
  f=${s%%:*}; n=${s##*:}
  if ! e=$(printf 'r:%s %s $retval\n' "$n" "$f" >> $T/kprobe_events 2>&1); then
    missed="$missed RET-$f[arm_failed: $(dmesg 2>/dev/null | tail -1)]"
  else
    echo 1 > $T/events/kprobes/$n/enable 2>/dev/null || true
    armed="$armed $n"
  fi
done
if [ -n "$armed" ]; then
  # ~100/s background v4 traffic makes every v4 lookup a dyn4 hit --
  # the default 7KB buffer overflows in <1s
  echo 256 > $T/buffer_size_kb 2>/dev/null || true
  printf '' > $T/trace
  echo 1 > $T/tracing_on 2>/dev/null || true
  echo "KP_OK armed:$armed${missed:+  missed:$missed}"
else
  echo "KP_SYMBOL_MISS missed:$missed"
fi
EOF
}
kp_count() {
  rs <<'EOF'
T=/sys/kernel/tracing
[ -e $T/kprobe_events ] || { echo KP_INACTIVE; exit 0; }
# event line pattern: "*:kprobes/<name> <sym>"; trace line: " <name>: ..."
for n in dynsk dyn4 dyn6 macop tagop tgmop retdynsk retdyn4 retdyn6; do
  if grep -qF "kprobes/${n} " $T/kprobe_events 2>/dev/null; then
    c=$(grep -c "[[:space:]]${n}:" $T/trace 2>/dev/null) || c=0
    echo "$n=${c:-0}"
  else
    echo "$n=SKIP"
  fi
done
EOF
}
kp_retvals() { # kp_retvals <name> -- last ret-probe trace lines (retval samples)
  rs <<EOF
grep -E "[[:space:]]${1}:" /sys/kernel/tracing/trace 2>/dev/null | tail -6
EOF
}
kp_disarm() {
  rs <<'EOF'
T=/sys/kernel/tracing
[ -e $T/kprobe_events ] || exit 0
for en in $T/events/kprobes/*/enable $T/events/ret_kprobes/*/enable; do
  [ -e "$en" ] && echo 0 > "$en" 2>/dev/null
done
: > $T/kprobe_events 2>/dev/null
echo 0 > $T/tracing_on 2>/dev/null
printf '' > $T/trace 2>/dev/null
EOF
}

# --------------------------------------------------------------- dmesg
dm_bad() {
  rs <<'EOF'
dmesg 2>/dev/null | grep -nE 'WARNING:|BUG:|Kernel panic|unhandled|lock dependency|list_add corruption|Unable to handle|Oops|invalid opcode' | tail -15
EOF
}

# --------------------------------------------------------------- netns glue
# ns_up <ns> <veth_root> <veth_ns> <ip_root/24> <ip_ns/24>
ns_up() {
  local ns=$1 vroot=$2 vns=$3 iproot=$4 ipns=$5
  # gateway octet computed HOST-side: $4 etc are local variables and must
  # not be expanded inside the heredoc (set -u: unbound locally, and the
  # remote $(...) would be executed locally anyway).
  local rip o1 o2 o3 gate
  rip=${iproot%/*}
  local IFS=.; read -r o1 o2 o3 _ <<<"$rip"; unset IFS
  gate=$o1.$o2.$o3.1
  rs <<EOF
ip netns add $ns 2>/dev/null || true
ip link del $vroot 2>/dev/null || true
ip link add $vroot type veth peer name $vns || exit 1
ip link set $vns netns $ns
ip link set $vroot up
ip addr replace $iproot dev $vroot
ip netns exec $ns ip addr replace $ipns dev $vns
ip netns exec $ns ip link set $vns up
ip netns exec $ns ip link set lo up
ip netns exec $ns ip route replace default via $gate
echo NS_OK
EOF
}
ns_down() {
  rs <<EOF
ip netns del $1 2>/dev/null || true
ip link del $2 2>/dev/null || true
echo NS_DOWN
EOF
}
