#!/usr/bin/env bash
# S8 -- live rule update: the forced egress survives the nftables rule.
#
# The DYNSRCROUTE target on the SYN writes the state that outlives the
# ruleset. Two carriers exist and the FIB reader (dynrt_op_oif_fl4) tries
# the ct-slot FIRST (ct extension, read with nf_conntrack_find_get at the
# SYN-ACK FIB lookup; only exists if conntrack hooks are registered on
# the bench), then the B4 ANCHOR fallback keyed on the exact 4-tuple
# (works also without conntrack -- 2026-10-10 probe on deb13: lazy
# nf_ct_netns_get registration, /proc/net/nf_conntrack = 0 entries).
# What this test must prove, independent of the carrier:
#   (a) a flow marked by the rule gets the forced egress at SYN-ACK time;
#   (b) the established flow survives the whole-table drop (the forced
#       path was pinned when the SYN-ACK FIB lookup ran; data packets
#       then ride the cached dst and never re-enter the hook);
#   (c) a fresh connection after the drop has neither a slot nor an
#       anchor (exact-4-tuple mismatch, fresh ephemeral port) and dies
#       in the blackhole again -- only the target writes state.
#
# History: pre-B4 (per-pair anchor) b1/b4 were "rescued" by scope
# (any 4-tuple of the pair matched); B4 (2026-10-10) made the key
# exact-4-tuple and b1/b4 are clean discriminators (S8 GREEN 16:14).
#
# Topology: deb13 listens on 0.0.0.0:9977 (python echo); host A
# 192.168.200.67 connects and echoes raw lines.  Anomaly (active in
# b1..b5): `ip route replace 192.168.200.67 blackhole` on deb13 -- so
# EVERY reply needs the forced egress to be delivered.
#
#   b0  sanity: no blackhole, no rules -> connect+echo OK
#   b1  blackhole only, no rules       -> new connect times out
#   b2  blackhole + rules              -> connect OK, 3 echo lines
#   b3  (socket held ESTABLISHED) all  -> probe echo on the SAME socket
#       rules dropped                   still delivered (slot persists,
#                                       built-in force hooks read it)
#   b4  socket closed; new connect     -> times out again (fresh ct has
#       (rule still absent)             no slot: only-the-target-writes)
#   b5  rules re-applied; new connect  -> OK; counter >= 2 (SYN-ACK +
#                                       data reply)
#
# PASS = b0 OK && b1 timeout && b2+b3 OK && b4 timeout && b5 OK cnt>=2
#        + dmesg clean.

S_NAME=S8
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"
TAB=dynrt_s8
PORT=9977
DST="$D13_IP:9977"
RES=/tmp/s8res ; SIG=/tmp/s8sig
CLIENT=/tmp/s8client.py
LISTNER=/tmp/echo9977.py

cleanup() {
  nft_drop "$TAB" || true
  bh_off "$A_IP" 2>/dev/null || true
  # rp_filter restore AFTER bh_off (S3 lesson)
  if [ -n "${RP8_SAVE:-}" ]; then rpf_put $RP8_SAVE; fi
  sshguard_off || true
  r "pkill -f 'echo9977[.]py' 2>/dev/null || true"
  rm -f "$RES" "$SIG" "$CLIENT"
}
trap cleanup EXIT

say "== S8 setup: echo listener on deb13:$PORT =="
"${SSH[@]}" "cat > $LISTNER" <<'PYEOF'
#!/usr/bin/env python3
import socket, threading, time
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 9977))
srv.listen(16)
srv.settimeout(2)
def h(c):
    try:
        c.settimeout(90)
        while True:
            d = c.recv(4096)
            if not d:
                break
            c.sendall(d)
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass
t0 = time.time()
while time.time() - t0 < 240:
    try:
        c, _ = srv.accept()
    except socket.timeout:
        continue
    threading.Thread(target=h, args=(c,), daemon=True).start()
print("listener done")
PYEOF
# pkill -f 'echo9977[.]py' -- bracket pattern: the regex matches the
# literal "echo9977.py" (the listener's cmdline) but NOT the caller shell's
# own cmdline ("echo9977[.]py"), which a bare `pkill -f echo9977.py` would
# self-match and kill (the 2026-10-10 SSH_RC=255 footgun).
r "pkill -f 'echo9977[.]py' 2>/dev/null || true; sleep 0.3"
r "nohup python3 $LISTNER >/tmp/echo9977.log 2>&1 & echo LST_PID \$!"
sleep 1

cat > "$CLIENT" <<'PYEOF'
#!/usr/bin/env python3
"""S8 client: one-shot echo handshake, or hold-the-socket across a rule drop."""
import os, socket, sys, time

HOST, PORT = "192.168.200.12", 9977
CT = 6.0

def handshake(conn, line):
    d = line.encode() + b"\n"
    conn.sendall(d)
    conn.settimeout(CT)
    buf = b""
    while len(buf) < len(d):
        p = conn.recv(len(d) - len(buf))
        if not p:
            return False
        buf += p
    return buf == d

def conn():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CT)
    s.connect((HOST, PORT))
    return s

def oneshot():
    try:
        s = conn()
        good = handshake(s, "s8-once")
        s.close()
        return 0 if good else 1
    except OSError:
        return 1

def hold(res_file, sig_file):
    def rec(tag):
        with open(res_file, "a") as f:
            f.write(tag + "\n")
    try:
        s = conn()
        good = all(handshake(s, f"s8-hold-{i}") for i in (1, 2, 3))
        if not good:
            rec("PH1_FAIL")
            s.close()
            return 1
        rec("PH1_OK")
        # wait (max 120s) for the orchestrator to drop the ruleset
        dl = time.time() + 120
        while time.time() < dl and not os.path.exists(sig_file):
            time.sleep(0.5)
        if not os.path.exists(sig_file):
            rec("PH1_SIG_TIMEOUT")
            s.close()
            return 1
        # probe on the SAME socket after the drop
        if handshake(s, "s8-probe-1"):
            rec("PH2_OK")
        else:
            rec("PH2_FAIL")
        s.close()
        return 0
    except OSError as e:
        rec(f"PH1_FAIL({e.__class__.__name__})")
        return 1

mode = sys.argv[1]
if mode == "oneshot":
    sys.exit(oneshot())
if mode == "hold":
    sys.exit(hold(sys.argv[2], sys.argv[3]))
print("usage: client.py oneshot|hold RES SIG", file=sys.stderr)
sys.exit(2)
PYEOF

wait_res() {   # wait_res <tag> <seconds> -> 0 if the tag appears in $RES
  local tag=$1 t=$2 i=0
  while [ $i -lt $t ]; do
    grep -q "$tag" "$RES" 2>/dev/null && return 0
    sleep 0.5; i=$((i+1))
  done
  return 1
}
# NEG premise (2026-10-10 run-2 post-mortem): b1/b4 are judged by TIMEOUT, so
# they only prove "no rule -> no slot -> reply dies in the FIB" if BOTH
#   (a) the blackhole is ACTUALLY effective (a dead-UNREACHABLE blackhole
#       would make the connect succeed and the NEG mislabeled), and
#   (b) no foreign table is still running a DYNSRCROUTE chain on this flow
#       and silently writing the ct slot (the run-2 b1/b4 inversion: a stale
#       non-dynrt table with a module-expression chain -- invisible to the
#       old dynrt_*-only pre-flight -- rescued both "no-rule" connects).
neg_premise() {   # neg_premise <phase>
  local bh fd nr
  bh=$(bh_check "$A_IP")
  if ! [ "${bh:-0}" -ge 1 ] 2>/dev/null; then
    bad "$1: blackhole NOT effective (ip route show type blackhole: $(r "ip route show type blackhole 2>&1 | head -1"))"
    return 1
  fi
  fd=$(foreign_dynrt "$TAB")
  if [ -n "${fd:-}" ]; then
    bad "$1: foreign dynrt_* tables active: $(tr '\n' ' ' <<<"$fd")"
    return 1
  fi
  # (b2) ANY table (e.g. the run-2 `table ip cx` contaminant) whose chains
  # reference the module expressions would still write ct slots on this flow.
  if [ -n "$(foreign_module_tables)" ]; then
    bad "$1: foreign tables with DYNSRCROUTE/DYNRT chains: $(tr '\n' ' ' <<<"$(foreign_module_tables)")"
    return 1
  fi
  # (b3) at most ONE rule at pref 32700 (our sport-22 guard).  A second rule
  # at the same pref (broad guard leftover) rescues ALL replies to A_IP --
  # the leading root cause of run-2 S8 b1/b4 (S7 b1 icmp NEG stayed 0/3
  # because that leftover was tcp-only; S8 b1/b4 tcp connects "succeeded").
  nr=$(r "ip rule list pref 32700 2>/dev/null | grep -c '^32700:'")
  if ! [ "${nr:-0}" -le 1 ] 2>/dev/null; then
    bad "$1: ${nr} rules at pref 32700 (want <=1): $(r "ip rule list pref 32700 2>/dev/null" | tr '\n' ' ')"
    return 1
  fi
  return 0
}

say "== b0 sanity: no blackhole, no rules =="
nft_drop "$TAB"
rm -f "$RES" "$SIG"
if python3 "$CLIENT" oneshot; then ok "b0 connect+echo OK"; else
  bad "b0 failed (listener? path?)"; finish FAIL "b0 sanity failed"; exit 1
fi

say "== b1 NEG: blackhole, no rules =="
# LOCKOUT GUARD (S3/S5 lesson): blackholing A_IP kills the deb13->host SSH
# transport (replies destined to blackholed A_IP) -> deadlock.  sshguard
# routes deb13-originated TCP sport 22 back out enp0s3; the test's own TCP
# (sport 9977) does NOT enter the guard table and stays subject to the test.
# APPLY BEFORE bh_on.
sshguard_on || { bad "guard install failed -- aborting (blackhole would self-lock ssh)"; finish FAIL "sshguard install failed -- aborted before bh_on"; exit 1; }
# RP_FILTER KILL (proven 2026-10-09): b1..b5 blackhole A_IP (192.168.200.67).
# Strict rp_filter (deb13 default=2) would DROP the INBOUND SYNs on enp0s3
# (reverse-path of the blackholed src) before deb13 could answer -- b2/b5
# structurally unachievable.  Relax enp0s3 (+all/default); restored after
# bh_off in cleanup.  NOTE: the NEG cases stay true NEG (SYN-ACK dies in
# the FIB, not in src validation) and the POS cases become reachable.
RP8_SAVE=$(rpf_snap "$D13_IF")
rpf0 "$D13_IF"
bh_on "$A_IP" || { bad "blackhole add failed"; }
neg_premise b1 || { bad "b1 NEG premise broken -- aborting"; finish FAIL "b1 premise broken (b0=OK)"; exit 1; }
sleep 0.5
# WIRE GATE (2026-10-10): a raw connect-timeout alone once hid a live rescue
# (run-2 b1 "connected" under a VERIFIED blackhole; two later manual
# reproductions were clean NEG -- the anomaly was unrecoverable state
# forensics).  The gate captures the host->deb13 wire from the HOST: a
# true NEG = SYN(s) left the wire and got NO answer.  If the connect ever
# succeeds again under this verified premise, the SYN-ACK capture (L2 src
# MAC + src IP) is itself the root-cause evidence of the rescue path.
cap_start "$HOST_IF" "host $D13_IP and tcp port $PORT" 25
if python3 "$CLIENT" oneshot; then
  cap_wait           # let the 25 s capture window expire -> complete -w file
  EVID=$(cap_dump "(tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack != 0)" 12 | tr '\n' ' | ')
  bad "b1 CONNECTED despite verified blackhole -- rescued by: ${EVID:-<no SYN-ACK in capture>}"
  b1=FAIL
else
  cap_wait           # 2026-10-10: count only after the window expired (tcpdump
                     # -w read-while-writer-alive = under-count, the b1 "SYN=0"
                     # artifact of the S8 forensics)
  SYN=$(cap_count "src host $A_IP and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack = 0)")
  SYNACK=$(cap_count "src host $D13_IP and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack != 0)")
  if [ "${SYN:-0}" -ge 1 ] 2>/dev/null && [ "${SYNACK:-0}" -eq 0 ] 2>/dev/null; then
    ok "b1 wire-verified NEG: $SYN SYN(s) unanswered, SYN-ACK=0"
    b1=OK
  else
    bad "b1 connect failed but wire incomplete: SYN=$SYN SYNACK=$SYNACK -- $(cap_dump 'tcp[tcpflags] != 0' 8 | tr '\n' ' | ')"
    b1=FAIL
  fi
fi

say "== b2/b3 POS: rule + hold socket over the drop =="
rm -f "$RES" "$SIG"
out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s8 {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# port-restricted to the test flow: slots must not be written
		# for unrelated ct (management SSH on this iface, port 22) -- report "ambient-pass"
		iifname "enp0s3" ip daddr 192.168.200.12 tcp dport 9977 DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 192.168.200.67 DYNRT counter
	}
}
DEF
)
grep -q NFT_OK <<<"$out" || { bad "nft apply: $(tr '\n' ' ' <<<"$out")"; finish FAIL "nft apply"; exit 1; }
ok "rules applied"

python3 "$CLIENT" hold "$RES" "$SIG" >/tmp/s8hold.out 2>&1 &
CPID=$!
if ! wait_res PH1_OK 30; then
  bad "b2 PH1_FAILED or timeout: $(cat "$RES" 2>/dev/null | tr '\n' ' ')"
  kill "$CPID" 2>/dev/null || true; wait "$CPID" 2>/dev/null || true
  b2=FAIL
  finish FAIL "b1=$b1 b2=FAIL: $(cat "$RES" 2>/dev/null | tr '\n' ' ')"
fi
ok "b2 connect + 3 echo lines OK"
b2=OK

nft_drop "$TAB" || { bad "b3: table drop UNVERIFIED -- b3/b4 semantics invalid"; finish FAIL "b1=$b1 b2=OK b3=DROP-UNVERIFIED"; exit 1; }
ok "b3: entire dynrt table dropped while socket is ESTABLISHED"
sleep 1
echo probe > "$SIG"
wait "$CPID" 2>/dev/null
if grep -q PH2_OK "$RES"; then
  ok "b3 probe on the held socket still delivered (slot survives the drop)"
  b3=OK
else
  bad "b3: $(cat "$RES" | tr '\n' ' ')"
  b3=FAIL
fi

say "== b4 NEG: no rule, socket gone, fresh connection =="
rm -f "$SIG"
neg_premise b4 || { bad "b4 NEG premise broken -- aborting (b1=$b1 b2=$b2 b3=$b3 collected)"; finish FAIL "b4 premise broken (b1=$b1 b2=$b2 b3=$b3)"; exit 1; }
# WIRE GATE (same discipline as b1; see 2026-10-10 notes above).
cap_start "$HOST_IF" "host $D13_IP and tcp port $PORT" 25
if python3 "$CLIENT" oneshot; then
  cap_wait           # let the 25 s capture window expire -> complete -w file
  EVID=$(cap_dump "(tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack != 0)" 12 | tr '\n' ' | ')
  bad "b4 CONNECTED (should have blackholed -- fresh ct, no slot) -- rescued by: ${EVID:-<no SYN-ACK in capture>}"
  b4=FAIL
else
  cap_wait           # 2026-10-10: count only after the window expired (see b1)
  SYN=$(cap_count "src host $A_IP and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack = 0)")
  SYNACK=$(cap_count "src host $D13_IP and (tcp[tcpflags] & tcp-syn != 0) and (tcp[tcpflags] & tcp-ack != 0)")
  if [ "${SYN:-0}" -ge 1 ] 2>/dev/null && [ "${SYNACK:-0}" -eq 0 ] 2>/dev/null; then
    ok "b4 wire-verified NEG: $SYN SYN(s) unanswered, SYN-ACK=0 (fresh ct, no slot)"
    b4=OK
  else
    bad "b4 connect failed but wire incomplete: SYN=$SYN SYNACK=$SYNACK -- $(cap_dump 'tcp[tcpflags] != 0' 8 | tr '\n' ' | ')"
    b4=FAIL
  fi
fi

say "== b5 POS: rule re-applied, fresh connection =="
rm -f "$RES"
out=$(nft_apply "$TAB" <<'DEF'
table inet dynrt_s8 {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# port-restricted to the test flow: slots must not be written
		# for unrelated ct (management SSH on this iface, port 22) -- report "ambient-pass"
		iifname "enp0s3" ip daddr 192.168.200.12 tcp dport 9977 DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 192.168.200.67 DYNRT counter
	}
}
DEF
)
grep -q NFT_OK <<<"$out" || { bad "nft re-apply: $(tr '\n' ' ' <<<"$out")"; }
if python3 "$CLIENT" oneshot; then b5=OK; ok "b5 connect+echo OK after re-apply"; else
  bad "b5 failed"; b5=FAIL
fi
CNS=$(nft_cnt inet "$TAB")
say "b5 counter=$CNS (want >= 2: SYN-ACK + data reply)"
[ "${CNS:-0}" -ge 2 ] 2>/dev/null && ok "b5 counter in range" || bad "b5 cnt=${CNS:-?}"

DM=$(dm_bad | tr '\n' ' | ')
say "dmesg: ${DM:-<clean>}"

if [ "$b1" = OK ] && [ "$b2" = OK ] && [ "$b3" = OK ] && [ "$b4" = OK ] \
   && [ "$b5" = OK ] && [ "${CNS:-0}" -ge 2 ] 2>/dev/null && [ -z "$DM" ]; then
  finish PASS "b0=OK b1=timeout b2=$b2 b3=held-delivered b4=timeout b5=OK cnt=$CNS"
else
  finish FAIL "b0=OK b1=$b1 b2=${b2:-?} b3=$b3 b4=$b4 b5=$b5 cnt=${CNS:-?} dm=${DM:-na}"
fi
