#!/usr/bin/env bash
# S6 -- device-type matrix: L2 override + forced egress on different L2/L3
#      device families on deb13.
#
#   S6a  veth      -- control: synthetic L2 peer in a netns (172.30.10.x),
#                     blackhole anomaly, same shape as S1 on a veth device.
#   S6b  TAP       -- "wrong MAC" anomaly: the fake peer (172.31.10.67,
#                     MAC FAKEA) poisons the kernel's ARP for itself with a
#                     WRONG MAC.  Normal path: kernel emits its L3-correct
#                     echo replies with dst MAC WRONG (undetectable by L3,
#                     lost in transit)  => "badmac" frames counted by the
#                     injector.  With the rules, patch 0005's L2 override
#                     must force dst MAC back to FAKEA (stored from the
#                     request)  => "ok" frames.  NEG: ok==0,bad>=4 ;
#                     POS: ok>=4,bad<=1,DYNRT counter delta>=5.  (Sharper
#                     than NOARP:
#                     L3 is fully functional in both phases; L2 is the
#                     sole variable.)
#   S6c  VXLAN     -- overlay over the 192.168.200.0/24 underlay: host vxha
#                     <-> deb13 vxlan1 (id 42), overlay 192.168.77.x.
#                     Blackhole A's overlay address.  If the host kernel
#                     refuses `ip link add type vxlan` (seccomp EPERM),
#                     the sub-test is recorded ENV-CONSTRAINED, not FAIL.
#   S6d  DUMMY     -- SKIPPED-BY-DESIGN: ARPHRD_NONE devices have no L2
#                     neighbor and no reachable peer through them; an
#                     ifindex-only forced egress would emit into a void
#                     device and nothing can be discriminated.
#   S6e  BOND      -- SKIPPED-BY-CONFIG / SKIPPED-ENV: CONFIG_NET_BONDING
#                     state recorded from the running 6.12.111 build.
#
# PASS = S6a PASS && S6b PASS && S6c in {PASS, ENV-CONSTRAINED} && dmesg
#        clean; S6d/S6e carried as SKIPPED (informational, not failure).

S_NAME=S6
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

A6IP=172.30.10.67        # S6a peer in netns nsA6
A6GW=172.30.10.1         # deb13 root IP on a6r
TIP=172.31.10.67         # S6b fake peer IP (on t6a)
TGW=172.31.10.1          # deb13 root IP on t6a
XD_IP=192.168.77.1       # S6c deb13 overlay IP (vxlan1)
XH_IP=192.168.77.67      # S6c host overlay IP (vxha)

NSA6=nsA6 ; A6R=a6r ; A6V=a6v
TAB_A=dynrt_s6a ; TAB_B=dynrt_s6b ; TAB_C=dynrt_s6c

cleanup() {
  nft_drop "$TAB_A" ip || true
  nft_drop "$TAB_B" ip || true
  nft_drop "$TAB_C" ip || true
  r "ip link del t6a 2>/dev/null || true"
  r "ip link del vxlan1 2>/dev/null || true"
  H "ip link del vxha 2>/dev/null" || true
  bh_off "$A6IP" 2>/dev/null || true
  bh_off "$TIP" 2>/dev/null || true
  bh_off "$XH_IP" 2>/dev/null || true
  # rp_filter restore AFTER all bh_off (S3 lesson); empty guard: S6c may be
  # ENV-CONSTRAINED and never snap
  if [ -n "${RP6A_SAVE:-}" ]; then rpf_put $RP6A_SAVE; fi
  if [ -n "${RP6C_SAVE:-}" ]; then rpf_put $RP6C_SAVE; fi
  ns_down "$NSA6" "$A6R" || true
  kp_disarm || true
}
trap cleanup EXIT

V_A=FAIL ; V_B=FAIL ; V_C=FAIL ; V_D=SKIPPED-BY-DESIGN
BDCFG=$(r "zcat /proc/config.gz 2>/dev/null | grep -m1 'CONFIG_NET_BONDING'")
if [ -z "$BDCFG" ]; then
  V_E="SKIPPED-BY-CONFIG (no CONFIG_NET_BONDING in running 6.12.111 build)"
else
  V_E="SKIPPED-ENV (bond module present, no second NIC to bond)"
fi
say "S6d DUMMY: $V_D"
say "S6e BOND : $V_E"

# ===================================================================== S6a
say "================== S6a: veth (control L2) ==================="
ns_up "$NSA6" "$A6R" "$A6V" "172.30.10.1/24" "172.30.10.67/24" || { bad "ns_up nsA6"; finish FAIL "S6a ns_up failed"; exit 1; }
# rp_filter window (RP_FILTER KILL, proven 2026-10-09 by the decisive 4-case
# matrix on exactly this topology): b1/b2 blackhole A6IP (172.30.10.67);
# strict rp_filter (deb13 default=2) drops the INBOUND request on a6r
# (reverse-path -> blackhole) BEFORE B can generate any reply -- b2 was
# structurally unachievable.  rpf=0 + rule => 5/5 (the true POS).  Relax
# host + nsA6 sides; restored in cleanup after bh_off.
RP6A_SAVE=$(rpf_snap "$A6R")
rpf0 "$A6R"
rpf0ns "$NSA6" "$A6V"
nft_drop "$TAB_A" ip
b0a=$(hpings "$NSA6" "$A6GW" 5)
bh_on "$A6IP" || bad "blackhole add (S6a)"
b1a=$(hpings "$NSA6" "$A6GW" 3)
say "S6a b0 baseline=$b0a ; b1 NEG(blackhole,no rule)=$b1a (want 5/5, 0/3)"

out=$(nft_apply "$TAB_A" <<'DEF'
table ip dynrt_s6a {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow (defense in depth: the TAP
		# already carries no ambient traffic) -- report "ambient-pass"
		iifname "a6r" ip daddr 172.30.10.1 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 172.30.10.67 DYNRT counter
	}
}
DEF
)
grep -q NFT_OK <<<"$out" || bad "nft S6a: $(tr '\n' ' ' <<<"$out")"
t_a=$(t13 "$A6R" tx_packets)
CNA0=$(nft_cnt ip "$TAB_A")
b2a=$(hpings "$NSA6" "$A6GW" 5)
t_b=$(t13 "$A6R" tx_packets)
d_a=$((t_b - t_a))
CNA=$(nft_cnt ip "$TAB_A")
dCNTA=$(cnt_delta "$CNA0" "$CNA")
say "S6a b2 POS=$b2a d($A6R tx)=$d_a counter=$CNA0->$CNA (dCNT=$dCNTA; want 5/5, >=5, >=5)"
if [ "$b0a" = 5/5 ] && [ "$b1a" = 0/3 ] && [ "$b2a" = 5/5 ] && [ -n "$CNA" ] && [ "${dCNTA:-0}" -ge 5 ] 2>/dev/null; then
  V_A=PASS; ok "S6a PASS (counter advanced by $dCNTA)"
else
  bad "S6a FAIL b0=$b0a b1=$b1a b2=$b2a d=$d_a cnt=$CNA0->$CNA dCNT=$dCNTA"
fi

# ===================================================================== S6b
say "================== S6b: TAP wrong-MAC anomaly ==================="
# Creator-injector model (verified on deb13, 2026-10-09): a second TUNSETIFF
# attach to a live non-MQ TAP returns EBUSY and this iproute2 will not add a
# persistent TAP, so the Python injector below is the SOLE owner/creator of
# t6a: open /dev/net/tun + TUNSETIFF (0x400454CA, flags TAP|NO_PI=0x1002),
# then `ip link set up` + `ip addr replace` in-process, inject/respond/
# verify, exit.  The netdev is non-persist and dies with the owner fd;
# each run (NEG/POS) starts on a fresh TAP with its own random MAC.
# Shell `ip link del` stays best-effort only (never the owner).
r "ip link del t6a 2>/dev/null || true"
say "rp_filter all=$(r "cat /proc/sys/net/ipv4/conf/all/rp_filter" 2>/dev/null) t6a=$(r "cat /proc/sys/net/ipv4/conf/t6a/rp_filter" 2>/dev/null || echo absent)"

"${SSH[@]}" "cat > /tmp/t6in.py" <<'PYEOF'
#!/usr/bin/env python3
# Creator-injector: this process is the SOLE owner/creator of t6a.
# /dev/net/tun + TUNSETIFF (0x400454CA; flags TAP|NO_PI = 0x1002) binds the
# netdev to this fd; configuration runs in-process (a write to a DOWN netdev
# is EIO, so `ip link set up` first).  The non-persist netdev vanishes when
# this process exits.  kmac is the hex of /sys/class/net/t6a/address with
# the colons stripped (a per-TAP devnode /dev/t6a does not exist on this
# iproute2/tun tree; the L2 frames carry the kernel's own MAC as dst).
import os, struct, time, fcntl, select
IFACE = "t6a"
MINE  = b"\xac\x1f\x0a\x01"          # 172.31.10.1 (kernel side)
PEER  = b"\xac\x1f\x0a\x43"          # 172.31.10.67 (fake A)
FAKEA = bytes.fromhex("02aabbccdd06")
WRONG = bytes.fromhex("02aabbccdd99")
BRC   = bytes([0xff] * 6)            # dst NULL-MAC frames are dispatched
                                     # PACKET_OTHERHOST and never seen here:
                                     # use broadcast for our own injects
fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
bio = IFACE.encode().ljust(16, b"\0") + struct.pack("<H", 0x1002)
fcntl.ioctl(fd, 0x400454CA, bio)
os.system("ip link set up dev %s" % IFACE)
os.system("ip addr replace 172.31.10.1/24 dev %s" % IFACE)
os.system("ip neigh flush dev %s" % IFACE)
time.sleep(0.2)
kmac = bytes.fromhex(open("/sys/class/net/%s/address" % IFACE).read().strip().replace(":", ""))

def csum16(b):
    if len(b) & 1: b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def w(frame, retries=60):
    off = 0
    for _ in range(retries):
        try:
            off += os.write(fd, frame[off:])
            if off >= len(frame):
                return
        except OSError:
            time.sleep(0.02)

def echo_req(seq):
    data = b"S6TAP-" + str(seq).encode()
    icmp = struct.pack("!BBHHH", 8, 0, 0, seq & 0xffff, seq & 0xffff) + data
    ck = csum16(icmp)
    icmp = icmp[:2] + struct.pack("!H", ck) + icmp[4:]
    tot = 20 + len(icmp)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 0, 0, 64, 1, 0, PEER, MINE)
    iph = iph[:10] + b"\x00\x00" + iph[12:]
    iph = iph[:10] + struct.pack("!H", csum16(iph)) + iph[12:]
    return BRC + FAKEA + b"\x08\x00" + iph + icmp

def arp_ans():
    eth = kmac + WRONG + b"\x08\x06"
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + WRONG + PEER + kmac + MINE
    return eth + body

def rd():
    try:
        return os.read(fd, 65536)
    except OSError:
        return b""

def split(buf):
    fr = []; i = 0; n = len(buf)
    while i + 14 <= n:
        et = buf[i+12:i+14]
        sz = None
        if et == b"\x08\x06":
            sz = 42
        elif et == b"\x08\x00":
            if i + 18 <= n:
                ihl = (buf[i+14] & 0x0f) * 4
                if ihl >= 20:
                    tot = int.from_bytes(buf[i+16:i+18], "big")
                    if tot >= ihl and 14 + tot <= n - i:
                        sz = 14 + tot
        if sz is None:
            break
        fr.append(buf[i:i+sz]); i += sz
    return fr

st = dict(ok=0, bad=0, other=0, arp=0, req=0)
for i in range(5):
    w(echo_req(i + 1))
    time.sleep(0.2)

tl = time.time() + 8
while time.time() < tl and (st["ok"] + st["bad"]) < 5:
    buf = rd()
    for fr in split(buf):
        edst, esrc, et = fr[0:6], fr[6:12], fr[12:14]
        if et == b"\x08\x06":
            body = fr[14:]
            if len(body) >= 28:
                op = int.from_bytes(body[6:8], "big")
                # tpa is body[24:28] (20-byte fixed fields + sha + spa = 24);
                # the kernel asks "who has PEER?", so tpa == PEER (== 6)
                tpa = body[24:28]
                if op == 1 and tpa == PEER:
                    w(arp_ans()); st["arp"] += 1
        elif et == b"\x08\x00":
            ihl = (fr[14] & 0x0f) * 4
            if ihl >= 20 and 14 + ihl + 2 <= len(fr):
                # IP header starts at 14; version/IHL at 14, saddr at
                # 14+12 = 26, daddr at 14+16 = 30 (not 14+16/14+20!)
                ipt = fr[14+ihl]
                ipsrc = fr[26:30]; ipdst = fr[30:34]
                if ipt == 8 and ipdst == MINE:
                    st["req"] += 1
                elif ipt == 0 and ipsrc == MINE and ipdst == PEER:
                    if edst == FAKEA:   st["ok"] += 1
                    elif edst == WRONG: st["bad"] += 1
                    else:               st["other"] += 1
    if not buf:
        time.sleep(0.05)

with open("/tmp/t6stat.txt", "w") as f:
    f.write("ok=%d bad=%d other=%d arp=%d req=%d\n" %
            (st["ok"], st["bad"], st["other"], st["arp"], st["req"]))
print("INJ ok=%d bad=%d other=%d arp=%d req=%d" %
      (st["ok"], st["bad"], st["other"], st["arp"], st["req"]))
PYEOF

run_inj() {
  # Snapshot `ip neigh` on t6a every 0.5s while the injector runs: if the
  # gate FAILS, the timeline (lladdr + NUD state at each t) is the arbiter
  # of "poison never learned" vs "learned but replies left to another MAC"
  # -- the run-2 inversion left no such record and had to be re-derived.
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
# s6b_precond -- assert (and enforce) a clean baseline for the tap phases.
# Root cause of the NEG inversion (ok=5 bad=0) -- CONFIRMED 2026-10-10 by
# the discriminating A/B (doc/results/s6b_discrim_2026-10-10_run1.log):
#   The DYNSRCROUTE target (dynrt_srcroute_eval, srcdynroute.c) writes a
#   MODULE-GLOBAL reverse-flow ANCHOR (exact tuple, ICMP ports 0/0, peer
#   L2 = FAKEA), TTL 60s (DYNRT_ANCHOR_TTL_MS), refreshed on every writer
#   fire.  The reader (dynrt_op_mac) serves that anchor for the exact
#   reply tuple at xmit time -- independent of neigh state -- and the
#   0005 patch applies it OVER neigh->ha.  The anchor list is invisible
#   and unflushable from userspace; dropping the nft table does NOT clear
#   it.  => a NEG phase that runs within 60s of ANY prior POS (same or
#   earlier battery run) gets FAKEA forced despite "no rules": the
#   ok=5/bad=0 signature of run-3 (07:30), R5 (09:23) and R6-replay#2
#   (17:37).  A clean NEG (anchor expired or never written) shows the
#   kernel taking the poisoned WRONG: ok=0 bad>=5.
#   Discriminating A/B (single variable = anchor freshness): P1 clean ->
#   ok0/bad5; P2 POS (writes the anchor) -> ok5; P3 NEG within TTL ->
#   ok5/bad0 (INVERTED, 172.31.10.67 stuck INCOMPLETE, so the kernel
#   itself never produced FAKEA); P4 NEG after TTL -> ok0/bad5.  The
#   discrimination proves the 60s shelf-life of re-anchored data, but
#   run9 (NEG at 19:26, ~19 min after the last known fire, still
#   INVERTED) is NOT explained by the surviving anchor alone: the
#   VERDICT-A close (S6b_neg_residual_check.sh, 2026-10-10 19:44:11,
#   run1 log: ok=0 bad=5 CLEAN) proves that with NO live writer and a
#   long-expired anchor the identical NEG is CLEAN -- hence run9's
#   window REQUIRED a live DYNSRCROUTE rule: a RESIDUAL writer table
#   left by an earlier session (run9's own cleanup later removed it:
#   0 DYNSRCROUTE post-run, so it cannot be named directly).  The
#   battery never asserted writer absence before NEG; the discrim
#   script did (verified drop + foreign table scan) -- that gap is
#   closed by check (4) below.
# Checks below: (1)-(3) kill the other confounder classes (phantom
# /dev/net/tun responder, stale FAKEA neigh entry, surviving t6a);
# (4) asserts + remediates writer absence (the run9 root-cause class);
# (5) enforces the anchor TTL expiry (60s shelf-life of re-anchored data).
s6b_precond() {
  local t
  r "pkill -f 't6in[.]py' 2>/dev/null || true"
  sleep 0.3
  r "ip link del t6a 2>/dev/null || true"
  sleep 0.2
  # (1) no process may hold a /dev/net/tun fd (a stray earlier injector
  # answers the kernel's who-has probes for PEER; whichever answer the
  # kernel accepts wins the learn -- run-2 inversion)
  t=$(rs <<'PRE'
for p in /proc/[0-9]*; do
  if ls -l "$p/fd" 2>/dev/null | grep -q '/dev/net/tun'; then
    printf 'pid=%s cmd=%s\n' "${p##*/}" "$(tr -d '\0' < "$p/cmdline" 2>/dev/null | head -c 48)"
  fi
done
PRE
)
  if [ -n "${t:-}" ]; then
    bad "S6b precond: process holding /dev/net/tun: $(tr '\n' ' ' <<<"$t")"
    return 1
  fi
  # (2) no stale 172.31.10.67 neigh entry in the main netns
  if [ -n "$(r "ip -4 neigh show to 172.31.10.67 2>/dev/null")" ]; then
    bad "S6b precond: stale neigh 172.31.10.67: $(r "ip -4 neigh show to 172.31.10.67" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  # (3) t6a must be gone (the injector recreates it fresh per phase)
  if [ -n "$(r "ip link show t6a 2>/dev/null")" ]; then
    bad "S6b precond: t6a still present after del: $(r "ip link show t6a" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  # (4) NO LIVE DYNSRCROUTE WRITER ANYWHERE (run9 root-cause class, see
  # header): a residual DYNSRCROUTE table left by an earlier session
  # fires the writer on the NEG-phase requests (iifname t6a, daddr
  # 172.31.10.1, ICMP echo-request) and re-anchors FAKEA -- this is what
  # inverted run9 (and the 2026-10-10 run-2 S8 b1/b4 class documented in
  # lib.sh foreign_dynrt).  The module exposes no userspace inspect/
  # flush for the anchor (grep-verified: no debugfs/proc/nfnetlink
  # surface) and the anchor is invisible -- the only userspace
  # lever is the rule that writes it.  Remediate: drop every dynrt_*
  # table and every foreign table carrying DYNSRCROUTE/DYNRT, record
  # each name, then RE-ASSERT and fail open if anything survived.
  local fdrop ftab
  nft_flush_dynrt   # dynrt_* drop loop (FLUSHED marker on deb13)
  for fdrop in $(foreign_module_tables); do
    say "S6b precond: dropping residual writer table: $fdrop"
    nft_drop "${fdrop#* }" "${fdrop%% *}" || bad "S6b precond: drop of '$fdrop' UNVERIFIED"
  done
  if [ -n "$(r "$NFT list tables 2>/dev/null | awk '\$3 ~ /^dynrt_/ {print \$2\" \"\$3}'")" ] || [ -n "$(foreign_module_tables)" ]; then
    bad "S6b precond: residual DYNSRCROUTE writer table survived the drop -- NEG baseline unenforceable"
    return 1
  fi
  # (5) MODULE ANCHOR TTL guard (root cause, see header): a prior S6b POS
  # left a {172.31.10.1 -> 172.31.10.67, ICMP 0/0, hw=FAKEA} anchor alive
  # for up to 60s after the last writer fire.  Only the TTL can clear it
  # (re-asserted by (4) above that no writer can re-arm it).  If the POS
  # marker is younger than 65s, wait out the remainder (bounded at 65s;
  # zero overhead when idle).
  local last now age need
  last=$(r "cat /tmp/dynrt_s6b_pos_epoch 2>/dev/null" | tr -cd '0-9')
  if [ -n "${last:-}" ]; then
    now=$(r "date +%s" | tr -cd '0-9')
    age=$(( now - last ))
    if [ "$age" -lt 65 ] 2>/dev/null; then
      need=$(( 65 - age ))
      say "S6b precond: prior POS anchor may be live (age ${age}s < 65s) -- waiting ${need}s for DYNRT_ANCHOR_TTL_MS expiry"
      sleep "$need"
    fi
  fi
  return 0
}

# Hard guard (audit B-02.4 fix, mirrors S8 L273): an unverified pre-NEG
# drop invalidates the baseline -- fail open, never fake NEG.  Combined
# with the nft_drop transport guard in lib.sh, a surviving writer rule
# (the run-3/07:30/R5 ok=5-bad=0 signature) can no longer pass as NEG.
nft_drop "$TAB_B" ip || { bad "S6b NEG: TAB_B drop UNVERIFIED (transport/nft error) -- NEG baseline broken"; n_1=NO; S6B_PRE=NO; }
S6B_PRE=${S6B_PRE:-YES}
s6b_precond || { bad "S6b: clean baseline not enforceable -- see precond output"; S6B_PRE=NO; n_1=NO; }
r "ip neigh flush dev t6a 2>/dev/null || true"
# Arm BEFORE the NEG window (fix 2026-10-11: the battery's other tests arm
# here too -- without this kp_count below read a DISARMED/stale trace and
# tracing_on could be 0, silently dropping the phase).  kp_arm clears the
# buffer and sets tracing_on=1, so any dynrt_srcroute_eval (tagop) hit in
# the NEG window is proof of a residual writer -- the NEG premise check.
KP_NEG_ARM=$(kp_arm)
case "$KP_NEG_ARM" in *KP_OK*) : ;; *) say "S6b NEG kprobe arm: $KP_NEG_ARM" ;; esac
T1=$(run_inj)
say "S6b NEG injector: $T1  (want ok=0, bad>=4)"
KPN1=$(kp_count | tr '\n' ' ')
TGON1=$(sed -n 's/.* tagop=\([0-9][0-9]*\).*/\1/p' <<<"$KPN1"); TGON1=${TGON1:-0}
TGN1=$(sed -n  's/.* tgmop=\([0-9][0-9]*\).*/\1/p' <<<"$KPN1"); TGN1=${TGN1:-0}
say "S6b NEG kprobes: $KPN1 (want tagop=0 tgmop=0 -- no writer/match may fire without a rule)"
ok1=$(sed -n 's/.*ok=\([0-9-]*\).*/\1/p' <<<"$T1"); bd1=$(sed -n 's/.*bad=\([0-9-]*\).*/\1/p' <<<"$T1")
n_1=NO
if [ "${ok1:-?}" = 0 ] && [ -n "${bd1:-}" ] && [ "$bd1" -ge 4 ] 2>/dev/null \
   && [ "$TGON1" -eq 0 ] 2>/dev/null && [ "$TGN1" -eq 0 ] 2>/dev/null; then
  n_1=YES; ok "NEG: all 5 replies left with the poisoned WRONG dst MAC; expressions silent (tagop=$TGON1 tgmop=$TGN1)"
else
  bad "NEG: ok=$ok1 bad=$bd1 tagop=$TGON1 tgmop=$TGN1"
  say "S6b NEG neigh timeline (poison=02:aa:bb:cc:dd:99, FAKEA=02:aa:bb:cc:dd:06):"
  r "sed -n '1,30p' /tmp/t6neigh.log 2>/dev/null" | sed 's/^/    /'
fi

if [ "${S6B_PRE:-NO}" = YES ]; then
nft_apply "$TAB_B" <<'DEF'
table ip dynrt_s6b {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow (defense in depth: the TAP
		# already carries no ambient traffic) -- report "ambient-pass"
		iifname "t6a" ip daddr 172.31.10.1 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 172.31.10.67 DYNRT counter
	}
}
DEF
r "ip neigh flush dev t6a 2>/dev/null || true"
sleep 0.3
CNB0=$(nft_cnt ip "$TAB_B")
T2=$(run_inj)
# Anchor-TTL bookkeeping (check (4) in s6b_precond): the writer fired on
# the requests above, so the FAKEA anchor for this flow is LIVE from here.
# The next NEG (this or a later battery run) must honour the 60s TTL.
r "date +%s > /tmp/dynrt_s6b_pos_epoch 2>/dev/null || true"
CNB=$(nft_cnt ip "$TAB_B")
dCNB=$(cnt_delta "$CNB0" "$CNB")
KP=$(kp_count | tr '\n' ' ')
say "S6b POS injector: $T2  counter=$CNB0->$CNB (dCNT=$dCNB; want ok>=4, bad<=1, dCNT>=5)"
say "S6b POS kprobes: $KP"
ok2=$(sed -n 's/.*ok=\([0-9-]*\).*/\1/p' <<<"$T2"); bd2=$(sed -n 's/.*bad=\([0-9-]*\).*/\1/p' <<<"$T2")
p_1=NO
if [ -n "${ok2:-}" ] && [ "$ok2" -ge 4 ] 2>/dev/null && [ "${bd2:-9}" -le 1 ] 2>/dev/null && [ -n "$CNB" ] && [ "${dCNB:-0}" -ge 5 ] 2>/dev/null; then
  p_1=YES; ok "POS: L2 override forced dst MAC back to FAKEA despite poisoned neigh (DYNRT counter advanced by $dCNB)"
else
  bad "POS: ok=$ok2 bad=$bd2 cnt=$CNB0->$CNB dCNT=$dCNB"
  say "S6b POS neigh timeline (module should force FAKEA=02:aa:bb:cc:dd:06 dst):"
  r "sed -n '1,30p' /tmp/t6neigh.log 2>/dev/null" | sed 's/^/    /'
fi
else
  bad "S6b POS: SKIPPED -- NEG baseline broken (evidence would be invalid: the same contamination that inverts NEG 'rescues' POS for the wrong reason)"
  p_1=NO
  nft_drop "$TAB_B" ip || true
fi
if [ "$n_1" = YES ] && [ "$p_1" = YES ]; then V_B=PASS; ok "S6b PASS"; else bad "S6b FAIL"; fi
kp_disarm || true

# ===================================================================== S6c
say "================== S6c: VXLAN overlay (192.168.77.0/24) ==================="
# Two USERSPACE requirements on `ip link add type vxlan` (iproute2 policy,
# not kernel constraints) -- both fixed 2026-10-10 with local evidence:
#   (a) dstport: iproute2 requires an explicit destination port (default
#       4789 exists upstream; the 2026-10-08 "ENV-CONSTRAINED (host kernel
#       link-add refused)" recorded for S6c was that misattribution,
#       audit B-05).
#   (b) remote: a remote-less vxlan is receive-only from an egress point
#       of view (no peer VTEP -> no encapsulation).  Local probe
#       (2026-10-10, host, same netns as the battery): `local $A_IP`
#       without `remote` gave TX=0/neigh FAILED on ping to 192.168.77.1
#       (b0=0/5 signature of the 2026-10-09 run); adding
#       `remote $D13_IP` gave 5/5 delivered.  Classical point-to-point
#       vxlan needs both sides to name the peer VTEP.
HOUT=$(H "ip link del vxha 2>/dev/null; ip link add vxha type vxlan id 42 dev $HOST_IF local $A_IP remote $D13_IP dstport 4789 2>&1; ip addr add 192.168.77.67/24 dev vxha 2>&1; ip link set vxha up 2>&1" || true)
if [ -n "$HOUT" ]; then
  say "S6c host vxlan creation failed: $HOUT"
  V_C=ENV-CONSTRAINED
  bad "S6c recorded ENV-CONSTRAINED (host vxlan link-add failed: $HOUT)"
else
  DK=$(r "ip link del vxlan1 2>/dev/null || true
ip link add vxlan1 type vxlan id 42 remote $A_IP dev $D13_IF dstport 4789 2>&1 && \
ip addr replace 192.168.77.1/24 dev vxlan1 && ip link set vxlan1 up && echo VX_OK || echo VX_FAIL")
  if ! grep -q VX_OK <<<"$DK"; then
    say "S6c deb13 vxlan creation failed: $DK"; V_C=ENV-CONSTRAINED; bad "S6c ENV-CONSTRAINED"
  else
    # rp_filter window (as S6a): b1/b2 blackhole XH_IP (192.168.77.67);
    # strict rp_filter would drop the INBOUND overlay request on vxlan1
    # (underlay enp0s3 leg) before deb13 can reply.  Relax overlay+underlay.
    RP6C_SAVE=$(rpf_snap "$D13_IF" vxlan1)
    rpf0 "$D13_IF" vxlan1
    b0c=$(hping "$XD_IP" 5)
    say "S6c b0 baseline host->overlay=$b0c (want 5/5)"
    bh_on "$XH_IP" ; sleep 0.5
    # premise guard (added 2026-10-10, run9 anomaly): run9's b1=3/3
    # despite BH_ON -- never verified after.  A delivered reply with the
    # blackhole missing is premise-break, not module behavior.  `ip route
    # show type blackhole` is the compatible form (lib.sh bh_check).
    bhc=$(bh_check "$XH_IP"); say "S6c b1 blackhole present: ${bhc:-0} route(s) for $XH_IP"
    if [ "${bhc:-0}" -lt 1 ] 2>/dev/null; then
      bad "S6c b1: blackhole for $XH_IP NOT present after bh_on (bh_check=${bhc:-0}) -- premise broken"
    fi
    b1c=$(hping "$XD_IP" 3)
    say "S6c b1 NEG(blackhole A-overlay,no rule)=$b1c (want 0/3)"

    out=$(nft_apply "$TAB_C" <<'DEF'
table ip dynrt_s6c {
	chain t {
		type filter hook prerouting priority filter; policy accept;
		# proto-restricted to the test flow (defense in depth: the vxlan
		# device already carries no ambient traffic) -- report "ambient-pass"
		iifname "vxlan1" ip daddr 192.168.77.1 icmp type echo-request DYNSRCROUTE
	}
	chain m {
		type filter hook output priority filter; policy accept;
		ip daddr 192.168.77.67 DYNRT counter
	}
}
DEF
    )
    grep -q NFT_OK <<<"$out" || bad "nft S6c: $(tr '\n' ' ' <<<"$out")"
    CNC0=$(nft_cnt ip "$TAB_C")
    b2c=$(hping "$XD_IP" 5)
    CNC=$(nft_cnt ip "$TAB_C")
    dCNCC=$(cnt_delta "$CNC0" "$CNC")
    say "S6c b2 POS=$b2c counter=$CNC0->$CNC (dCNT=$dCNCC; want 5/5, >=5)"
    if [ "$b0c" = 5/5 ] && [ "$b1c" = 0/3 ] && [ "$b2c" = 5/5 ] && [ -n "$CNC" ] && [ "${dCNCC:-0}" -ge 5 ] 2>/dev/null; then
      V_C=PASS; ok "S6c PASS (counter advanced by $dCNCC)"
    else
      bad "S6c FAIL b0=$b0c b1=$b1c b2=$b2c cnt=$CNC0->$CNC dCNT=$dCNCC"; V_C=FAIL
    fi
  fi
fi

# =====================================================================
DM=$(dm_bad | tr '\n' ' | ')
say "dmesg: ${DM:-<clean>}"

V_A=${V_A:-FAIL}; V_B=${V_B:-FAIL}; V_C=${V_C:-FAIL}
if [ "$V_A" = PASS ] && [ "$V_B" = PASS ] && \
   { [ "$V_C" = PASS ] || [ "$V_C" = ENV-CONSTRAINED ]; } && [ -z "$DM" ]; then
  finish PASS "S6 veth=PASS tap=PASS vxlan=$V_C dummy=$V_D bond=$V_E"
else
  finish FAIL "S6 veth=$V_A tap=$V_B vxlan=$V_C dummy=$V_D bond=$V_E dm=${DM:-na}"
fi
