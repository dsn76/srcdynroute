#!/usr/bin/env python3
# m6.py -- A/B matrix injector (cur_report_01.md sec.6, audit_02 E-06).
#
# usage: python3 m6.py <iface> <net> <mode> [window_s]
#   iface : TAP device name (must not exist beforehand; the kernel drops it
#           when this process exits -- non-persist netdev)
#   net   : /24 base without host part, e.g. 172.31.10  -> MINE=.1, PEER=.67
#   mode  : plain   ~ t6in.py   (R1 baseline: blocking os.read)
#           select  ~ t6in2.py  (R4: select-poll + per-frame wire log)
#           minimal ~ probe3.py (V3/V4: least plumbing, same protocol core)
#   window: response window in seconds (default 8, same as round-1 cells)
#
# Protocol core (identical across modes -- the DISCRIMINATOR is the plumbing
# variant, the net column is the network variable):
#   * TAP as MINE=.1; PEER=.67 does not exist on the L2 segment (fake A).
#   * 5 ICMP echo-requests are INJECTED with eth-src = FAKEA
#     (dst = broadcast, so the TAP delivers them to the stack as self-frames
#     -- unicast-to-FAKEA would be PACKET_OTHERHOST and never seen).
#   * The kernel replies to PEER and must L2-resolve it; when it asks
#     "who has .67" the injector answers with src = WRONG (poison).
#   * Verdict per received reply by eth-DST:
#       edst == FAKEA -> ok   (reply kept the injected requester MAC)
#       edst == WRONG -> bad  (kernel used the poisoned neighbour entry)
#       other         -> other
#   * NEG baseline (S6 script, rule-less): ok=0, bad>=4, arp>=2.
#
# The stats line format matches the S6 runner's sed expectation:
#   INJ ok=N bad=N other=N arp=N req=N
import os, socket, struct, time, fcntl, sys, select
import subprocess, threading

IFACE   = sys.argv[1]
NET     = sys.argv[2].rstrip("/")
MODE    = sys.argv[3]
WINDOW  = float(sys.argv[4]) if len(sys.argv) > 4 else 8.0

def ip4(s):
    return socket.inet_aton(s)

MINE    = NET + ".1"
PEER    = NET + ".67"
MINE4   = ip4(MINE)
PEER4   = ip4(PEER)
FAKEA   = bytes.fromhex("02aabbccdd06")
WRONG   = bytes.fromhex("02aabbccdd99")
BRC     = bytes([0xff] * 6)

WIRELOG = "/tmp/t6wire_%s.log" % IFACE   # select mode (t6in2) only

fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
bio = IFACE.encode().ljust(16, b"\0") + struct.pack("<H", 0x1002)  # TAP|NO_PI
fcntl.ioctl(fd, 0x400454CA, bio)                                   # TUNSETIFF
os.system("ip link set up dev %s" % IFACE)
os.system("ip addr replace %s/24 dev %s" % (MINE, IFACE))
os.system("ip neigh flush dev %s" % IFACE)
time.sleep(0.2)
kmac = bytes.fromhex(open("/sys/class/net/%s/address" % IFACE).read()
                     .strip().replace(":", ""))

wlog = None
if MODE == "select":
    wlog = open(WIRELOG, "wb")

def csum16(b):
    if len(b) & 1:
        b += b"\x00"
    s = 0
    for i in range(0, len(b), 2):
        s += (b[i] << 8) | b[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def w(frame):
    # minimal: single attempt; plain/select: retry until fully written
    off = 0
    attempts = 1 if MODE == "minimal" else 60
    for _ in range(attempts):
        try:
            off += os.write(fd, frame[off:])
            if off >= len(frame):
                if wlog is not None:
                    wlog.write(b"t=%.3f TX %s\n" % (time.time(),
                             frame.hex().encode()))
                    wlog.flush()
                return
        except OSError:
            if MODE == "minimal":
                return
            time.sleep(0.02)

def echo_req(seq):
    data = b"S6TAP-" + str(seq).encode()
    icmp = struct.pack("!BBHHH", 8, 0, 0, seq & 0xffff, seq & 0xffff) + data
    ck = csum16(icmp)
    icmp = icmp[:2] + struct.pack("!H", ck) + icmp[4:]
    tot = 20 + len(icmp)
    iph = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 0, 0, 64, 1, 0, PEER4, MINE4)
    iph = iph[:10] + struct.pack("!H", csum16(iph)) + iph[12:]
    return BRC + FAKEA + b"\x08\x00" + iph + icmp

def arp_ans():
    eth = kmac + WRONG + b"\x08\x06"
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + WRONG + PEER4 + kmac + MINE4
    return eth + body

def rd():
    try:
        if MODE == "select":
            r, _, _ = select.select([fd], [], [], 0.05)
            if not r:
                return b""
            return os.read(fd, 65536)
        try:
            return os.read(fd, 65536)
        except OSError:
            return b""
    except OSError:
        return b""

def split(buf):
    # minimal: one expected frame per read, take the head, no robustity scan
    if MODE == "minimal":
        if len(buf) >= 14:
            return [buf[:len(buf)]]
        return []
    fr = []
    i = 0
    n = len(buf)
    while i + 14 <= n:
        et = buf[i + 12:i + 14]
        sz = None
        if et == b"\x08\x06":
            sz = 42
        elif et == b"\x08\x00":
            if i + 18 <= n:
                ihl = (buf[i + 14] & 0x0f) * 4
                if ihl >= 20:
                    tot = int.from_bytes(buf[i + 16:i + 18], "big")
                    if tot >= ihl and 14 + tot <= n - i:
                        sz = 14 + tot
        if sz is None:
            break
        fr.append(buf[i:i + sz])
        i += sz
    return fr

st = dict(ok=0, bad=0, other=0, arp=0, req=0)

# neighbour timeline (one self-contained snapshot loop per cell -- the S6
# runner's /tmp/t6neigh.log equivalent, written under a per-iface name):
NEIGHLOG = "/tmp/t6neigh_%s.log" % IFACE
_stop = threading.Event()
def _neigh_poll():
    with open(NEIGHLOG, "w") as f:
        i = 0
        while not _stop.is_set():
            i += 1
            try:
                out = subprocess.run(["ip", "neigh", "show", "dev", IFACE],
                                    capture_output=True, text=True,
                                    timeout=2).stdout.strip()
            except Exception as e:
                out = "<poll-err:%s>" % e
            f.write("t=%.3f seq=%d %s\n" %
                    (time.time(), i, out.replace("\n", " | ")))
            f.flush()
            time.sleep(0.3)
_nt = threading.Thread(target=_neigh_poll, daemon=True)
_nt.start()

for i in range(5):
    w(echo_req(i + 1))
    if MODE == "minimal":
        time.sleep(0.15)
    else:
        time.sleep(0.2)

tl = time.time() + WINDOW
while time.time() < tl and (st["ok"] + st["bad"]) < 5:
    buf = rd()
    if wlog is not None and buf:
        wlog.write(b"t=%.3f RX %s\n" % (time.time(), buf.hex().encode()))
        wlog.flush()
    for fr in split(buf):
        edst, et = fr[0:6], fr[12:14]
        if et == b"\x08\x06":
            body = fr[14:]
            if len(body) >= 28:
                op = int.from_bytes(body[6:8], "big")
                tpa = body[24:28]
                if op == 1 and tpa == PEER4:
                    w(arp_ans())
                    st["arp"] += 1
        elif et == b"\x08\x00":
            ihl = (fr[14] & 0x0f) * 4
            if ihl >= 20 and 14 + ihl + 2 <= len(fr):
                ipt = fr[14 + ihl]
                ipsrc = fr[26:30]
                ipdst = fr[30:34]
                if ipt == 8 and ipdst == MINE4:
                    st["req"] += 1
                elif ipt == 0 and ipsrc == MINE4 and ipdst == PEER4:
                    if edst == FAKEA:
                        st["ok"] += 1
                    elif edst == WRONG:
                        st["bad"] += 1
                    else:
                        st["other"] += 1
    if not buf and MODE != "select":
        time.sleep(0.05)

_stop.set()
_nt.join(timeout=1)
try:
    with open(NEIGHLOG) as f:
        lines = [l.rstrip() for l in f if l.strip()]
    last = lines[-1] if lines else "<empty>"
except Exception:
    last = "<unreadable>"

os.close(fd)
with open("/tmp/t6stat_%s.txt" % IFACE, "w") as f:
    f.write("ok=%d bad=%d other=%d arp=%d req=%d\n" %
            (st["ok"], st["bad"], st["other"], st["arp"], st["req"]))
print("INJ ok=%d bad=%d other=%d arp=%d req=%d (%s %s %s)" %
      (st["ok"], st["bad"], st["other"], st["arp"], st["req"],
       MODE, IFACE, MINE))
print("NEIGH-LAST %s" % last)
if wlog is not None:
    try:
        print("WIRE %s: %d lines" % (WIRELOG,
              sum(1 for _ in open(WIRELOG, "rb"))))
    except Exception:
        pass
