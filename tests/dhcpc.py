#!/usr/bin/env python3
"""Minimal scripted DHCP client for the test harness.

Each invocation performs ONE exchange and prints the result as JSON, so the
test runner can drive it inside a network namespace with `ip netns exec`.
Because we craft chaddr ourselves, one namespace can impersonate any number of
devices — the server only ever sees the MAC inside the packet.

  dhcpc.py IFACE MAC discover   [--wait S] [--cid HEX] [--host NAME]
  dhcpc.py IFACE MAC select     IP SERVER  [--cid HEX] [--host NAME]
  dhcpc.py IFACE MAC renew      IP SERVER  [--cid HEX]      (unicast, RENEWING)
  dhcpc.py IFACE MAC rebind     IP         [--wait S] [--cid HEX] (broadcast, REBINDING)
  dhcpc.py IFACE MAC reboot     IP         [--wait S] [--cid HEX] (broadcast, INIT-REBOOT)
  dhcpc.py IFACE MAC release    IP SERVER  [--cid HEX]
  dhcpc.py IFACE MAC decline    IP SERVER  [--cid HEX]
  dhcpc.py IFACE MAC relay      GIADDR SERVER [--wait S]      (DISCOVER as if via relay)
  dhcpc.py IFACE MAC relayreq   GIADDR SERVER IP SERVER_ID    (REQUEST as if via relay)

Replies are collected for --wait seconds (default 2) so we can see *every*
server that answered, which is exactly what the failover tests need.
"""
import json
import os
import random
import socket
import struct
import sys
import time

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE, INFORM = range(1, 9)
NAMES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK",
         6: "NAK", 7: "RELEASE", 8: "INFORM"}
MAGIC = 0x63825363


def ip2b(ip):
    return socket.inet_aton(ip)


def mac2b(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def build(msg_type, mac, xid, ciaddr="0.0.0.0", giaddr="0.0.0.0",
          broadcast=True, opts=()):
    flags = 0x8000 if broadcast else 0
    hdr = struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, xid, 0, flags,
                      struct.unpack("!I", ip2b(ciaddr))[0], 0, 0,
                      struct.unpack("!I", ip2b(giaddr))[0])
    hdr += mac2b(mac) + b"\0" * 10 + b"\0" * 64 + b"\0" * 128
    hdr += struct.pack("!I", MAGIC)
    o = bytes([53, 1, msg_type])
    for code, data in opts:
        o += bytes([code, len(data)]) + data
    o += bytes([55, 4, 1, 3, 6, 51]) + b"\xff"
    pkt = hdr + o
    return pkt + b"\0" * max(0, 300 - len(pkt))


def parse(data):
    if len(data) < 240:
        return None
    (op, _ht, _hl, _hops, xid, _secs, _flags, ciaddr, yiaddr, _si,
     giaddr) = struct.unpack("!BBBBIHHIIII", data[:28])
    chaddr = data[28:34]
    if struct.unpack("!I", data[236:240])[0] != MAGIC:
        return None
    opts = {}
    i = 240
    while i < len(data):
        c = data[i]
        if c == 255:
            break
        if c == 0:
            i += 1
            continue
        ln = data[i + 1]
        opts[c] = data[i + 2:i + 2 + ln]
        i += 2 + ln
    r = {
        "op": op, "xid": xid,
        "mac": ":".join("%02X" % b for b in chaddr),
        "yiaddr": socket.inet_ntoa(struct.pack("!I", yiaddr)),
        "ciaddr": socket.inet_ntoa(struct.pack("!I", ciaddr)),
        "type": NAMES.get(opts.get(53, b"\0")[0], "?"),
    }
    if 54 in opts:
        r["server"] = socket.inet_ntoa(opts[54])
    if 51 in opts:
        r["lease"] = struct.unpack("!I", opts[51])[0]
    return r


def exchange(iface, pkt, xid, dest, wait, port=68, first_only=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
    s.bind(("0.0.0.0", port))
    s.sendto(pkt, (dest, 67))
    replies = []
    end = time.time() + wait
    while True:
        left = end - time.time()
        if left <= 0:
            break
        s.settimeout(left)
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            break
        r = parse(data)
        if r and r["op"] == 2 and r["xid"] == xid:
            replies.append(r)
            if first_only:
                break
    s.close()
    return replies


def main():
    a = sys.argv[1:]
    iface, mac, cmd = a[0], a[1].upper(), a[2]
    rest = a[3:]
    wait = 2.0
    cid = None
    host = None
    pos = []
    i = 0
    while i < len(rest):
        if rest[i] == "--wait":
            wait = float(rest[i + 1]); i += 2
        elif rest[i] == "--cid":
            cid = bytes.fromhex(rest[i + 1]); i += 2
        elif rest[i] == "--host":
            host = rest[i + 1].encode(); i += 2
        else:
            pos.append(rest[i]); i += 1

    xid = random.getrandbits(32)
    base = []
    if cid:
        base.append((61, cid))
    if host:
        base.append((12, host))

    if cmd == "discover":
        pkt = build(DISCOVER, mac, xid, opts=base)
        out = exchange(iface, pkt, xid, "255.255.255.255", wait)
    elif cmd == "select":
        ip, srv = pos
        pkt = build(REQUEST, mac, xid, opts=base + [(50, ip2b(ip)), (54, ip2b(srv))])
        out = exchange(iface, pkt, xid, "255.255.255.255", wait)
    elif cmd == "renew":
        ip, srv = pos
        pkt = build(REQUEST, mac, xid, ciaddr=ip, broadcast=False, opts=base)
        out = exchange(iface, pkt, xid, srv, wait)
    elif cmd == "rebind":
        (ip,) = pos
        pkt = build(REQUEST, mac, xid, ciaddr=ip, broadcast=False, opts=base)
        out = exchange(iface, pkt, xid, "255.255.255.255", wait)
    elif cmd == "reboot":
        (ip,) = pos
        pkt = build(REQUEST, mac, xid, opts=base + [(50, ip2b(ip))])
        out = exchange(iface, pkt, xid, "255.255.255.255", wait)
    elif cmd == "release":
        ip, srv = pos
        pkt = build(RELEASE, mac, xid, ciaddr=ip, broadcast=False,
                    opts=base + [(54, ip2b(srv))])
        out = exchange(iface, pkt, xid, srv, 0.3)
    elif cmd == "decline":
        ip, srv = pos
        pkt = build(DECLINE, mac, xid, opts=base + [(50, ip2b(ip)), (54, ip2b(srv))])
        out = exchange(iface, pkt, xid, "255.255.255.255", 0.3)
    elif cmd == "relay":
        gi, srv = pos
        pkt = build(DISCOVER, mac, xid, giaddr=gi, broadcast=False, opts=base)
        out = exchange(iface, pkt, xid, srv, wait, port=67)
    elif cmd == "relayreq":
        gi, srv, ip, sid = pos
        pkt = build(REQUEST, mac, xid, giaddr=gi, broadcast=False,
                    opts=base + [(50, ip2b(ip)), (54, ip2b(sid))])
        out = exchange(iface, pkt, xid, srv, wait, port=67)
    else:
        print(json.dumps({"error": "unknown command " + cmd}))
        return 2
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
