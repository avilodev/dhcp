#!/usr/bin/env python3
"""End-to-end tests for the DHCP server: single-server mode and clusters.

    python3 tests/run_tests.py [path/to/dhcp_server] [test-name ...]

Runs every scenario in its own throwaway virtual network (see harness.py).
No sudo needed.  Takes a few minutes: failover tests wait out real timeouts.
"""
import os
import signal
import socket
import struct
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Topology, ensure_namespace, ip_of, POOL  # noqa: E402

# ---- the server's hashing, ported, so tests can check who owns what --------
M64 = (1 << 64) - 1


def fnv1a64(s):
    h = 0xcbf29ce484222325
    for c in s.encode():
        h ^= c
        h = (h * 0x100000001b3) & M64
    return h


def mix64(z):
    z = (z + 0x9e3779b97f4a7c15) & M64
    z = ((z ^ (z >> 30)) * 0xbf58476d1ce4e5b9) & M64
    z = ((z ^ (z >> 27)) * 0x94d049bb133111eb) & M64
    return z ^ (z >> 31)


def score(key, node_id):
    return mix64(fnv1a64(node_id) ^ mix64(key))


def ip_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def slice_owner(ip, nodes):
    return max(nodes, key=lambda n: (score(ip_int(ip), n), n))


def bucket_owner(device_id, serving):
    b = mix64(fnv1a64(device_id)) >> 56
    return max(serving, key=lambda n: (score(b | (1 << 32), n), n))


def pool_ips(pool=POOL):
    a, b = ip_int(pool[0]), ip_int(pool[1])
    return [socket.inet_ntoa(struct.pack("!I", v)) for v in range(a, b + 1)]


def mac(i, prefix=0x10):
    return "02:00:00:%02X:%02X:%02X" % (prefix, (i >> 8) & 0xFF, i & 0xFF)


SERVER_OF = {ip_of(n): n.upper() for n in ("a", "b", "c")}

# ---- tiny test framework ----------------------------------------------------
TESTS = []


def test(fn):
    TESTS.append(fn)
    return fn


def wait_for(cond, timeout, step=0.25, what="condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(step)
    raise AssertionError(f"timed out after {timeout}s waiting for {what}")


def status(t, name):
    rc, out = t.ctl(name, "status")
    assert rc == 0, f"ctl status on {name} failed: {out}"
    return out


def self_state(t, name):
    for line in status(t, name).splitlines():
        if line.startswith("self "):
            return dict(kv.split("=", 1) for kv in line.split()[3:] if "=" in kv)
    return {}


def cluster(t, names, controller=None, extra="", start=True, pool=POOL):
    members = [("node", n) for n in names]
    if controller:
        members.append(("controller", controller))
    for n in names + ([controller] if controller else []):
        t.write_conf(n, role="controller" if n == controller else "node", pool=pool)
        t.write_cluster(n, members, extra, pool=pool)
    if start:
        for n in names + ([controller] if controller else []):
            t.start(n)
        converged(t, names)


def converged(t, names, timeout=15):
    """Every node NORMAL and their views agree: buckets add up to exactly 256"""
    def ok():
        st = [self_state(t, n) for n in names]
        return all(s.get("state") == "NORMAL" for s in st) and \
            sum(int(s["buckets"].split("/")[0]) for s in st) == 256
    wait_for(ok, timeout, what=f"{names} converged")


def no_duplicate_ips(members):
    by_ip = {}
    for dev, m in members.items():
        assert m["ip"] not in by_ip, f"{m['ip']} held by {by_ip[m['ip']]} and {dev}"
        by_ip[m["ip"]] = dev


# ---- single server ------------------------------------------------------------

@test
def single_basic(t):
    t.write_conf("a", cluster=False)
    with open(t.node_dir("a") + "/static_list.txt", "w") as f:
        f.write("printer 02:00:00:00:00:99 10.77.0.150\n")
    t.start("a")
    ip, srv, ack = t.lease(mac(1))
    assert ip and srv == ip_of("a") and ack["lease"] == 600, ack
    t.client_addr(ip)
    assert [r["type"] for r in t.client(mac(1), "renew", ip, srv, wait=1)] == ["ACK"]
    assert [r["type"] for r in t.client(mac(1), "rebind", ip, wait=1)] == ["ACK"]
    assert [r["type"] for r in t.client(mac(1), "reboot", ip, wait=1)] == ["ACK"]
    assert [r["type"] for r in t.client(mac(1), "reboot", "10.77.0.99", wait=1)] == ["NAK"]
    assert t.lease("02:00:00:00:00:99")[0] == "10.77.0.150"
    # static survives an ACK + expiry window (bug fixed: ACK used to set an expiry)
    ip2 = t.lease(mac(2))[0]
    t.client(mac(2), "decline", ip2, srv)
    ip3 = t.lease(mac(2))[0]
    assert ip3 and ip3 != ip2, (ip2, ip3)
    t.client(mac(1), "release", ip, srv)
    time.sleep(1.5)
    m = t.members("a")
    assert mac(1) not in m and m[mac(2)]["ip"] == ip3 and m["02:00:00:00:00:99"]["expires"] == "static", m
    j = t.read("a", "leases.journal")
    assert " DECLINE " in j and " RELEASE " in j, j


@test
def single_restart_and_migration(t):
    t.write_conf("a", cluster=False)
    with open(t.node_dir("a") + "/members.txt", "w") as f:
        f.write("01AABBCCDDEEFF,AA:BB:CC:DD:EE:FF,10.77.0.60,laptop\n"
                "02:00:00:00:00:07,02:00:00:00:00:07,10.77.0.61,Unknown\n")
    t.start("a")
    time.sleep(1.5)
    m = t.members("a")
    assert m["01AABBCCDDEEFF"]["ip"] == "10.77.0.60" and m["01AABBCCDDEEFF"]["host"] == "laptop", m
    assert m["02:00:00:00:00:07"]["ip"] == "10.77.0.61", m
    # a migrated device keeps its address
    assert t.lease("02:00:00:00:00:07")[0] == "10.77.0.61"
    ip = t.lease(mac(5))[0]
    t.kill("a")                                   # no clean shutdown
    # simulate a crash mid-append: a partial last line
    with open(t.node_dir("a") + "/leases.journal", "a") as f:
        f.write("pi 99 1790000000 LEASE 02:00:00:00:")
    t.start("a")
    time.sleep(1.5)
    m = t.members("a")
    assert m[mac(5)]["ip"] == ip and m["01AABBCCDDEEFF"]["ip"] == "10.77.0.60", m
    assert "partial last line" in t.log("a")
    ip_b = t.lease(mac(6))[0]
    j = t.read("a", "leases.journal")
    assert j.endswith("\n") and "02:00:00:\n" not in j and ip_b in j, j[-300:]
    # compaction keeps exactly one line per live lease, plus the high-water mark
    t.lease(mac(6))                            # a renewal: now two lines for mac(6)
    t.signal("a", signal.SIGUSR2)
    time.sleep(1.5)
    j2 = t.read("a", "leases.journal")
    records = [l for l in j2.splitlines() if l and not l.startswith("#")]
    assert len(records) == 4 and "# hw " in j2, j2
    t.stop("a")
    t.start("a")
    time.sleep(1.5)
    assert t.members("a") == m | {mac(6): t.members("a")[mac(6)]}


@test
def conflict_check(t):
    """A device squatting on an address (hand-configured, firewalled against
    ping) is caught by the ARP probe before we offer that address."""
    t.write_conf("a", cluster=False)
    t.start("a")
    # Learn which address this device will be offered, then give it back
    dev = mac(1)
    ip1 = t.lease(dev)[0]
    t.client(dev, "release", ip1, ip_of("a"))
    time.sleep(0.3)
    # Something else now uses ip1 — and ignores ping, like a Windows PC
    t.client_addr(ip1)
    from harness import nsexec
    nsexec("cl", "sysctl", "-qw", "net.ipv4.icmp_echo_ignore_all=1", check=False)
    offers = [r for r in t.client(dev, "discover", wait=1.5) if r["type"] == "OFFER"]
    assert len(offers) == 1 and offers[0]["yiaddr"] != ip1, (ip1, offers)
    assert f"Address {ip1} is already in use" in t.log("a"), "conflict not logged"
    # ...and it stays held back: later new devices don't get it either
    for i in range(2, 8):
        got = t.lease(mac(i))[0]
        assert got and got != ip1, (i, got)
    time.sleep(1.2)
    assert ip1 not in [m["ip"] for m in t.members("a").values()]
    # Relayed clients (another subnet, no ARP) are checked with a ping instead
    nsexec("cl", "sysctl", "-qw", "net.ipv4.icmp_echo_ignore_all=0", check=False)
    rdev = mac(60)
    rip = t.lease(rdev)[0]
    t.client(rdev, "release", rip, ip_of("a"))
    time.sleep(0.3)
    t.client_addr(rip)
    answers = t.client(rdev, "relay", ip_of("cl"), ip_of("a"), wait=1.5)
    assert len(answers) == 1 and answers[0]["yiaddr"] != rip, (rip, answers)
    assert f"Address {rip} is already in use by {rip}" in t.log("a"), "ping conflict not logged"

    # A free address costs one probe wait (200 ms here), not a DISCOVER retry
    t0 = time.time()
    first = t.client(mac(50), "discover", wait=0.45)
    assert first and first[0]["type"] == "OFFER", "offer slower than one probe wait"
    assert time.time() - t0 < 1.5


# ---- clusters -----------------------------------------------------------------

@test
def pair_splits_work(t):
    cluster(t, ["a", "b"])
    served = {}
    for i in range(24):
        offers = [r for r in t.client(mac(i), "discover", wait=0.8) if r["type"] == "OFFER"]
        assert len(offers) == 1, f"{mac(i)} got {len(offers)} offers"
        o = offers[0]
        want = bucket_owner(mac(i), ["A", "B"])
        assert SERVER_OF[o["server"]] == want, (mac(i), o["server"], want)
        assert slice_owner(o["yiaddr"], ["A", "B"]) == want, (o["yiaddr"], want)
        acks = [r for r in t.client(mac(i), "select", o["yiaddr"], o["server"], wait=0.8)
                if r["type"] == "ACK"]
        assert len(acks) == 1 and acks[0]["lease"] == 600, acks
        served[want] = served.get(want, 0) + 1
    assert served.get("A") and served.get("B"), served
    wait_for(lambda: len(t.members("a")) == 24 and t.members("a") == t.members("b"), 5,
             what="members.txt equal on A and B")
    no_duplicate_ips(t.members("a"))


@test
def failover_and_return(t):
    cluster(t, ["a", "b"])
    leases = {}
    for i in range(16):
        ip, srv, _ = t.lease(mac(i), wait=0.8)
        leases[mac(i)] = (ip, SERVER_OF[srv])
    a_clients = [m for m, (_, s) in leases.items() if s == "A"]
    assert a_clients, leases
    wait_for(lambda: len(t.members("b")) == 16, 5, what="B has all leases")

    t.kill("a")
    wait_for(lambda: "peer A node 10.77.0.2:647 DOWN" in status(t, "b"), 10,
             what="B sees A down")
    assert self_state(t, "b").get("buckets") == "256/256"
    # A's clients hit T2 and broadcast REBINDING — B keeps them on the same IP
    for m in a_clients:
        ip = leases[m][0]
        t.client_addr(ip)
        acks = [r for r in t.client(m, "rebind", ip, wait=1) if r["type"] == "ACK"]
        assert len(acks) == 1 and acks[0]["yiaddr"] == ip and acks[0]["server"] == ip_of("b"), acks
        assert acks[0]["lease"] == 120, "lease should be capped at MCLT while A is down"
        t.client_addr(ip, add=False)
    # new clients are served by B, only from B's slice
    for i in range(100, 106):
        ip, srv, ack = t.lease(mac(i), wait=0.8)
        assert srv == ip_of("b") and slice_owner(ip, ["A", "B"]) == "B" and ack["lease"] == 120

    t.start("a")
    wait_for(lambda: self_state(t, "a").get("state") == "NORMAL", 15, what="A back to NORMAL")
    wait_for(lambda: t.members("a") == t.members("b") and len(t.members("a")) == 22, 5,
             what="A caught up")
    ip, srv, ack = t.lease(mac(200), wait=0.8)
    assert ack["lease"] == 600, "leases back to full length"
    assert SERVER_OF[srv] == bucket_owner(mac(200), ["A", "B"])


@test
def partition_never_duplicates(t):
    cluster(t, ["a", "b"])
    for i in range(6):
        t.lease(mac(i), wait=0.8)
    t.block_peer_link("a")
    wait_for(lambda: all(self_state(t, n).get("buckets") == "256/256" for n in "ab"), 12,
             what="both nodes take all buckets")
    # both answer now; each offers only from its own slice
    for i in range(10, 40):
        offers = [r for r in t.client(mac(i), "discover", wait=0.8) if r["type"] == "OFFER"]
        assert len(offers) == 2, offers
        for o in offers:
            assert slice_owner(o["yiaddr"], ["A", "B"]) == SERVER_OF[o["server"]], o
        o = offers[i % 2]                      # clients pick either
        acks = [r for r in t.client(mac(i), "select", o["yiaddr"], o["server"], wait=0.8)
                if r["type"] == "ACK"]
        assert acks and acks[0]["lease"] == 120, acks
    t.unblock_peer_link("a")
    wait_for(lambda: t.members("a") == t.members("b") and len(t.members("a")) == 36, 15,
             what="nodes merge after the partition heals")
    no_duplicate_ips(t.members("a"))
    assert "CONFLICT" not in t.log("a") + t.log("b")


@test
def partner_down_takes_slice(t):
    small = ("10.77.0.10", "10.77.0.21")      # 12 addresses keeps this quick
    cluster(t, ["a", "b"], extra="mclt 4\n", pool=small)
    b_slice = [ip for ip in pool_ips(small) if slice_owner(ip, ["A", "B"]) == "B"]
    a_slice = [ip for ip in pool_ips(small) if slice_owner(ip, ["A", "B"]) == "A"]
    assert a_slice and b_slice, (a_slice, b_slice)
    t.kill("b")
    wait_for(lambda: "peer B node 10.77.0.3:647 DOWN" in status(t, "a"), 10, what="A sees B down")
    rc, out = t.ctl("a", "partner-down", "A")
    assert rc != 0 and "this node" in out, out
    # fill A's slice
    for i in range(len(a_slice)):
        assert t.lease(mac(i), wait=0.5)[0], f"lease {i} of {len(a_slice)} failed"
    assert t.lease(mac(500), wait=0.8)[0] is None, "A must not touch B's slice yet"
    rc, out = t.ctl("a", "partner-down", "B")
    assert rc == 0, out
    time.sleep(1)
    assert t.lease(mac(501), wait=0.8)[0] is None, "still inside MCLT"
    time.sleep(4)
    ip = t.lease(mac(502), wait=0.8)[0]
    assert ip in b_slice, ip
    # B comes back and A stops using B's slice.  (That lease was capped at the
    # 4 s MCLT, so it may have expired meanwhile; the client renews it with A,
    # and B must learn that one of its addresses is in use.)
    t.start("b")
    wait_for(lambda: self_state(t, "b").get("state") == "NORMAL", 15, what="B NORMAL")
    assert "PARTNER-DOWN" not in status(t, "a")
    t.client_addr(ip)
    acks = [r for r in t.client(mac(502), "renew", ip, ip_of("a"), wait=1) if r["type"] == "ACK"]
    assert acks and acks[0]["yiaddr"] == ip, acks
    wait_for(lambda: t.members("b").get(mac(502), {}).get("ip") == ip, 5,
             what="B learned A's use of its slice")


@test
def restart_catches_up(t):
    cluster(t, ["a", "b"])
    t.stop("b")
    time.sleep(0.5)
    for i in range(10):
        t.lease(mac(i), wait=0.8)
    t.start("b")
    wait_for(lambda: self_state(t, "b").get("state") == "NORMAL", 15, what="B NORMAL")
    wait_for(lambda: t.members("b") == t.members("a") and len(t.members("a")) == 10, 5,
             what="B caught up")
    assert "catching up on A" in t.log("b")


@test
def unknown_lease_is_adopted(t):
    """A node dies before its journal line reaches the peer: the survivor
    accepts the client's address instead of NAKing it off the network."""
    cluster(t, ["a", "b"])
    t.block_peer_link("a")                     # A's records won't reach B...
    time.sleep(0.5)
    dev = next(mac(i) for i in range(500) if bucket_owner(mac(i), ["A", "B"]) == "A")
    ip, srv, _ = t.lease(dev, wait=0.8)
    assert srv == ip_of("a")
    t.kill("a")                                # ...and A dies
    t.unblock_peer_link("a")
    wait_for(lambda: self_state(t, "b").get("buckets") == "256/256", 12, what="B owns all")
    assert dev not in t.members("b")
    t.client_addr(ip)
    acks = [r for r in t.client(dev, "rebind", ip, wait=1) if r["type"] == "ACK"]
    assert acks and acks[0]["yiaddr"] == ip, acks
    time.sleep(1.2)
    assert t.members("b")[dev]["ip"] == ip


@test
def relay_goes_to_bucket_owner(t):
    cluster(t, ["a", "b"])
    for i in range(8):
        want = bucket_owner(mac(i), ["A", "B"])
        answers = []
        for n in ("a", "b"):
            answers += t.client(mac(i), "relay", ip_of("cl"), ip_of(n), wait=0.6)
        assert len(answers) == 1 and SERVER_OF[answers[0]["server"]] == want, answers


@test
def controller_pushes_config(t):
    # nodes start knowing only where the controller is
    t.write_conf("ctl", role="controller", node_id="CTL")
    t.write_cluster("ctl", [("node", "a"), ("node", "b"), ("controller", "ctl")])
    with open(t.node_dir("ctl") + "/cluster/static_list.txt", "w") as f:
        f.write("cam 02:00:00:00:00:77 10.77.0.140\n")
    for n in ("a", "b"):
        t.write_conf(n, controller="ctl")
    t.start("ctl")
    t.start("a")
    t.start("b")
    for n in ("a", "b"):
        wait_for(lambda n=n: self_state(t, n).get("state") == "NORMAL", 15, what=f"{n} NORMAL")
    assert "cam 02:00:00:00:00:77" in t.read("a", "cluster/static_list.txt")
    ver = self_state(t, "a")["config"]
    assert ver == self_state(t, "b")["config"] == self_state(t, "ctl")["config"], ver
    ip, srv, _ = t.lease("02:00:00:00:00:77", wait=0.8)
    assert ip == "10.77.0.140"
    for i in range(6):
        t.lease(mac(i), wait=0.8)
    wait_for(lambda: len(t.members("ctl")) == 7, 5, what="controller sees every lease")

    # change shared config on the controller only
    with open(t.node_dir("ctl") + "/cluster/cluster.conf", "a") as f:
        f.write("dns 10.77.0.53\n")
    t.signal("ctl", signal.SIGHUP)
    wait_for(lambda: "10.77.0.53" in t.read("a", "cluster/cluster.conf")
             and "10.77.0.53" in t.read("b", "cluster/cluster.conf"), 10, what="push")
    new = self_state(t, "ctl")["config"]
    assert new != ver
    wait_for(lambda: self_state(t, "a")["config"] == new == self_state(t, "b")["config"], 5,
             what="nodes on the new config")

    # adding a member while one is down is refused...
    t.stop("b")
    wait_for(lambda: "peer B node 10.77.0.3:647 DOWN" in status(t, "ctl"), 10, what="ctl sees B down")
    t.write_conf("c")
    t.write_cluster("ctl", [("node", "a"), ("node", "b"), ("node", "c"), ("controller", "ctl")],
                    extra="dns 10.77.0.53\n")
    rc, out = t.ctl("ctl", "push")
    assert rc != 0 and "not up" in out, out
    # ...until the node is back
    t.start("b")
    wait_for(lambda: "peer B node 10.77.0.3:647 UP" in status(t, "ctl"), 15, what="B back")
    rc, out = t.ctl("ctl", "push")
    assert rc == 0, out
    with open(t.node_dir("c") + "/dhcp.conf", "a") as f:
        f.write(f"controller   {ip_of('ctl')}\n")
    t.start("c")
    wait_for(lambda: self_state(t, "c").get("state") == "NORMAL", 20, what="C NORMAL")
    wait_for(lambda: len({self_state(t, n)["config"] for n in ("a", "b", "c", "ctl")}) == 1, 10,
             what="everyone on the same config")
    wait_for(lambda: len(t.members("c")) == 7, 5, what="C synced the leases")
    total = sum(int(self_state(t, n)["buckets"].split("/")[0]) for n in ("a", "b", "c"))
    assert total == 256, total
    for i in range(50, 70):
        ip, srv, _ = t.lease(mac(i), wait=0.8)
        want = bucket_owner(mac(i), ["A", "B", "C"])
        assert SERVER_OF[srv] == want and slice_owner(ip, ["A", "B", "C"]) == want, (ip, srv, want)
    wait_for(lambda: len(t.members("ctl")) == 27, 5, what="controller sees all")
    no_duplicate_ips(t.members("ctl"))


@test
def peer_link_security(t):
    cluster(t, ["a", "b"])
    # wrong key: rejected, and says why
    with open(t.node_dir("a") + "/peer.key", "w") as f:
        f.write("not-the-right-key-at-all\n")
    rc, out = t.ctl("a", "status")
    assert rc != 0, out
    assert "bad signature" in t.log("a")
    # an unknown node id is refused even with the right key
    # (an id that sorts before A and B, so it's the one that dials them)
    t.write_conf("c", node_id="0EVIL")
    t.write_cluster("c", [("node", "a"), ("node", "b"), ("node", "c")])
    with open(t.node_dir("c") + "/cluster/cluster.conf") as f:
        conf = f.read().replace(" C    ", " 0EVIL ")
    with open(t.node_dir("c") + "/cluster/cluster.conf", "w") as f:
        f.write(conf)
    t.start("c")
    wait_for(lambda: "isn't in cluster.conf" in t.log("a") or "isn't in cluster.conf" in t.log("b"),
             10, what="EVIL rejected")


@test
def same_host_instances(t):
    """Three servers sharing ONE address on one machine (own peer ports) plus
    one on another machine — a mixture.  No extra IPs, no forwarder."""
    ports = {"a": 647, "a2": 648, "a3": 649, "b": 647}
    members = [("node", n, p) for n, p in ports.items()]
    for n, p in ports.items():
        t.write_conf(n, peer_port=p)
        t.write_cluster(n, members)
    for n in ports:
        t.start(n)
    converged(t, list(ports))
    ids = [n.upper() for n in ports]
    on_a = {"A", "A2", "A3"}

    def issuer(dev):
        return wait_for(lambda: t.members("b").get(dev, {}).get("node"), 3,
                        what=f"{dev} replicated")

    # Broadcast DORA: exactly one answer, from the bucket owner (checked via
    # which node the lease is recorded under, since machine A has one address)
    by_node = {}
    for i in range(32):
        offers = [r for r in t.client(mac(i), "discover", wait=0.8) if r["type"] == "OFFER"]
        assert len(offers) == 1, f"{mac(i)} got {len(offers)} offers"
        o = offers[0]
        want = bucket_owner(mac(i), ids)
        acks = [r for r in t.client(mac(i), "select", o["yiaddr"], o["server"], wait=0.8)
                if r["type"] == "ACK"]
        assert len(acks) == 1, acks
        assert issuer(mac(i)) == want and slice_owner(o["yiaddr"], ids) == want, (mac(i), want)
        assert o["server"] == ip_of("a" if want in on_a else "b")
        by_node.setdefault(want, []).append((mac(i), o["yiaddr"]))
    assert {"A", "A2", "A3", "B"} <= set(by_node), by_node.keys()

    # A renewal sent to machine A's address reaches exactly one of its servers
    dev, ip = by_node["A2"][0]
    t.client_addr(ip)
    acks = t.client(dev, "renew", ip, ip_of("a"), wait=1)
    assert len(acks) == 1 and acks[0]["type"] == "ACK" and acks[0]["yiaddr"] == ip, acks
    t.client_addr(ip, add=False)

    # Relays send one copy per machine: exactly one answer, from the machine
    # whose servers own the bucket, and from the answering node's own slice
    for i in range(100, 116):
        dev = mac(i)
        answers = []
        for host in ("a", "b"):
            answers += t.client(dev, "relay", ip_of("cl"), ip_of(host), wait=0.5)
        want = bucket_owner(dev, ids)
        assert len(answers) == 1, (dev, answers)
        o = answers[0]
        host = "a" if want in on_a else "b"
        assert o["server"] == ip_of(host), (dev, want)
        # handed to the owning sibling, so the address comes from ITS slice
        assert slice_owner(o["yiaddr"], ids) == want, (dev, o["yiaddr"], want)
        acks = t.client(dev, "relayreq", ip_of("cl"), ip_of(host), o["yiaddr"], o["server"],
                        wait=0.8)
        assert len(acks) == 1 and acks[0]["type"] == "ACK", (dev, acks)
        assert issuer(dev) == want, (dev, want)

    wait_for(lambda: all(t.members(n) == t.members("a") for n in ports)
             and len(t.members("a")) == 48, 5, what="all four agree")
    # (the node column is whoever last wrote the lease — any node may renew —
    # so slices were checked above, at the moment each address was handed out)
    no_duplicate_ips(t.members("a"))

    # One server on the shared machine dies: its clients keep their addresses,
    # both by broadcast rebind and by renewing to the machine's address
    t.kill("a2")
    wait_for(lambda: sum(int(self_state(t, n)["buckets"].split("/")[0])
                         for n in ("a", "a3", "b")) == 256, 10, what="A2's buckets taken over")
    for dev, ip in by_node["A2"][:3]:
        t.client_addr(ip)
        acks = [r for r in t.client(dev, "rebind", ip, wait=1) if r["type"] == "ACK"]
        assert len(acks) == 1 and acks[0]["yiaddr"] == ip, acks
        acks = [r for r in t.client(dev, "renew", ip, ip_of("a"), wait=1) if r["type"] == "ACK"]
        assert len(acks) == 1 and acks[0]["yiaddr"] == ip, acks
        t.client_addr(ip, add=False)
    no_duplicate_ips(t.members("b"))


def main():
    ensure_namespace()
    args = sys.argv[1:]
    binary = "bin/dhcp_server"
    if args and os.path.exists(args[0]):
        binary = args.pop(0)
    chosen = [f for f in TESTS if not args or f.__name__ in args]
    results = []
    for fn in chosen:
        t = Topology(binary)
        t0 = time.time()
        try:
            t.up()
            fn(t)
            t.down()                   # clean shutdown, so sanitizers report too
            for n in ("a", "b", "c", "ctl"):
                log = t.log(n)
                for bad in ("AddressSanitizer", "LeakSanitizer", "runtime error:"):
                    assert bad not in log, f"{bad} report in {n}'s log"
            results.append((fn.__name__, True, time.time() - t0, ""))
            print(f"PASS  {fn.__name__}  ({time.time() - t0:.1f}s)", flush=True)
        except Exception as e:
            detail = traceback.format_exc()
            logs = "".join(f"\n--- {n} log (tail) ---\n" + "\n".join(t.log(n).splitlines()[-40:])
                           for n in ("a", "b", "c", "ctl") if t.log(n))
            results.append((fn.__name__, False, time.time() - t0, detail + logs))
            print(f"FAIL  {fn.__name__}  ({time.time() - t0:.1f}s): {e}", flush=True)
        finally:
            t.cleanup()
    failed = [r for r in results if not r[1]]
    for name, _, _, detail in failed:
        print(f"\n===== {name} =====\n{detail}")
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
