"""Network-namespace test harness for the DHCP server.

Builds a private virtual LAN that never touches the host's real network:

    dhcpt-sw   holds a bridge (br0) — the "switch"
    dhcpt-a    server A   10.77.0.2
    dhcpt-b    server B   10.77.0.3
    dhcpt-c    server C   10.77.0.4
    dhcpt-ctl  controller 10.77.0.5
    dhcpt-cl   clients    10.77.0.200 (+ leased IPs added on demand)

Everything is torn down again on exit.  Needs no sudo: when not root, the
test re-runs itself inside a private user + network namespace (see
ensure_namespace), so it can't touch the host's real network either way.
"""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PFX = "dhcpt-"
SUBNET = "10.77.0"
HOSTS = {"a": 2, "b": 3, "c": 4, "ctl": 5, "cl": 200}
# Extra server instances running on another host ("machine"), sharing its
# address the way several servers share one Pi:   name -> host
INSTANCES = {"a2": "a", "a3": "a"}
POOL = (f"{SUBNET}.10", f"{SUBNET}.109")      # 100 addresses
PEER_KEY = "test-key-0123456789abcdef0123456789abcdef"


def ensure_namespace():
    """Re-exec inside `unshare` unless we're already root (real or namespaced).

    The new user namespace maps us to root, so we can create namespaces,
    veths and bind port 67 — but only inside this sandbox.  /run is replaced
    by a private tmpfs so `ip netns` has somewhere to keep its handles."""
    if os.environ.get("DHCPT_SANDBOX") == "1":
        subprocess.run(["mount", "-t", "tmpfs", "tmpfs", "/run"], check=True)
        os.makedirs("/run/netns", exist_ok=True)
        return
    if os.geteuid() == 0:
        return
    env = dict(os.environ, DHCPT_SANDBOX="1")
    os.execvpe("unshare", ["unshare", "--user", "--map-root-user", "--net",
                           "--mount", "--", sys.executable, *sys.argv], env)


def sh(*cmd, check=True, capture=False):
    r = subprocess.run(cmd, check=False, text=True,
                       stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                       stderr=subprocess.PIPE if capture else subprocess.DEVNULL)
    if check and r.returncode != 0:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}\n"
                           f"{r.stdout if capture else ''}{r.stderr if capture else ''}")
    return r


def ns(name):
    return PFX + name


def nsexec(name, *cmd, **kw):
    return sh("ip", "netns", "exec", ns(name), *cmd, **kw)


def host_of(name):
    return INSTANCES.get(name, name)


def ip_of(name):
    return f"{SUBNET}.{HOSTS[host_of(name)]}"


class Topology:
    def __init__(self, binary, keep=False):
        self.binary = os.path.abspath(binary)
        self.dir = tempfile.mkdtemp(prefix="dhcpt-")
        self.procs = {}
        self.keep = keep
        self.flags = ["-v"]

    # ---- lifecycle -------------------------------------------------------
    def up(self):
        self.down(quiet=True)
        sh("ip", "netns", "add", ns("sw"))
        nsexec("sw", "ip", "link", "add", "br0", "type", "bridge")
        nsexec("sw", "ip", "link", "set", "br0", "up")
        nsexec("sw", "ip", "link", "set", "lo", "up")
        for h, octet in HOSTS.items():
            sh("ip", "netns", "add", ns(h))
            sh("ip", "link", "add", "eth0", "netns", ns(h), "type", "veth",
               "peer", "name", f"p-{h}", "netns", ns("sw"))
            nsexec("sw", "ip", "link", "set", f"p-{h}", "master", "br0")
            nsexec("sw", "ip", "link", "set", f"p-{h}", "up")
            nsexec(h, "ip", "link", "set", "lo", "up")
            nsexec(h, "ip", "addr", "add", f"{SUBNET}.{octet}/24", "dev", "eth0")
            nsexec(h, "ip", "link", "set", "eth0", "up")
        # Let the bridge learn/forward immediately
        time.sleep(0.5)

    def down(self, quiet=False):
        for name in list(self.procs):
            self.stop(name)
        r = sh("ip", "netns", "list", capture=True, check=False)
        for line in r.stdout.splitlines():
            n = line.split()[0] if line.strip() else ""
            if n.startswith(PFX):
                sh("ip", "netns", "del", n, check=False)

    def cleanup(self):
        self.down()
        if not self.keep:
            shutil.rmtree(self.dir, ignore_errors=True)

    # ---- servers ---------------------------------------------------------
    def node_dir(self, name):
        d = os.path.join(self.dir, name)
        os.makedirs(os.path.join(d, "cluster"), exist_ok=True)
        return d

    def write_conf(self, name, cluster=True, role="node", node_id=None,
                   controller=None, extra="", pool=POOL, peer_port=647,
                   controller_port=None):
        d = self.node_dir(name)
        with open(os.path.join(d, "peer.key"), "w") as f:
            f.write(PEER_KEY + "\n")
        os.chmod(os.path.join(d, "peer.key"), 0o600)
        lines = [
            f"server_ip    {ip_of(name)}",
            f"start_ip     {pool[0]}",
            f"end_ip       {pool[1]}",
            "subnet_mask  255.255.255.0",
            f"gateway      {SUBNET}.1",
            f"dns          {SUBNET}.1",
            "domain       test",
            "lease_time   600",
            f"lease_db     {d}/members.txt",
            f"static       {d}/static_list.txt",
            f"blacklist    {d}/blacklist.txt",
            f"log          {d}/server.log",
            f"pid          {d}/server.pid",
            f"dump         {d}/leases_current.txt",
            f"journal      {d}/leases.journal",
            "probe_timeout_ms 200",
        ]
        if cluster:
            lines += [
                f"node_id      {node_id or name.upper()}",
                f"role         {role}",
                f"cluster_dir  {d}/cluster",
                f"peer_key     {d}/peer.key",
                f"peer_port    {peer_port}",
            ]
            if controller:
                lines.append(f"controller   {ip_of(controller)} {controller_port or ''}")
        path = os.path.join(d, "dhcp.conf")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n" + extra)
        for fn in ("static_list.txt", "blacklist.txt"):
            p = os.path.join(d, fn)
            if not os.path.exists(p):
                open(p, "w").close()
        return path

    def write_cluster(self, name, members, extra="", pool=POOL):
        """members: (role, name) or (role, name, peer_port) tuples,
        e.g. [("node","a"), ("node","a2",648), ("controller","ctl")]"""
        d = os.path.join(self.node_dir(name), "cluster")
        lines = [f"{m[0]:<11} {m[1].upper():<4} {ip_of(m[1])} {m[2] if len(m) > 2 else ''}"
                 for m in members]
        lines += [
            f"start_ip     {pool[0]}",
            f"end_ip       {pool[1]}",
            "subnet_mask  255.255.255.0",
            f"gateway      {SUBNET}.1",
            f"dns          {SUBNET}.1",
            "domain       test",
            "lease_time   600",
            "mclt         120",
            "peer_timeout 3",
        ]
        with open(os.path.join(d, "cluster.conf"), "w") as f:
            f.write("\n".join(lines) + "\n" + extra)
        for fn in ("static_list.txt", "blacklist.txt"):
            p = os.path.join(d, fn)
            if not os.path.exists(p):
                open(p, "w").close()

    def start(self, name, args=(), wait=0.5):
        d = self.node_dir(name)
        log = open(os.path.join(d, "stderr.log"), "a")
        cmd = ["ip", "netns", "exec", ns(host_of(name)), self.binary, *self.flags, *args,
               os.path.join(d, "dhcp.conf")]
        p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
        self.procs[name] = p
        time.sleep(wait)
        if p.poll() is not None:
            raise RuntimeError(f"server {name} exited early:\n" + self.log(name))
        return p

    def stop(self, name, sig=signal.SIGTERM):
        p = self.procs.pop(name, None)
        if not p:
            return
        if p.poll() is None:
            p.send_signal(sig)
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()

    def kill(self, name):
        self.stop(name, signal.SIGKILL)

    def signal(self, name, sig):
        self.procs[name].send_signal(sig)

    def alive(self, name):
        p = self.procs.get(name)
        return p is not None and p.poll() is None

    def log(self, name):
        try:
            return open(os.path.join(self.node_dir(name), "stderr.log")).read()
        except OSError:
            return ""

    def read(self, name, rel):
        try:
            return open(os.path.join(self.node_dir(name), rel)).read()
        except OSError:
            return ""

    def members(self, name):
        """Parse members.txt → {device_id: dict}"""
        out = {}
        for line in self.read(name, "members.txt").splitlines():
            if not line or line.startswith("#"):
                continue
            f = line.split(",")
            if len(f) >= 6:
                out[f[0]] = {"mac": f[1], "ip": f[2], "host": f[3],
                             "expires": f[4], "node": f[5]}
            elif len(f) >= 3:
                out[f[0]] = {"mac": f[1], "ip": f[2]}
        return out

    # ---- network faults --------------------------------------------------
    def block_peer_link(self, name):
        """Drop peer-link TCP (port 647) in and out of `name` — DHCP still flows."""
        nsexec(name, "nft", "add", "table", "inet", "dhcpt")
        nsexec(name, "nft", "add", "chain", "inet", "dhcpt", "in",
               "{ type filter hook input priority 0 ; }")
        nsexec(name, "nft", "add", "chain", "inet", "dhcpt", "out",
               "{ type filter hook output priority 0 ; }")
        # only on eth0: loopback stays open so `--ctl` still works
        for chain, dev in (("in", "iifname"), ("out", "oifname")):
            for port in ("dport", "sport"):
                nsexec(name, "nft", "add", "rule", "inet", "dhcpt", chain,
                       dev, "eth0", "tcp", port, "647", "drop")

    def unblock_peer_link(self, name):
        nsexec(name, "nft", "delete", "table", "inet", "dhcpt", check=False)

    # ---- clients ---------------------------------------------------------
    def client(self, mac, cmd, *args, wait=None):
        a = [os.path.join(HERE, "dhcpc.py"), "eth0", mac, cmd, *args]
        if wait is not None:
            a += ["--wait", str(wait)]
        r = nsexec("cl", "python3", *a, capture=True)
        return json.loads(r.stdout)

    def client_addr(self, ip, add=True):
        nsexec("cl", "ip", "addr", "add" if add else "del", f"{ip}/32",
               "dev", "eth0", check=False)

    def ctl(self, name, *args):
        d = self.node_dir(name)
        r = nsexec(host_of(name), self.binary, "--ctl", os.path.join(d, "dhcp.conf"),
                   *args, capture=True, check=False)
        return r.returncode, r.stdout + r.stderr

    def lease(self, mac, wait=1.5):
        """Full DORA.  Returns (ip, server, ack) or (None, None, offers)."""
        offers = [r for r in self.client(mac, "discover", wait=wait)
                  if r["type"] == "OFFER"]
        if not offers:
            return None, None, offers
        o = offers[0]
        acks = self.client(mac, "select", o["yiaddr"], o["server"], wait=wait)
        acks = [r for r in acks if r["type"] == "ACK"]
        if not acks:
            return None, None, offers
        return acks[0]["yiaddr"], acks[0]["server"], acks[0]
