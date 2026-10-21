# DHCP Server

A DHCP server written in C that runs on a Raspberry Pi. It was built from scratch to have full control over what's on the network — who gets an IP, what IP they get, and who gets blocked entirely.

---

## What it does

When a device connects to the network it asks "can I get an IP address?" The server picks a free address from the pool and hands it out. Every lease change is written as one line to `leases.journal`, and `members.txt` always shows who has what right now — one line per device. When a device leaves cleanly the entry is removed. Simple.

It can also run as a **cluster** of several servers that share one view of every lease, so losing a box doesn't take the network down. See [CLUSTER.md](CLUSTER.md).

A few things worth knowing about how it works under the hood:

- **IPs are sticky, not sequential.** Each device starts searching the pool from a spot derived from its own ID, so a device that comes back usually gets its old address again, and addresses don't line up in join order.
- **`leases.journal` is the database** — a plain text file, one line per lease change, appended and `fsync`ed before the client gets its ACK, so a power cut can't lose a lease. It's compacted hourly.
- **`members.txt` is not a log file.** It's rebuilt from memory whenever something changes: currently active leases plus every static assignment, sorted by IP, with when each lease expires.
- **It checks an address is free before offering it.** A new device's first offer waits half a second while the server asks the network (ARP) whether anything already uses that address. If something does, the server logs its MAC, holds the address back and offers the next one.
- **It knows which interface a packet came in on** and replies on the same one. This matters on a Pi with multiple network interfaces — without this, replies can go out the wrong port.
- **Worker threads** handle packets in parallel so a slow client never holds up the rest. All the shared state is locked tightly — only for as long as needed.

---

## Directory layout

```
dhcp/
  src/              Source code
  tests/            End-to-end tests (`make test`, no sudo needed)
  obj/              Build artifacts (created automatically)
  bin/              The server binary (created automatically)
  scripts/
    dhcp-startup    Boot launcher — what `make install` runs at @reboot
    maintenance.sh  Nightly cleanup (log rotation, backups)
    new-instance.sh Adds another cluster node on this machine (`make instance`)
  config/           Everything you edit
    dhcp.conf.in    Config template (the repo path is stamped in at build time)
    dhcp.conf       Main config — edit this first (created from .in by the first
                    `make`; never overwritten after that — `make config-diff`
                    shows options added to the template since)
    static_list.txt Devices that always get the same IP
    blacklist.txt   Devices that get ignored completely
    instance.conf.in      Template for extra instances (`make instance`)
    cluster.conf.example  Template for cluster mode (see CLUSTER.md)
  etc/              Everything the server writes — don't edit, safe to read
    leases.journal  The lease database — one line per lease change (append-only)
    members.txt     Who currently has a lease (rebuilt from the journal)
    server.log      What the server has been doing
    server.pid      The running server's process ID
    refresh.log     Output of the cron jobs
    backups/        Daily backups of the journal and members.txt
    logs/           Archived server.log, one per day (logs/YYYY/MM/DD/)
```

---

## Getting started

### 1. Install dependencies

```bash
sudo apt update
sudo apt install gcc make libssl-dev
```

### 2. Build

```bash
make
```

The binary ends up at `bin/dhcp_server`.

### 3. Configure it

Open `config/dhcp.conf`. The main things to set for your network:

```
server_ip    192.168.1.2       # This machine's IP on the LAN
start_ip     192.168.1.10      # Start of the IP pool
end_ip       192.168.1.254     # End of the IP pool
subnet_mask  255.255.255.0
gateway      192.168.1.1
dns          192.168.1.2       # You can list up to 4 dns lines
lease_time   86400             # How long a lease lasts in seconds (86400 = 24h)
```

Everything else in the file points to the right places already and shouldn't need touching.

### 4. Give devices fixed IPs (optional)

Edit `config/static_list.txt`. One device per line — a label, then the MAC, then the IP:

```
my-laptop  AA:BB:CC:DD:EE:FF  192.168.1.5
```

The label is just for you, the server doesn't use it. Pick IPs outside your pool range so there's no conflict. You can reload this file without restarting — see the operations section below.

### 5. Block devices (optional)

Edit `config/blacklist.txt`. One MAC per line, any case. The server will silently ignore any traffic from those devices. A reload (`kill -HUP`) applies additions and removals:

```
AA:BB:CC:DD:EE:FF
```

### 6. Make sure nothing else is running DHCP

If `dnsmasq` is installed and running it will fight with this server:

```bash
sudo systemctl stop dnsmasq
sudo systemctl disable dnsmasq
```

Same idea for anything else that might be handing out IPs on your LAN.

### 7. Run it

Port 67 needs root:

```bash
sudo bin/dhcp_server config/dhcp.conf
```

That runs in the foreground — handy for a first test (you'll see it log to the terminal; Ctrl-C to stop). To have it start on boot and keep itself maintained, use `make install` in the next step instead.

It needs root only to bind port 67. After that it drops to the `user` in `config/dhcp.conf`, which `make` fills in as the owner of this checkout. A compromise of the daemon then no longer hands an attacker root, and every file it writes belongs to you, so logs and backups can be read and deleted without sudo. Starting a second copy on the same config is refused.

### 8. Install it to start at boot (recommended)

```bash
sudo make install
```

This builds the server and installs two cron jobs under `/etc/cron.d`:

- **`dhcp-startup`** — launches the server every time the Pi boots (waiting up to a minute for `server_ip` to come up), then checks every 5 minutes and restarts it if it has died.
- **`dhcp-maintenance`** — runs nightly at 03:00, as you rather than root, to archive `server.log` to `etc/logs/YYYY/MM/DD/`, back up the lease journal and `members.txt`, and clear out archives and backups older than 30 days.

Every path is derived from wherever the repo lives, so there's nothing to hand-edit. Reboot to start it automatically, or launch it right now with the same command boot uses:

```bash
sudo scripts/dhcp-startup
```

To change *how* it starts, edit `scripts/dhcp-startup` — the cron entries point back at that file, so changes take effect on its next run with no reinstall.

To remove both cron jobs:

```bash
sudo make uninstall
```

---

## Day-to-day

**Reload static assignments or blacklist without restarting:**
```bash
sudo kill -HUP $(cat etc/server.pid)
```

**Dump the current in-memory lease table to a file:**
```bash
sudo kill -USR1 $(cat etc/server.pid)
```

**Watch what the server is doing live:**
```bash
tail -f etc/server.log
```

**See who currently has a lease:**
```bash
cat etc/members.txt
```
Columns: `device_id,mac,ip,hostname,expires,node`. `node` is which server issued the lease.

**Compact the journal now (it happens hourly anyway):**
```bash
sudo kill -USR2 $(cat etc/server.pid)
```

**Start it (same command boot uses):**
```bash
sudo scripts/dhcp-startup
```

**Stop the server:**
```bash
sudo kill $(cat etc/server.pid)
```
If you installed it with `make install`, the 5-minute check starts it again — which is all a restart after a config change needs. To keep it stopped, run `sudo make uninstall` first.
