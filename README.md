# DHCP Server

A DHCP server written in C that runs on a Raspberry Pi. It was built from scratch to have full control over what's on the network — who gets an IP, what IP they get, and who gets blocked entirely.

---

## What it does

When a device connects to the network it asks "can I get an IP address?" The server picks a random free address from the pool and hands it out. It keeps track of who has what in `members.txt` — one line per device, always up to date. When a device leaves cleanly the entry is removed. Simple.

A few things worth knowing about how it works under the hood:

- **IPs are assigned randomly**, not sequentially. This means an attacker watching traffic can't trivially map out the rest of your pool.
- **`members.txt` is not a log file.** It only contains currently active leases. One line per device. Updated on each renewal, removed on release.
- **It knows which interface a packet came in on** and replies on the same one. This matters on a Pi with multiple network interfaces — without this, replies can go out the wrong port.
- **Worker threads** handle packets in parallel so a slow client never holds up the rest. All the shared state is locked tightly — only for as long as needed.

---

## Directory layout

```
dhcp/
  src/              Source code
  obj/              Build artifacts (created automatically)
  bin/              The server binary (created automatically)
  cron_scripts/
    dhcp-startup    Boot launcher — what `make install` runs at @reboot
  misc/
    dhcp.conf.in    Config template (the repo path is stamped in at build time)
    dhcp.conf       Main config — edit this first (generated from .in by `make`)
    static_list.txt Devices that always get the same IP
    blacklist.txt   Devices that get ignored completely
    members.txt     Who currently has a lease
    server.log      What the server has been doing
    server.pid      The running server's process ID
    maintence.sh    Nightly cleanup script
    backups/        Daily backups of members.txt and server.log
```

---

## Getting started

### 1. Install dependencies

```bash
sudo apt update
sudo apt install gcc make
```

### 2. Build

```bash
make
```

The binary ends up at `bin/dhcp_server`.

### 3. Configure it

Open `misc/dhcp.conf`. The main things to set for your network:

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

Edit `misc/static_list.txt`. One device per line — a label, then the MAC, then the IP:

```
my-laptop  AA:BB:CC:DD:EE:FF  192.168.1.5
```

The label is just for you, the server doesn't use it. Pick IPs outside your pool range so there's no conflict. You can reload this file without restarting — see the operations section below.

### 5. Block devices (optional)

Edit `misc/blacklist.txt`. One MAC per line. The server will silently ignore any traffic from those devices:

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
sudo bin/dhcp_server misc/dhcp.conf
```

That runs in the foreground — handy for a first test (you'll see it log to the terminal; Ctrl-C to stop). To have it start on boot and keep itself maintained, use `make install` in the next step instead.

It needs root only to bind port 67. To have it drop back to an unprivileged user for the rest of its run, uncomment the `user` line in `misc/dhcp.conf` (set it to whoever owns `misc/`). With that set, a compromise of the daemon no longer hands an attacker root.

### 8. Install it to start at boot (recommended)

```bash
sudo make install
```

This builds the server and installs two cron jobs under `/etc/cron.d`:

- **`dhcp-startup`** — an `@reboot` entry that launches the server every time the Pi boots.
- **`dhcp-maintenance`** — runs nightly at 03:00 to prune leases that expired without a clean release, rotate `server.log` if it gets big, and clear out old backups.

Every path is derived from wherever the repo lives, so there's nothing to hand-edit. Reboot to start it automatically, or launch it right now with the same command boot uses:

```bash
sudo cron_scripts/dhcp-startup
```

To change *how* it starts at boot, edit `cron_scripts/dhcp-startup` — the cron entry points back at that file, so changes take effect on the next boot with no reinstall.

To remove both cron jobs:

```bash
sudo make uninstall
```

---

## Day-to-day

**Reload static assignments or blacklist without restarting:**
```bash
sudo kill -HUP $(cat misc/server.pid)
```

**Dump the current in-memory lease table to a file:**
```bash
sudo kill -USR1 $(cat misc/server.pid)
```

**Watch what the server is doing live:**
```bash
tail -f misc/server.log
```

**See who currently has a lease:**
```bash
cat misc/members.txt
```

**Start it (same command boot uses):**
```bash
sudo cron_scripts/dhcp-startup
```

**Stop the server:**
```bash
sudo kill $(cat misc/server.pid)
```
If you installed it with `make install`, this just stops the running process — it'll start again on the next reboot. Run `sudo make uninstall` first if you want it gone for good.
