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
  misc/
    dhcp.conf       Main config — edit this first
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

### 8. Set up the maintenance cron job

This runs nightly to prune any leases that expired without a proper release, rotate the log if it gets big, and clean up old backups:

```bash
sudo crontab -e
```

Add:

```
0 3 * * * /home/avilo/dhcp/misc/maintence.sh >> /home/avilo/dhcp/misc/refresh.log 2>&1
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

**Stop the server:**
```bash
sudo kill $(cat misc/server.pid)
```
