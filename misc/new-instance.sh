#!/bin/bash
#
# new-instance.sh — create another DHCP cluster node on THIS machine.
#
#   misc/new-instance.sh <ID> [IP] [PEER_PORT] [CONTROLLER_IP[:PORT]] [ROLE]
#   (or: make instance ID=A2 [IP=...] [PEER_PORT=648] [CONTROLLER=192.168.1.4] [ROLE=controller])
#
# IP defaults to this machine's address (server_ip in misc/dhcp.conf): every
# server on the machine shares it and clients see one DHCP server here.  Each
# instance only needs its own node id and peer port.
#
# Writes misc/instances/<ID>/dhcp.conf.  cron_scripts/dhcp-startup starts every
# instance it finds there.  Prints the remaining steps.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="$(dirname "$SCRIPT_DIR")"
TEMPLATE="$PREFIX/misc/instance.conf.in"

ID="$1"; IP="$2"; PORT="$3"; CONTROLLER="$4"; ROLE="${5:-node}"

die() { echo "Error: $*" >&2; exit 1; }

[ -n "$ID" ] || die "usage: $0 <ID> [IP] [PEER_PORT] [CONTROLLER_IP[:PORT]] [ROLE]"
[[ "$ID" =~ ^[A-Za-z0-9_-]{1,15}$ ]] || die "ID must be 1-15 of A-Z a-z 0-9 _ -"
if [ -z "$IP" ]; then
    IP=$(awk '$1 == "server_ip" { print $2 }' "$PREFIX/misc/dhcp.conf" 2>/dev/null | tail -1)
    [ -n "$IP" ] || die "no IP given and no server_ip in misc/dhcp.conf"
fi
[[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "'$IP' is not an IPv4 address"
[ "$ROLE" = node ] || [ "$ROLE" = controller ] || die "ROLE must be node or controller"
[ "$ROLE" = controller ] && [ -n "$CONTROLLER" ] && die "a controller doesn't take CONTROLLER="

DIR="$PREFIX/misc/instances/$ID"
[ -e "$DIR/dhcp.conf" ] && die "$DIR/dhcp.conf already exists"

# Every config on this machine — the main one plus existing instances
CONFS=("$PREFIX/misc/dhcp.conf")
for c in "$PREFIX"/misc/instances/*/dhcp.conf; do [ -f "$c" ] && CONFS+=("$c"); done

conf_value() {   # conf_value <file> <key> <default>
    local v
    v=$(awk -v k="$2" '$1 == k { print $2 }' "$1" 2>/dev/null | tail -1)
    echo "${v:-$3}"
}

# Pick the next free peer port if none was given; refuse clashes
USED_PORTS=()
for c in "${CONFS[@]}"; do
    [ -f "$c" ] || continue
    USED_PORTS+=("$(conf_value "$c" peer_port 647)")
    [ "$(conf_value "$c" node_id "")" = "$ID" ] && die "node_id $ID is already used by $c"
done
if [ -z "$PORT" ]; then
    PORT=647
    while printf '%s\n' "${USED_PORTS[@]}" | grep -qx "$PORT"; do PORT=$((PORT + 1)); done
fi
printf '%s\n' "${USED_PORTS[@]}" | grep -qx "$PORT" && die "peer port $PORT is already used on this machine"

if [ "$ROLE" = controller ]; then
    CLUSTER_DIR="$DIR/cluster"          # the real shared config lives here
    CONTROLLER_LINE=""
elif [ -n "$CONTROLLER" ]; then
    CLUSTER_DIR="$DIR/cluster"          # the controller pushes a private copy here
    CONTROLLER_LINE="controller   ${CONTROLLER/:/ }"
else
    CLUSTER_DIR="$PREFIX/misc/cluster"  # hand-managed: shared with the main config
    CONTROLLER_LINE="# controller   192.168.1.4     # optional: pull cluster_dir from here"
fi

mkdir -p "$DIR"
sed -e "s|@ID@|$ID|g" -e "s|@IP@|$IP|g" -e "s|@PORT@|$PORT|g" \
    -e "s|@PREFIX@|$PREFIX|g" -e "s|@DIR@|$DIR|g" \
    -e "s|@CLUSTER_DIR@|$CLUSTER_DIR|g" -e "s|@CONTROLLER_LINE@|$CONTROLLER_LINE|g" \
    -e "s|@ROLE@|$ROLE|g" \
    "$TEMPLATE" > "$DIR/dhcp.conf"

echo "Created $DIR/dhcp.conf  ($ROLE $ID, $IP, peer port $PORT)"
echo

if [ "$ROLE" = controller ]; then
    mkdir -p "$CLUSTER_DIR"
    [ -f "$CLUSTER_DIR/cluster.conf" ] || cp "$PREFIX/misc/cluster.conf.example" "$CLUSTER_DIR/cluster.conf"
    touch "$CLUSTER_DIR/static_list.txt" "$CLUSTER_DIR/blacklist.txt"
    echo "Next:"
    echo "  1. Edit the shared config — this is now the one place to change it:"
    echo "       $CLUSTER_DIR/cluster.conf   (members, pool, dns, ...)"
    echo "       $CLUSTER_DIR/static_list.txt"
    echo "       $CLUSTER_DIR/blacklist.txt"
    echo "     and list the controller itself:   controller  $ID  $IP  $PORT"
    echo "  2. Point every node at it: 'controller $IP $PORT' in each node's dhcp.conf"
    echo "  3. Start it:  sudo cron_scripts/dhcp-startup   (starts anything not already running)"
    exit 0
fi
echo "Next:"
step=1
if ! ip -o -4 addr show 2>/dev/null | grep -q " $IP/"; then
    IFACE=$(ip -o -4 route get "$IP" 2>/dev/null | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1)}')
    echo "  $step. $IP isn't an address of this machine yet.  Usually you want to leave IP"
    echo "     out so the instance shares the machine's address; if you really want a"
    echo "     separate one, add it (and make sure nothing else on the network uses it)."
    echo "     To keep it across reboots:"
    echo "       sudo nmcli con mod \"\$(nmcli -g GENERAL.CONNECTION dev show ${IFACE:-eth0})\" +ipv4.addresses $IP/24"
    echo "       sudo nmcli dev reapply ${IFACE:-eth0}"
    echo "     (use your real prefix instead of /24 if the LAN isn't a /24)"
    step=$((step + 1))
fi
if [ -n "$CONTROLLER" ]; then
    echo "  $step. On the controller, add to cluster.conf and push:"
else
    echo "  $step. Add to cluster.conf on EVERY member (here: $CLUSTER_DIR/cluster.conf), then HUP them:"
fi
echo "       node  $ID  $IP  $PORT"
step=$((step + 1))
echo "  $step. Start it:  sudo cron_scripts/dhcp-startup   (starts anything not already running)"
