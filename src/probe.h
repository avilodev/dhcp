#ifndef PROBE_H
#define PROBE_H

#include "types.h"

/* Conflict detection: before offering an address we've never handed out,
 * check that nothing on the network is already using it.
 *
 * On the local network we send an ARP probe (RFC 5227: "who has X?" from
 * 0.0.0.0).  Every device using an address must answer ARP for it — even ones
 * whose firewall drops ping — so this catches hand-configured devices and
 * leftovers from another DHCP server.  For relayed clients (another subnet,
 * where ARP can't reach) we fall back to an ICMP echo.
 *
 * Each worker thread owns one probe_ctx_t, so probes run in parallel without
 * locking.  The sockets need root (CAP_NET_RAW), so they're opened at startup,
 * before the server drops privileges. */

typedef struct {
    int      arp_fd;    /* AF_PACKET, ARP only; -1 if unavailable */
    int      icmp_fd;   /* raw ICMP; -1 if unavailable */
    uint16_t ping_id;
} probe_ctx_t;

int  probe_open(probe_ctx_t *p, int worker_index);
void probe_close(probe_ctx_t *p);

/* ip in network order.  on_link: the client is on one of our interfaces
 * (ifindex), so ARP works; otherwise ping.
 * Returns 1 if something answered (who = its MAC or IP), 0 if nothing did
 * within timeout_ms, -1 if we couldn't probe at all. */
int  probe_address(probe_ctx_t *p, uint32_t ip, int ifindex, bool on_link,
                   int timeout_ms, char *who, size_t wholen);

#endif /* PROBE_H */
