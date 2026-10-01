#ifndef PROBE_H
#define PROBE_H

#include "types.h"

// Detect conflicts before offering fresh addresses.

typedef struct {
	int arp_fd;	 // AF_PACKET, ARP only; -1 if unavailable
	int icmp_fd; // raw ICMP; -1 if unavailable
	uint16_t ping_id;
} probe_ctx_t;

int probe_open(probe_ctx_t *p, int worker_index);
void probe_close(probe_ctx_t *p);

// Probe an address in network byte order.
int probe_address(probe_ctx_t *p, uint32_t ip, int ifindex, bool on_link,
				  int timeout_ms, char *who, size_t wholen);

#endif /* PROBE_H */
