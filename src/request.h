#ifndef REQUEST_H
#define REQUEST_H

#include "stdio.h"
#include "string.h"

#include "types.h"
#include "utils.h"
#include "lease.h"
#include "response.h"
#include "ha.h"

/*
 * Carries logging and lease-write state out of process_dhcp_message so
 * those operations can happen AFTER releasing g_server_mutex, keeping
 * the critical section free of file I/O.
 */
typedef struct {
    char mac[MAC_STR_LEN];
    char device_id[256];
    char hostname[256];      /* client option-12 hostname, or "" */
    char req_log[32];        /* message type string for request log entry, or "" */
    char req_ip[IP_STR_LEN]; /* IP for request log entry, or "" (e.g. REQUEST) */
    char resp_log[32];       /* message type string for response log entry, or "" */
    char resp_ip[IP_STR_LEN];/* IP for response log entry (offered / confirmed) */
    lease_commit_t commit;   /* journal line to fsync + send to peers after unlock */
    char forward_to[NODE_ID_LEN]; /* hand the packet to this sibling instead of answering */
    char probe_ip[IP_STR_LEN];    /* a fresh address in this OFFER: check it's free first */
} dhcp_result_t;

/* How a packet reached us */
typedef struct {
    bool broadcast;   /* sent to a broadcast address — every node got a copy */
    bool forwarded;   /* handed over by a sibling on our address: it's ours to answer */
} dhcp_rx_t;

void log_dhcp_interaction(dhcp_config_t *config, const char *event,
                          const char *mac, const char *device_id,
                          const char *hostname, const char *ip);
int process_dhcp_message(struct dhcp_packet *request,
                        struct dhcp_packet *response,
                        dhcp_options_t *opts,
                        dhcp_config_t *config,
                        size_t *pkt_len,
                        dhcp_result_t *result,
                        const dhcp_rx_t *rx);
/* opt_len is the number of option bytes actually received (packet length minus
 * the fixed header), so parsing never reads past the end of the real packet. */
int parse_dhcp_options(struct dhcp_packet *packet, dhcp_options_t *opts,
                       size_t opt_len);

#endif /* REQUEST_H */ 