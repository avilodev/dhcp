#ifndef REQUEST_H
#define REQUEST_H

#include "stdio.h"
#include "string.h"

#include "types.h"
#include "utils.h"
#include "lease.h"
#include "response.h"

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
    bool write_lease_db;     /* true → call update_lease_database after unlock */
    bool remove_lease_db;    /* true → call remove_lease_from_database after unlock */
} dhcp_result_t;

void log_dhcp_interaction(dhcp_config_t *config, const char *message_type,
                          const char *mac, const char *hostname, const char *ip);
int process_dhcp_message(struct dhcp_packet *request,
                        struct dhcp_packet *response,
                        dhcp_options_t *opts,
                        dhcp_config_t *config,
                        size_t *pkt_len,
                        dhcp_result_t *result);
int parse_dhcp_options(struct dhcp_packet *packet, dhcp_options_t *opts);

#endif /* REQUEST_H */ 