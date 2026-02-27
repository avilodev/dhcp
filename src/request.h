#ifndef REQUEST_H
#define REQUEST_H

#include "stdio.h"
#include "string.h"

#include "types.h"
#include "utils.h"
#include "lease.h"
#include "response.h"

void log_dhcp_interaction(const char *message_type, const char *mac, 
                                 const char *hostname, const char *ip);
int process_dhcp_message(struct dhcp_packet *request,
                        struct dhcp_packet *response,
                        dhcp_options_t *opts,
                        dhcp_config_t *config,
                        size_t *pkt_len);
int parse_dhcp_options(struct dhcp_packet *packet, dhcp_options_t *opts);

#endif /* REQUEST_H */ 