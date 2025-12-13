#ifndef RESPONSE_H
#define RESPONSE_H

#include <stdio.h>
#include <string.h>

#include "types.h"
#include "utils.h"


/* Build DHCP OFFER */
int build_offer(struct dhcp_packet *resp, struct dhcp_packet *req,
               dhcp_options_t *opts, dhcp_config_t *config);

/* Build DHCP ACK */
int build_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
             dhcp_options_t *opts, dhcp_config_t *config);

#endif /* RESPONSE_H */ 