#ifndef RESPONSE_H
#define RESPONSE_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "types.h"
#include "utils.h"

// lease_secs: the lease to grant
int build_offer(struct dhcp_packet *resp, struct dhcp_packet *req,
				dhcp_options_t *opts, dhcp_config_t *config,
				size_t *pkt_len, uint32_t lease_secs);

int build_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
			  dhcp_options_t *opts, dhcp_config_t *config,
			  size_t *pkt_len, uint32_t lease_secs);

int build_nak(struct dhcp_packet *resp, struct dhcp_packet *req,
			  dhcp_config_t *config, size_t *pkt_len);

int build_inform_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
					 dhcp_options_t *opts, dhcp_config_t *config,
					 size_t *pkt_len);

#endif /* RESPONSE_H */
