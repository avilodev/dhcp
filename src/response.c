#include "response.h"


/* Build DHCP OFFER packet */
int build_offer(struct dhcp_packet *resp, struct dhcp_packet *req,
               dhcp_options_t *opts, dhcp_config_t *config) {
    memset(resp, 0, sizeof(*resp));

    resp->op = 2;
    resp->htype = req->htype;
    resp->hlen = req->hlen;
    resp->xid = req->xid;
    resp->flags = req->flags;
    memcpy(resp->chaddr, req->chaddr, 16);

    char mac_str[MAC_STR_LEN];
    format_mac_address(req->chaddr, mac_str, sizeof(mac_str));

    char *addr = allocate_ip_address(mac_str, opts, config);
    if (!addr) {
        syslog(LOG_ERR, "Failed to allocate IP address");
        return -1;
    }

    resp->yiaddr = inet_addr(addr);
    resp->siaddr = inet_addr(config->server_ip);
    resp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *opt = resp->options;

    /* DHCP Message Type: Offer */
    *opt++ = 53; *opt++ = 1; *opt++ = DHCPOFFER;

    /* Server Identifier */
    *opt++ = 54; *opt++ = 4;
    uint32_t server = inet_addr(config->server_ip);
    memcpy(opt, &server, 4); opt += 4;

    /* Subnet Mask */
    *opt++ = 1; *opt++ = 4;
    uint32_t mask = inet_addr(config->subnet_mask);
    memcpy(opt, &mask, 4); opt += 4;

    /* Router (default gateway) */
    *opt++ = 3; *opt++ = 4;
    uint32_t gateway = inet_addr(config->gateway);
    memcpy(opt, &gateway, 4); opt += 4;

    /* DNS Servers */
    *opt++ = 6; *opt++ = 4; /* Single DNS server */
    uint32_t dns = inet_addr(config->dns_servers[0]);
    memcpy(opt, &dns, 4); opt += 4;

    /* Lease Time */
    *opt++ = 51; *opt++ = 4;
    uint32_t lease = htonl(config->lease_time);
    memcpy(opt, &lease, 4); opt += 4;

    *opt++ = 255; /* End */

    free(addr);
    return 0;
}

/* Build DHCP ACK packet */
int build_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
             dhcp_options_t *opts, dhcp_config_t *config) {
    memset(resp, 0, sizeof(*resp));

    resp->op = 2;
    resp->htype = req->htype;
    resp->hlen = req->hlen;
    resp->xid = req->xid;
    resp->flags = req->flags;
    memcpy(resp->chaddr, req->chaddr, 16);

    char mac_str[MAC_STR_LEN];
    format_mac_address(req->chaddr, mac_str, sizeof(mac_str));

    char *addr = allocate_ip_address(mac_str, opts, config);
    if (!addr) {
        syslog(LOG_ERR, "Failed to allocate IP address");
        return -1;
    }

    resp->yiaddr = inet_addr(addr);
    resp->siaddr = inet_addr(config->server_ip);
    resp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *opt = resp->options;

    /* DHCP Message Type: ACK */
    *opt++ = 53; *opt++ = 1; *opt++ = DHCPACK;

    /* Server Identifier */
    *opt++ = 54; *opt++ = 4;
    uint32_t server = inet_addr(config->server_ip);
    memcpy(opt, &server, 4); opt += 4;

    /* Subnet Mask */ 
    *opt++ = 1; *opt++ = 4;
    uint32_t mask = inet_addr(config->subnet_mask);
    memcpy(opt, &mask, 4); opt += 4;

    /* Router */
    *opt++ = 3; *opt++ = 4;
    uint32_t gateway = inet_addr(config->gateway);
    memcpy(opt, &gateway, 4); opt += 4;

    /* DNS */
    *opt++ = 6; *opt++ = 4;
    uint32_t dns = inet_addr(config->dns_servers[0]);
    memcpy(opt, &dns, 4); opt += 4;

    /* Lease Time */
    *opt++ = 51; *opt++ = 4;
    uint32_t lease = htonl(config->lease_time);
    memcpy(opt, &lease, 4); opt += 4;

    *opt++ = 255; /* End */

    free(addr);
    return 0;
}