#include "response.h"
#include <stddef.h>

#define ADD_OPTION(code, len, data) do { \
    if (opt + 2 + (size_t)(len) > opt_end) { \
        syslog(LOG_ERR, "Options buffer overflow at code %d", (code)); \
        free(addr); return -1; \
    } \
    *opt++ = (uint8_t)(code); \
    *opt++ = (uint8_t)(len); \
    memcpy(opt, (data), (len)); \
    opt += (len); \
} while (0)

#define ADD_OPTION_U8(code, value) do { \
    if (opt + 3 > opt_end) { \
        syslog(LOG_ERR, "Options buffer overflow at code %d", (code)); \
        free(addr); return -1; \
    } \
    *opt++ = (uint8_t)(code); \
    *opt++ = 1; \
    *opt++ = (uint8_t)(value); \
} while (0)

#define ADD_OPTION_U32(code, value) do { \
    if (opt + 6 > opt_end) { \
        syslog(LOG_ERR, "Options buffer overflow at code %d", (code)); \
        free(addr); return -1; \
    } \
    *opt++ = (uint8_t)(code); \
    *opt++ = 4; \
    uint32_t _tmp = (value); \
    memcpy(opt, &_tmp, 4); \
    opt += 4; \
} while (0)

/* NAK and INFORM ACK never allocate an IP, so these variants skip the free(addr) */
#define NOADDR_U8(code, value) do { \
    if (opt + 3 > opt_end) { syslog(LOG_ERR, "Options overflow"); return -1; } \
    *opt++ = (uint8_t)(code); *opt++ = 1; *opt++ = (uint8_t)(value); \
} while (0)

#define NOADDR_U32(code, value) do { \
    if (opt + 6 > opt_end) { syslog(LOG_ERR, "Options overflow"); return -1; } \
    *opt++ = (uint8_t)(code); *opt++ = 4; \
    uint32_t _t = (value); memcpy(opt, &_t, 4); opt += 4; \
} while (0)

static void fill_common_fields(struct dhcp_packet *resp,
                               const struct dhcp_packet *req) {
    resp->op     = 2;           /* BOOTREPLY */
    resp->htype  = req->htype;
    resp->hlen   = req->hlen;
    resp->hops   = 0;
    resp->xid    = req->xid;
    resp->secs   = 0;
    resp->flags  = req->flags;
    resp->ciaddr = req->ciaddr;
    resp->yiaddr = 0;
    resp->siaddr = 0;
    resp->giaddr = req->giaddr;
    memcpy(resp->chaddr, req->chaddr, 16);
    memset(resp->sname, 0, sizeof(resp->sname));
    memset(resp->file,  0, sizeof(resp->file));
    resp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);
}

/* OFFER and ACK have almost identical option sets — the only difference is
 * the message type value in option 53.  msg_type picks which one. */
static int build_offer_ack_common(struct dhcp_packet *resp,
                                  struct dhcp_packet *req,
                                  dhcp_options_t *opts,
                                  dhcp_config_t *config,
                                  size_t *pkt_len,
                                  uint8_t msg_type) {
    memset(resp, 0, sizeof(*resp));
    fill_common_fields(resp, req);

    char mac_str[MAC_STR_LEN];
    format_mac_address(req->chaddr, mac_str, sizeof(mac_str));

    char *addr = allocate_ip_address(mac_str, opts, config);
    if (!addr) {
        syslog(LOG_ERR, "Failed to allocate IP for %s",
               msg_type == DHCPOFFER ? "OFFER" : "ACK");
        return -1;
    }
    resp->yiaddr = inet_addr(addr);

    uint8_t *opt     = resp->options;
    uint8_t *opt_end = resp->options + sizeof(resp->options);

    ADD_OPTION_U8(53, msg_type);

    uint32_t server = inet_addr(config->server_ip);
    ADD_OPTION_U32(54, server);
    ADD_OPTION_U32(1,  inet_addr(config->subnet_mask));
    ADD_OPTION_U32(3,  inet_addr(config->gateway));

    /* Option 6: DNS servers */
    if (config->dns_count > 0 && config->dns_servers[0]) {
        uint8_t dns_buf[8];
        uint32_t dns1 = inet_addr(config->dns_servers[0]);
        memcpy(dns_buf, &dns1, 4);
        int dns_len = 4;
        if (config->dns_count >= 2 && config->dns_servers[1]) {
            uint32_t dns2 = inet_addr(config->dns_servers[1]);
            memcpy(dns_buf + 4, &dns2, 4);
            dns_len = 8;
        }
        ADD_OPTION(6, dns_len, dns_buf);
    }

    /* Option 28: Broadcast address */
    {
        uint32_t bcast = inet_addr(addr) | ~inet_addr(config->subnet_mask);
        ADD_OPTION_U32(28, bcast);
    }

    /* Option 15: Domain name */
    const char *domain = config->domain_name ? config->domain_name : "";
    if (domain[0] != '\0')
        ADD_OPTION(15, strlen(domain), domain);

    /* Option 12: Hostname — echo client's or generate a default */
    if (opts->found_hostname && opts->hostname[0] != '\0') {
        uint8_t hn = (uint8_t)strlen(opts->hostname);
        if (hn > 0 && hn < 64) ADD_OPTION(12, hn, opts->hostname);
    } else {
        char dflt[64];
        const char *pfx = (domain[0] != '\0') ? domain : "dhcp";
        snprintf(dflt, sizeof(dflt), "%s-%02X%02X%02X",
                 pfx, req->chaddr[3], req->chaddr[4], req->chaddr[5]);
        ADD_OPTION(12, strlen(dflt), dflt);
    }

    /* Lease time (opt 51), renewal time T1 at 50% (opt 58), rebind time T2 at 87.5% (opt 59) */
    ADD_OPTION_U32(51, htonl(config->lease_time));
    ADD_OPTION_U32(58, htonl(config->lease_time / 2));
    ADD_OPTION_U32(59, htonl((config->lease_time * 7) / 8));

    /* Send any optional options the client explicitly asked for */
    for (int i = 0; i < opts->parameter_list_len; i++) {
        switch (opts->parameter_list[i]) {
            case 28: break;  /* broadcast address — already sent above */
            case 42: ADD_OPTION_U32(42, server); break;  /* NTP — point at ourselves */
        }
    }

    if (opt >= opt_end) {
        syslog(LOG_ERR, "No space for End option in %s",
               msg_type == DHCPOFFER ? "OFFER" : "ACK");
        free(addr);
        return -1;
    }
    *opt++ = 255;

    *pkt_len = (size_t)((uint8_t *)opt - (uint8_t *)resp);
    syslog(LOG_DEBUG, "Built %s: %zu bytes",
           msg_type == DHCPOFFER ? "OFFER" : "ACK", *pkt_len);
    free(addr);
    return 0;
}

int build_offer(struct dhcp_packet *resp, struct dhcp_packet *req,
                dhcp_options_t *opts, dhcp_config_t *config,
                size_t *pkt_len) {
    return build_offer_ack_common(resp, req, opts, config, pkt_len, DHCPOFFER);
}

int build_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
              dhcp_options_t *opts, dhcp_config_t *config,
              size_t *pkt_len) {
    return build_offer_ack_common(resp, req, opts, config, pkt_len, DHCPACK);
}

int build_nak(struct dhcp_packet *resp, struct dhcp_packet *req,
              dhcp_config_t *config, size_t *pkt_len) {
    memset(resp, 0, sizeof(*resp));
    resp->op     = 2;
    resp->htype  = req->htype;
    resp->hlen   = req->hlen;
    resp->hops   = 0;
    resp->xid    = req->xid;
    resp->secs   = 0;
    resp->flags  = req->flags;
    resp->giaddr = req->giaddr;
    memcpy(resp->chaddr, req->chaddr, 16);
    resp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *opt     = resp->options;
    uint8_t *opt_end = resp->options + sizeof(resp->options);

    NOADDR_U8(53, DHCPNAK);
    NOADDR_U32(54, inet_addr(config->server_ip));

    if (opt >= opt_end) return -1;
    *opt++ = 255;

    *pkt_len = (size_t)((uint8_t *)opt - (uint8_t *)resp);
    syslog(LOG_DEBUG, "Built NAK: %zu bytes", *pkt_len);
    return 0;
}

int build_inform_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
                     dhcp_options_t *opts, dhcp_config_t *config,
                     size_t *pkt_len) {
    memset(resp, 0, sizeof(*resp));
    resp->op     = 2;
    resp->htype  = req->htype;
    resp->hlen   = req->hlen;
    resp->hops   = 0;
    resp->xid    = req->xid;
    resp->secs   = 0;
    resp->flags  = req->flags;
    resp->ciaddr = req->ciaddr;  /* echo ciaddr; yiaddr stays 0 */
    resp->giaddr = req->giaddr;
    memcpy(resp->chaddr, req->chaddr, 16);
    resp->magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *opt     = resp->options;
    uint8_t *opt_end = resp->options + sizeof(resp->options);

    NOADDR_U8(53, DHCPACK);

    uint32_t server = inet_addr(config->server_ip);
    NOADDR_U32(54, server);
    NOADDR_U32(1,  inet_addr(config->subnet_mask));
    NOADDR_U32(3,  inet_addr(config->gateway));

    /* Option 6: DNS servers */
    if (config->dns_count > 0 && config->dns_servers[0]) {
        uint8_t dns_buf[8];
        uint32_t dns1 = inet_addr(config->dns_servers[0]);
        memcpy(dns_buf, &dns1, 4);
        int dns_len = 4;
        if (config->dns_count >= 2 && config->dns_servers[1]) {
            uint32_t dns2 = inet_addr(config->dns_servers[1]);
            memcpy(dns_buf + 4, &dns2, 4);
            dns_len = 8;
        }
        if (opt + 2 + dns_len <= opt_end) {
            *opt++ = 6;
            *opt++ = (uint8_t)dns_len;
            memcpy(opt, dns_buf, dns_len);
            opt += dns_len;
        }
    }

    /* Option 28: Broadcast address */
    {
        uint32_t bcast = req->ciaddr | ~inet_addr(config->subnet_mask);
        NOADDR_U32(28, bcast);
    }

    /* Option 15: Domain name */
    const char *domain = config->domain_name ? config->domain_name : "";
    if (domain[0] != '\0' && opt + 2 + strlen(domain) <= opt_end) {
        *opt++ = 15;
        *opt++ = (uint8_t)strlen(domain);
        memcpy(opt, domain, strlen(domain));
        opt += strlen(domain);
    }

    /* Send any optional options the client asked for */
    for (int i = 0; i < opts->parameter_list_len; i++) {
        switch (opts->parameter_list[i]) {
            case 42: NOADDR_U32(42, server); break;  /* NTP */
        }
    }

    if (opt >= opt_end) return -1;
    *opt++ = 255;

    *pkt_len = (size_t)((uint8_t *)opt - (uint8_t *)resp);
    syslog(LOG_DEBUG, "Built INFORM ACK: %zu bytes", *pkt_len);
    return 0;
}

#undef ADD_OPTION
#undef ADD_OPTION_U8
#undef ADD_OPTION_U32
#undef NOADDR_U8
#undef NOADDR_U32
