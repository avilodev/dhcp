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

/* Variants for build_nak / build_inform_ack that don't free(addr) */
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

/* --------------------------------------------------------------------------
 * build_offer
 * -------------------------------------------------------------------------- */
int build_offer(struct dhcp_packet *resp, struct dhcp_packet *req,
                dhcp_options_t *opts, dhcp_config_t *config,
                size_t *pkt_len) {
    memset(resp, 0, sizeof(*resp));
    fill_common_fields(resp, req);

    char mac_str[MAC_STR_LEN];
    format_mac_address(req->chaddr, mac_str, sizeof(mac_str));

    char *addr = allocate_ip_address(mac_str, opts, config);
    if (!addr) {
        syslog(LOG_ERR, "Failed to allocate IP for OFFER");
        return -1;
    }
    resp->yiaddr = inet_addr(addr);

    uint8_t *opt     = resp->options;
    uint8_t *opt_end = resp->options + sizeof(resp->options);

    /* Option 53 MUST come first (RFC 2132 §9.6) */
    ADD_OPTION_U8(53, DHCPOFFER);

    uint32_t server = inet_addr(config->server_ip);
    ADD_OPTION_U32(54, server);                          /* Server ID   */
    ADD_OPTION_U32(1,  inet_addr(config->subnet_mask));  /* Subnet Mask */
    ADD_OPTION_U32(3,  inet_addr(config->gateway));      /* Router      */
    ADD_OPTION_U32(6,  inet_addr(config->dns_servers[0])); /* DNS       */

    /* Option 28: Broadcast Address */
    {
        uint32_t bcast = resp->yiaddr | ~inet_addr(config->subnet_mask);
        ADD_OPTION_U32(28, bcast);
    }

    const char *domain = config->domain_name ? config->domain_name : "";
    if (domain[0] != '\0')
        ADD_OPTION(15, strlen(domain), domain);

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

    ADD_OPTION_U32(51, htonl(config->lease_time));
    ADD_OPTION_U32(58, htonl(config->lease_time / 2));
    ADD_OPTION_U32(59, htonl((config->lease_time * 7) / 8));

    for (int i = 0; i < opts->parameter_list_len; i++) {
        switch (opts->parameter_list[i]) {
            case 28: break;                          /* already sent */
            case 42: ADD_OPTION_U32(42, server); break;  /* NTP */
        }
    }

    if (opt >= opt_end) {
        syslog(LOG_ERR, "No space for End option in OFFER");
        free(addr);
        return -1;
    }
    *opt++ = 255;

    *pkt_len = (size_t)((uint8_t *)opt - (uint8_t *)resp);
    syslog(LOG_DEBUG, "Built OFFER: %zu bytes", *pkt_len);
    free(addr);
    return 0;
}

/* --------------------------------------------------------------------------
 * build_ack
 * -------------------------------------------------------------------------- */
int build_ack(struct dhcp_packet *resp, struct dhcp_packet *req,
              dhcp_options_t *opts, dhcp_config_t *config,
              size_t *pkt_len) {
    memset(resp, 0, sizeof(*resp));
    fill_common_fields(resp, req);

    char mac_str[MAC_STR_LEN];
    format_mac_address(req->chaddr, mac_str, sizeof(mac_str));

    char *addr = allocate_ip_address(mac_str, opts, config);
    if (!addr) {
        syslog(LOG_ERR, "Failed to allocate IP for ACK");
        return -1;
    }
    resp->yiaddr = inet_addr(addr);

    uint8_t *opt     = resp->options;
    uint8_t *opt_end = resp->options + sizeof(resp->options);

    ADD_OPTION_U8(53, DHCPACK);

    uint32_t server = inet_addr(config->server_ip);
    ADD_OPTION_U32(54, server);
    ADD_OPTION_U32(1,  inet_addr(config->subnet_mask));
    ADD_OPTION_U32(3,  inet_addr(config->gateway));
    ADD_OPTION_U32(6,  inet_addr(config->dns_servers[0]));

    {
        uint32_t bcast = inet_addr(addr) | ~inet_addr(config->subnet_mask);
        ADD_OPTION_U32(28, bcast);
    }

    const char *domain = config->domain_name ? config->domain_name : "";
    if (domain[0] != '\0')
        ADD_OPTION(15, strlen(domain), domain);

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

    ADD_OPTION_U32(51, htonl(config->lease_time));
    ADD_OPTION_U32(58, htonl(config->lease_time / 2));
    ADD_OPTION_U32(59, htonl((config->lease_time * 7) / 8));

    for (int i = 0; i < opts->parameter_list_len; i++) {
        switch (opts->parameter_list[i]) {
            case 28: break;
            case 42: ADD_OPTION_U32(42, server); break;
        }
    }

    if (opt >= opt_end) {
        syslog(LOG_ERR, "No space for End option in ACK");
        free(addr);
        return -1;
    }
    *opt++ = 255;

    *pkt_len = (size_t)((uint8_t *)opt - (uint8_t *)resp);
    syslog(LOG_DEBUG, "Built ACK: %zu bytes", *pkt_len);
    free(addr);
    return 0;
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
    NOADDR_U32(6,  inet_addr(config->dns_servers[0]));

    {
        uint32_t bcast = req->ciaddr | ~inet_addr(config->subnet_mask);
        NOADDR_U32(28, bcast);
    }

    const char *domain = config->domain_name ? config->domain_name : "";
    if (opt + 2 + strlen(domain) <= opt_end) {
        *opt++ = 15;
        *opt++ = (uint8_t)strlen(domain);
        memcpy(opt, domain, strlen(domain));
        opt += strlen(domain);
    }

    for (int i = 0; i < opts->parameter_list_len; i++) {
        switch (opts->parameter_list[i]) {
            case 42: NOADDR_U32(42, server); break;
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
