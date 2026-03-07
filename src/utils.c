#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "utils.h"
#include <time.h>

/* How long we hold an IP after sending an OFFER before giving up on the client.
 * If the DHCPREQUEST never comes, the slot gets reclaimed on the next sweep. */
#define OFFER_TENTATIVE_SECS 60

char *get_device_identifier(const char *mac, dhcp_options_t *opts,
                            char *buffer, size_t buflen) {
    if (opts && opts->found_client_id && opts->client_id_len > 0) {
        size_t hex_len = opts->client_id_len * 2 + 1;
        if (hex_len > buflen)
            hex_len = buflen;

        for (size_t i = 0; i < opts->client_id_len && (i * 2 + 2) < buflen; i++)
            snprintf(buffer + (i * 2), 3, "%02X", opts->client_id[i]);
        buffer[hex_len - 1] = '\0';

        syslog(LOG_DEBUG, "Using Client ID for device: %s (MAC: %s)", buffer, mac);
        return buffer;
    }

    strncpy(buffer, mac, buflen - 1);
    buffer[buflen - 1] = '\0';
    return buffer;
}

char *allocate_ip_address(const char *mac, dhcp_options_t *opts,
                          dhcp_config_t *config) {
    if (!mac || !config) {
        syslog(LOG_ERR, "allocate_ip_address: NULL parameter");
        return NULL;
    }
    if (!config->mac_table || !config->ip_table) {
        syslog(LOG_ERR, "allocate_ip_address: data structures not initialised");
        return NULL;
    }

    char device_id[256];
    get_device_identifier(mac, opts, device_id, sizeof(device_id));

    /* If the same hardware address has somehow ended up with two different
     * lease entries (one by MAC, one by Client-ID), clean up the stale one */
    if (opts && opts->found_client_id) {
        struct Tree_Node *mac_node = find_node(config->mac_table, mac);
        struct Tree_Node *id_node  = find_node(config->mac_table, device_id);
        if (mac_node && id_node && mac_node != id_node) {
            syslog(LOG_WARNING,
                   "Client-ID collision: MAC %s has different lease than "
                   "Client ID %s", mac, device_id);
            if (mac_node->ip) {
                remove_word(config->ip_table, mac_node->ip);
                free(mac_node->ip);
                mac_node->ip = NULL;
            }
        }
    }

    /* If this device already has a valid lease, hand the same IP back */
    char *existing = find_existing_lease(device_id, config);
    if (existing) {
        syslog(LOG_DEBUG, "Reusing IP %s for device %s (MAC: %s)",
               existing, device_id, mac);
        return existing;
    }

    /* Static assignments always win over the dynamic pool */
    char *static_ip = check_static_assignment(mac, config);
    if (static_ip) {
        syslog(LOG_INFO, "Using static assignment %s for MAC %s",
               static_ip, mac);
        if (!find_node(config->mac_table, device_id)) {
            char *ip_copy = strdup(static_ip);
            if (ip_copy)
                add_tree_node(config->mac_table, device_id,
                              ip_copy, 0 /* static: no expiry */);
        }
        if (!test_ip(config->ip_table, static_ip))
            add_word(config->ip_table, static_ip);
        return static_ip;
    }

    /* New device — find a free IP.  Short expiry means if the client goes
     * silent the slot comes back after OFFER_TENTATIVE_SECS seconds. */
    char *new_ip = find_free_ip(config);
    if (new_ip) {
        struct Tree_Node *existing_node = find_node(config->mac_table, device_id);
        if (!existing_node) {
            char *ip_copy = strdup(new_ip);
            if (!ip_copy) {
                free(new_ip);
                return NULL;
            }
            add_tree_node(config->mac_table, device_id,
                          ip_copy, time(NULL) + OFFER_TENTATIVE_SECS);
        } else if (!existing_node->ip) {
            /* Node exists (from a prior DECLINE or RELEASE) but has no IP — fill it in */
            existing_node->ip      = strdup(new_ip);
            existing_node->expires = time(NULL) + OFFER_TENTATIVE_SECS;
        }
        syslog(LOG_INFO, "Allocated new IP %s for device %s (MAC: %s)",
               new_ip, device_id, mac);
    }
    return new_ip;
}

/* Returns the device's current IP, or NULL if it doesn't have one or
 * the lease expired.  Reclaims the slot on expiry so the pool stays healthy. */
char *find_existing_lease(const char *device_id, dhcp_config_t *config) {
    if (!device_id || !config || !config->mac_table)
        return NULL;

    struct Tree_Node *node = find_node(config->mac_table, device_id);
    if (!node || !node->ip)
        return NULL;

    if (node->expires > 0 && node->expires <= time(NULL)) {
        syslog(LOG_INFO, "Lease for device %s (IP %s) expired — reclaiming",
               device_id, node->ip);
        remove_word(config->ip_table, node->ip);
        free(node->ip);
        node->ip      = NULL;
        node->expires = 0;
        return NULL;
    }

    return strdup(node->ip);
}

/* Static assignments have expires=0 so they're easy to identify.  They're
 * already in memory from startup, so no file access needed here. */
char *check_static_assignment(const char *mac, dhcp_config_t *config) {
    if (!mac || !config || !config->mac_table) return NULL;

    struct Tree_Node *node = find_node(config->mac_table, mac);
    if (node && node->ip && node->expires == 0)
        return strdup(node->ip);

    return NULL;
}

char *find_free_ip(dhcp_config_t *config) {
    if (!config || !config->start_ip || !config->end_ip || !config->ip_table)
        return NULL;

    uint32_t start = ntohl(inet_addr(config->start_ip));
    uint32_t end   = ntohl(inet_addr(config->end_ip));
    if (start == INADDR_NONE || end == INADDR_NONE || start > end) {
        syslog(LOG_ERR, "Invalid IP range: %s – %s",
               config->start_ip, config->end_ip);
        return NULL;
    }

    uint32_t pool_size = end - start + 1;

    /* Random start so devices can't predict what IP they'll get next time */
    uint32_t offset = (uint32_t)rand() % pool_size;

    char *new_ip = malloc(IP_STR_LEN);
    if (!new_ip) return NULL;

    for (uint32_t i = 0; i < pool_size; i++) {
        uint32_t v = start + ((offset + i) % pool_size);
        snprintf(new_ip, IP_STR_LEN, "%u.%u.%u.%u",
                 (v >> 24) & 0xFF, (v >> 16) & 0xFF,
                 (v >>  8) & 0xFF,  v        & 0xFF);
        if (!test_ip(config->ip_table, new_ip)) {
            add_word(config->ip_table, new_ip);
            return new_ip;
        }
    }

    free(new_ip);
    syslog(LOG_ERR, "No free IP address in range %s – %s",
           config->start_ip, config->end_ip);
    return NULL;
}

int release_ip_address(const char *device_id, dhcp_config_t *config) {
    if (!device_id || !config) return -1;

    struct Tree_Node *node = find_node(config->mac_table, device_id);
    if (node && node->ip) {
        syslog(LOG_INFO, "Released IP %s for device %s",
               node->ip, device_id);
        remove_word(config->ip_table, node->ip);
        free(node->ip);
        node->ip      = NULL;
        node->expires = 0;
        return 0;
    }
    syslog(LOG_WARNING, "Release for unknown device: %s", device_id);
    return -1;
}

int mark_ip_declined(uint32_t ip, const char *device_id,
                     dhcp_config_t *config) {
    struct in_addr addr;
    addr.s_addr = ip;
    char ip_str[IP_STR_LEN];
    inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

    /* Permanently reserve this IP — something on the network already owns it
     * so we should never offer it to anyone again */
    add_word(config->ip_table, ip_str);
    syslog(LOG_WARNING, "IP %s marked as declined (ARP conflict)", ip_str);

    /* Wipe the device's IP slot so its next DISCOVER gets a different address */
    if (device_id) {
        struct Tree_Node *node = find_node(config->mac_table, device_id);
        if (node && node->ip) {
            free(node->ip);
            node->ip      = NULL;
            node->expires = 0;
        }
    }
    return 0;
}

int update_lease_expiry(const char *device_id, time_t expires,
                        dhcp_config_t *config) {
    if (!device_id || !config || !config->mac_table) return -1;

    struct Tree_Node *node = find_node(config->mac_table, device_id);
    if (!node) return -1;

    node->expires = expires;
    return 0;
}

static void sweep_node(struct Tree_Node *node, struct Trie *ip_table, time_t now) {
    if (!node) return;
    sweep_node(node->left, ip_table, now);
    sweep_node(node->right, ip_table, now);
    /* Walk this BST node and anything chained off it (hash collisions) */
    for (struct Tree_Node *n = node; n; n = n->chain) {
        if (n->ip && n->expires > 0 && n->expires <= now) {
            remove_word(ip_table, n->ip);
            free(n->ip);
            n->ip      = NULL;
            n->expires = 0;
        }
    }
}

void sweep_expired_leases(dhcp_config_t *config) {
    if (!config || !config->mac_table || !config->ip_table) return;
    sweep_node(config->mac_table->head, config->ip_table, time(NULL));
    syslog(LOG_DEBUG, "Expired lease sweep complete");
}

bool is_ip_available(const char *ip, dhcp_config_t *config) {
    return !test_ip(config->ip_table, (char *)ip);
}

bool validate_mac_address(const char *mac) {
    if (!mac) return false;
    int parts[6];
    int matched = sscanf(mac,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        &parts[0], &parts[1], &parts[2],
        &parts[3], &parts[4], &parts[5]);
    if (matched != 6)
        matched = sscanf(mac,
            "%02x:%02x:%02x:%02x:%02x:%02x",
            &parts[0], &parts[1], &parts[2],
            &parts[3], &parts[4], &parts[5]);
    return matched == 6;
}

char *format_timestamp(time_t t) {
    struct tm tm_buf;
    struct tm *tm = gmtime_r(&t, &tm_buf);
    if (!tm) return NULL;
    char *str = malloc(64);
    if (str && strftime(str, 64, "%a, %d %b %Y %H:%M:%S GMT", tm) == 0) {
        free(str);
        return NULL;
    }
    return str;
}

time_t parse_timestamp(const char *str) {
    if (!str) return 0;
    struct tm tm = {0};
    char *result = strptime(str, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (!result) return 0;
#ifdef __USE_MISC
    return timegm(&tm);
#else
    time_t t = mktime(&tm);
    if (t == -1) return 0;
    struct tm *local = localtime(&t);
    if (!local) return 0;
    time_t local_t = mktime(local);
    return t + (t - local_t);
#endif
}

uint32_t ip_string_to_uint32(const char *ip) {
    if (!ip) return 0;
    return inet_addr(ip);
}

void uint32_to_ip_string(uint32_t ip, char *buf, size_t buflen) {
    if (!buf || buflen == 0) return;
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, (socklen_t)buflen);
}

void format_mac_address(const uint8_t *mac, char *buf, size_t buflen) {
    if (!mac || !buf || buflen < MAC_STR_LEN) return;
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
