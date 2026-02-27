#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "utils.h"
#include <time.h>

/* Tentative reservation lifetime (seconds).  An IP offered in a DHCPOFFER
 * but never confirmed by a DHCPREQUEST is automatically freed after this. */
#define OFFER_TENTATIVE_SECS 30

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

    /* Collision detection: same MAC and Client-ID map to different nodes */
    if (opts && opts->found_client_id) {
        struct Tree_Node *mac_node = find_node(config->mac_table,
                                               hash_string(mac));
        struct Tree_Node *id_node  = find_node(config->mac_table,
                                               hash_string(device_id));
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

    /* Check for existing (non-expired) lease */
    char *existing = find_existing_lease(device_id, config);
    if (existing) {
        syslog(LOG_DEBUG, "Reusing IP %s for device %s (MAC: %s)",
               existing, device_id, mac);
        return existing;
    }

    /* Check for static assignment (never expires) */
    char *static_ip = check_static_assignment(mac, config);
    if (static_ip) {
        syslog(LOG_INFO, "Using static assignment %s for MAC %s",
               static_ip, mac);
        if (!find_node(config->mac_table, hash_string(device_id))) {
            char *ip_copy = strdup(static_ip);
            if (ip_copy)
                add_tree_node(config->mac_table, hash_string(device_id),
                              ip_copy, 0 /* static: no expiry */);
        }
        if (!test_ip(config->ip_table, static_ip))
            add_word(config->ip_table, static_ip);
        return static_ip;
    }

    /* Allocate new IP with a short tentative expiry.
     * If the client never sends a DHCPREQUEST the slot is freed after
     * OFFER_TENTATIVE_SECS seconds so the pool does not fill up. */
    char *new_ip = find_free_ip(config);
    if (new_ip) {
        if (!find_node(config->mac_table, hash_string(device_id))) {
            char *ip_copy = strdup(new_ip);
            if (!ip_copy) {
                free(new_ip);
                return NULL;
            }
            add_tree_node(config->mac_table, hash_string(device_id),
                          ip_copy, time(NULL) + OFFER_TENTATIVE_SECS);
        }
        syslog(LOG_INFO, "Allocated new IP %s for device %s (MAC: %s)",
               new_ip, device_id, mac);
    }
    return new_ip;
}

/* Returns a strdup'd copy of the IP, or NULL if not found / expired.
 * Expired leases are reclaimed here so the pool stays healthy. */
char *find_existing_lease(const char *device_id, dhcp_config_t *config) {
    if (!device_id || !config || !config->mac_table)
        return NULL;

    struct Tree_Node *node = find_node(config->mac_table,
                                       hash_string(device_id));
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

char *check_static_assignment(const char *mac, dhcp_config_t *config) {
    (void)config;

    char static_file_path[256];
    snprintf(static_file_path, sizeof(static_file_path), "%s%s",
             SERVER_PATH, STATIC_FILE);

    int fd = open(static_file_path, O_RDONLY);
    if (fd < 0) return NULL;

    char *buffer = malloc(MAXLINE);
    if (!buffer) { close(fd); return NULL; }

    ssize_t bytes_read = read(fd, buffer, MAXLINE - 1);
    close(fd);
    if (bytes_read <= 0) { free(buffer); return NULL; }
    buffer[bytes_read] = '\0';

    char *save_ptr;
    char *line   = strtok_r(buffer, "\n", &save_ptr);
    char *result = NULL;

    while (line) {
        if (line[0] == '#' || line[0] == '\0' || line[0] == '\n') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        char line_copy[256];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *token = strtok(line_copy, " \t");
        if (!token || strcmp(token, "device") != 0) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        char *file_mac = strtok(NULL, " \t");
        char *ip       = strtok(NULL, " \t\r\n");

        if (file_mac && ip && strcasecmp(mac, file_mac) == 0) {
            result = strdup(ip);
            break;
        }
        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    return result;
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

    char *new_ip = malloc(IP_STR_LEN);
    if (!new_ip) return NULL;

    for (uint32_t v = start; v <= end; v++) {
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

    struct Tree_Node *node = find_node(config->mac_table,
                                       hash_string(device_id));
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
    strncpy(ip_str, inet_ntoa(addr), IP_STR_LEN - 1);
    ip_str[IP_STR_LEN - 1] = '\0';

    /* Keep the IP permanently reserved so it is never re-offered */
    add_word(config->ip_table, ip_str);
    syslog(LOG_WARNING, "IP %s marked as declined (ARP conflict)", ip_str);

    /* Clear the device's mac_table entry so it receives a fresh IP */
    if (device_id) {
        struct Tree_Node *node = find_node(config->mac_table,
                                           hash_string(device_id));
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

    struct Tree_Node *node = find_node(config->mac_table,
                                       hash_string(device_id));
    if (!node) return -1;

    node->expires = expires;
    return 0;
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
    struct tm *tm = gmtime(&t);
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
    strncpy(buf, inet_ntoa(addr), buflen - 1);
    buf[buflen - 1] = '\0';
}

void format_mac_address(const uint8_t *mac, char *buf, size_t buflen) {
    if (!mac || !buf || buflen < MAC_STR_LEN) return;
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
