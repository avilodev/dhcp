#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "utils.h"
#include <time.h>

/* Generate a consistent identifier for a device */
char *get_device_identifier(const char *mac, dhcp_options_t *opts, char *buffer, size_t buflen) {
    if (opts && opts->found_client_id && opts->client_id_len > 0) {
        size_t hex_len = opts->client_id_len * 2 + 1;
        if (hex_len > buflen) {
            hex_len = buflen;
        }
        
        for (size_t i = 0; i < opts->client_id_len && (i * 2 + 2) < buflen; i++) {
            snprintf(buffer + (i * 2), 3, "%02X", opts->client_id[i]);
        }
        buffer[hex_len - 1] = '\0'; 
        
        syslog(LOG_DEBUG, "Using Client ID for device: %s (MAC: %s)", buffer, mac);
        return buffer;
    }
    
    strncpy(buffer, mac, buflen - 1);
    buffer[buflen - 1] = '\0';
    return buffer;
}

char *allocate_ip_address(const char *mac, dhcp_options_t *opts, dhcp_config_t *config) {
    if (!mac || !config) {
        syslog(LOG_ERR, "allocate_ip_address: NULL parameter");
        return NULL;
    }
    
    if (!config->mac_table || !config->ip_table) {
        syslog(LOG_ERR, "allocate_ip_address: Data structures not initialized");
        return NULL;
    }
    
    char device_id[256];
    get_device_identifier(mac, opts, device_id, sizeof(device_id));
    
    /* COLLISION DETECTION */
    if (opts && opts->found_client_id) {
        struct Tree_Node *mac_node = find_node(config->mac_table, hash_string((char *)mac));
        struct Tree_Node *id_node = find_node(config->mac_table, hash_string(device_id));
        
        if (mac_node && id_node && mac_node != id_node) {
            syslog(LOG_WARNING, "Client ID collision detected: MAC %s has different lease than Client ID %s", 
                mac, device_id);
            // Prefer Client ID, free MAC lease
            if (mac_node->ip) {
                free(mac_node->ip);
                mac_node->ip = NULL;
            }
        }
    }
    
    /* Check for existing lease */
    char *existing = find_existing_lease(device_id, config);
    if (existing) {
        syslog(LOG_DEBUG, "Reusing existing IP %s for device %s (MAC: %s)", 
               existing, device_id, mac);
        return existing;
    }

    /* Check for static assignment */
    char *static_ip = check_static_assignment(mac, config);
    if (static_ip) {
        syslog(LOG_INFO, "Using static assignment %s for MAC %s", static_ip, mac);
        
        struct Tree_Node *node = find_node(config->mac_table, hash_string(device_id));
        if (!node) {
            char *ip_copy = strdup(static_ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, hash_string(device_id), ip_copy);
            }
        }
        if (!test_ip(config->ip_table, static_ip)) {
            add_word(config->ip_table, static_ip);
        }
        return static_ip;
    }

    /* Allocate new IP */
    char *new_ip = find_free_ip(config);
    if (new_ip) {
        struct Tree_Node *node = find_node(config->mac_table, hash_string(device_id));
        if (!node) {
            char *ip_copy = strdup(new_ip);
            if (!ip_copy) {
                free(new_ip);
                return NULL;
            }
            add_tree_node(config->mac_table, hash_string(device_id), ip_copy);
        }
        syslog(LOG_INFO, "Allocated new IP %s for device %s (MAC: %s)", 
               new_ip, device_id, mac);
    }
    return new_ip;
}

char *find_existing_lease(const char *device_id, dhcp_config_t *config) {
    if (!device_id || !config || !config->mac_table) {
        return NULL;
    }
    
    unsigned long hash = hash_string((char *)device_id);
    struct Tree_Node *node = find_node(config->mac_table, hash);
    
    if (node && node->ip) {
        return strdup(node->ip);
    }
    return NULL;
}

char *check_static_assignment(const char *mac, dhcp_config_t *config) {
    (void)config;
    
    char static_file_path[256];
    snprintf(static_file_path, sizeof(static_file_path), "%s%s", SERVER_PATH, STATIC_FILE);
    
    int fd = open(static_file_path, O_RDONLY);
    if (fd < 0) {
        return NULL;
    }

    char *buffer = malloc(MAXLINE);
    if (!buffer) {
        close(fd);
        return NULL;
    }
    
    ssize_t bytes_read = read(fd, buffer, MAXLINE - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        free(buffer);
        return NULL;
    }
    buffer[bytes_read] = '\0';

    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);
    char *result = NULL;

    while (line != NULL) {
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
        char *ip = strtok(NULL, " \t\r\n");

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
    if (!config || !config->start_ip || !config->end_ip) {
        return NULL;
    }
    
    int start_octet[4], end_octet[4];
    
    if (sscanf(config->start_ip, "%d.%d.%d.%d",
               &start_octet[0], &start_octet[1], &start_octet[2], &start_octet[3]) != 4) {
        syslog(LOG_ERR, "Invalid start IP format: %s", config->start_ip);
        return NULL;
    }

    if (sscanf(config->end_ip, "%d.%d.%d.%d",
               &end_octet[0], &end_octet[1], &end_octet[2], &end_octet[3]) != 4) {
        syslog(LOG_ERR, "Invalid end IP format: %s", config->end_ip);
        return NULL;
    }

    char *new_ip = malloc(IP_STR_LEN);
    if (!new_ip) {
        syslog(LOG_ERR, "Failed to allocate memory for IP string");
        return NULL;
    }

    if (!config->ip_table) {
        free(new_ip);
        return NULL;
    }

    int attempts = 0;
    const int MAX_ATTEMPTS = 1000;
    
    while (attempts++ < MAX_ATTEMPTS) {
        int octet[4];
        
        for (int i = 0; i < 4; i++) {
            if (end_octet[i] == start_octet[i]) {
                octet[i] = start_octet[i];
            } else {
                int range = end_octet[i] - start_octet[i] + 1;
                octet[i] = (rand() % range) + start_octet[i];
            }
        }

        snprintf(new_ip, IP_STR_LEN, "%d.%d.%d.%d", octet[0], octet[1], octet[2], octet[3]);
        
        if (!test_ip(config->ip_table, new_ip)) {
            add_word(config->ip_table, new_ip);
            return new_ip;
        }
    }

    free(new_ip);
    syslog(LOG_ERR, "Failed to find free IP after %d attempts", MAX_ATTEMPTS);
    return NULL;
}

int release_ip_address(const char *mac, dhcp_config_t *config) {
    struct Tree_Node *node = find_node(config->mac_table, hash_string((char *)mac));
    if (node && node->ip) {
        syslog(LOG_INFO, "Released IP %s for MAC %s", node->ip, mac);
        
        /* Free the IP string */
        if (node->ip) {
            free(node->ip);
            node->ip = NULL;
        }
        return 0;
    }
    syslog(LOG_WARNING, "Attempted to release IP for unknown MAC: %s", mac);
    return -1;
}

int mark_ip_declined(uint32_t ip, dhcp_config_t *config) {
    struct in_addr addr;
    addr.s_addr = ip;
    char *ip_str = inet_ntoa(addr);
    
    add_word(config->ip_table, ip_str);
    syslog(LOG_WARNING, "IP %s marked as declined", ip_str);
    return 0;
}

bool is_ip_available(const char *ip, dhcp_config_t *config) {
    return !test_ip(config->ip_table, (char *)ip);
}

bool validate_mac_address(const char *mac) {
    if (!mac) return false;
    
    int parts[6];
    int matched = sscanf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                        &parts[0], &parts[1], &parts[2],
                        &parts[3], &parts[4], &parts[5]);
    
    if (matched != 6) {
        matched = sscanf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        &parts[0], &parts[1], &parts[2],
                        &parts[3], &parts[4], &parts[5]);
    }
    
    return matched == 6;
}

char *format_timestamp(time_t t) {
    struct tm *tm = gmtime(&t);
    if (!tm) return NULL;
    
    char *str = malloc(64);
    if (str) {
        if (strftime(str, 64, "%a, %d %b %Y %H:%M:%S GMT", tm) == 0) {
            free(str);
            return NULL;
        }
    }
    return str;
}

time_t parse_timestamp(const char *str) {
    if (!str) return 0;
    
    struct tm tm = {0};
    char *result = strptime(str, "%a, %d %b %Y %H:%M:%S GMT", &tm);
    if (result == NULL) {
        return 0;
    }
    
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
    const char *ip_str = inet_ntoa(addr);
    
    strncpy(buf, ip_str, buflen - 1);
    buf[buflen - 1] = '\0';
}

void format_mac_address(const uint8_t *mac, char *buf, size_t buflen) {
    if (!mac || !buf || buflen < MAC_STR_LEN) return;
    
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}