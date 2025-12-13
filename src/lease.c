#include "lease.h"

extern char *get_device_identifier(const char *mac, dhcp_options_t *opts, char *buffer, size_t buflen);

/* Load lease database from members.txt */
int load_lease_database(dhcp_config_t *config) {
    char lease_db_file[256];
    snprintf(lease_db_file, sizeof(lease_db_file), "%s%s", SERVER_PATH, LEASE_DB_FILE);
    
    int fd = open(lease_db_file, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_INFO, "No existing lease database found");
        return 0;
    }

    char *buffer = malloc(MAXLINE * 4);
    if (!buffer) {
        close(fd);
        syslog(LOG_ERR, "Failed to allocate buffer for lease database");
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, MAXLINE * 4 - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        free(buffer);
        return 0;
    }
    buffer[bytes_read] = '\0';

    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);
    int loaded = 0;

    while (line != NULL) {
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }
        
        // Format: device_id mac ip [hostname] 
        char device_id[256], mac[MAC_STR_LEN], ip[IP_STR_LEN], hostname[256];
        hostname[0] = '\0';
        
        // Try to parse with hostname first, fall back to without 
        int parsed = sscanf(line, "%255s %17s %15s %255s", device_id, mac, ip, hostname);
        
        if (parsed >= 3) {
            if (!find_node(config->mac_table, hash_string(device_id))) {
                char *ip_copy = strdup(ip);
                if (ip_copy) {
                    add_tree_node(config->mac_table, hash_string(device_id), ip_copy);
                    add_word(config->ip_table, ip);
                    loaded++;
                    if (hostname[0] != '\0') {
                        syslog(LOG_DEBUG, "Loaded lease: %s (MAC: %s) -> %s [%s]", 
                               device_id, mac, ip, hostname);
                    } else {
                        syslog(LOG_DEBUG, "Loaded lease: %s (MAC: %s) -> %s", 
                               device_id, mac, ip);
                    }
                }
            }
        }

        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    syslog(LOG_INFO, "Loaded %d active leases from database", loaded);
    return 0;
}

/* Update lease database when a lease is granted */
int update_lease_database(const char *mac, dhcp_options_t *opts, dhcp_config_t *config) {
    if (!mac || !config) {
        syslog(LOG_ERR, "update_lease_database: NULL parameter");
        return -1;
    }
    
    /* Get device identifier (Client ID or MAC) */
    char device_id[256];
    get_device_identifier(mac, opts, device_id, sizeof(device_id));
    
    /* Find the IP address for this device */
    struct Tree_Node *node = find_node(config->mac_table, hash_string(device_id));
    if (!node || !node->ip) {
        syslog(LOG_ERR, "Cannot update lease database: device %s not found in table", device_id);
        return -1;
    }

    char ip_addr[IP_STR_LEN];
    strncpy(ip_addr, node->ip, IP_STR_LEN - 1);
    ip_addr[IP_STR_LEN - 1] = '\0';

    /* Get hostname if available */
    const char *hostname = "Unknown";
    if (opts && opts->found_hostname && opts->hostname[0] != '\0') {
        hostname = opts->hostname;
    }

    /* Check if entry already exists in members.txt */
    char lease_db_file[256];
    snprintf(lease_db_file, sizeof(lease_db_file), "%s%s", SERVER_PATH, LEASE_DB_FILE);
    
    bool entry_exists = false;
    int fd = open(lease_db_file, O_RDONLY);
    
    if (fd >= 0) {
        char *buffer = malloc(MAXLINE * 4);
        if (buffer) {
            ssize_t bytes_read = read(fd, buffer, MAXLINE * 4 - 1);
            close(fd);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                char search_str[300];
                snprintf(search_str, sizeof(search_str), "%s %s", device_id, mac);
                if (strstr(buffer, search_str)) {
                    entry_exists = true;
                }
            }
            free(buffer);
        } else {
            close(fd);
        }
    }

    /* Only append if entry doesn't exist */
    if (!entry_exists) {
        fd = open(lease_db_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            syslog(LOG_ERR, "Failed to open lease database: %s", strerror(errno));
            return -1;
        }

        char buffer[1024];
        /* Format: device_id mac ip hostname */
        char safe_hostname[256];
        strncpy(safe_hostname, hostname, sizeof(safe_hostname) - 1);
        safe_hostname[sizeof(safe_hostname) - 1] = '\0';
        
        /* Remove any spaces or newlines from hostname to keep format clean */
        for (char *p = safe_hostname; *p; p++) {
            if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
                *p = '_';
            }
        }
        
        snprintf(buffer, sizeof(buffer), "%s %s %s %s\n", device_id, mac, ip_addr, safe_hostname);

        ssize_t written = write(fd, buffer, strlen(buffer));
        close(fd);

        if (written < 0) {
            syslog(LOG_ERR, "Failed to write to lease database: %s", strerror(errno));
            return -1;
        }
    }

    /* Log to server.log with timestamp and expiration */
    char server_log[256];
    snprintf(server_log, sizeof(server_log), "%s%s", SERVER_PATH, SERVER_LOG_FILE);
    
    fd = open(server_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        time_t now = time(NULL);
        time_t expires = now + config->lease_time;
        struct tm *tm_now = localtime(&now);
        struct tm *tm_exp = gmtime(&expires);
        
        if (tm_now && tm_exp) {
            char time_now[64], time_exp[64];
            strftime(time_now, sizeof(time_now), "%Y-%m-%d %H:%M:%S", tm_now);
            strftime(time_exp, sizeof(time_exp), "%a, %d %b %Y %H:%M:%S GMT", tm_exp);
            
            char log_entry[512];
            snprintf(log_entry, sizeof(log_entry), 
                    "[%s] LEASE: %s (MAC: %s) -> %s (expires: %s)\n",
                    time_now, hostname, mac, ip_addr, time_exp);
            
            write(fd, log_entry, strlen(log_entry));
        }
        close(fd);
    }

    syslog(LOG_INFO, "Updated lease: device %s (MAC: %s) -> %s [%s]", 
           device_id, mac, ip_addr, hostname);
    return 0;
}

/* Compact lease database - remove duplicates */
int compact_lease_database(dhcp_config_t *config) {
    if (!config) {
        return -1;
    }
    
    char lease_db_file[256];
    snprintf(lease_db_file, sizeof(lease_db_file), "%s%s", SERVER_PATH, LEASE_DB_FILE);
    
    int fd = open(lease_db_file, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_INFO, "No lease database to compact");
        return 0;
    }

    char *buffer = malloc(MAXLINE * 4);
    if (!buffer) {
        close(fd);
        syslog(LOG_ERR, "Failed to allocate buffer for compaction");
        return -1;
    }
    
    ssize_t bytes_read = read(fd, buffer, MAXLINE * 4 - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        free(buffer);
        return 0;
    }
    buffer[bytes_read] = '\0';

    /* Create temporary file with unique entries */
    char temp_file[256];
    snprintf(temp_file, sizeof(temp_file), "%s%s.tmp", SERVER_PATH, LEASE_DB_FILE);
    
    int temp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (temp_fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file: %s", strerror(errno));
        free(buffer);
        return -1;
    }

    /* Use a simple hash table to track seen device IDs */
    #define MAX_LEASES 1000
    char (*seen_devices)[256] = malloc(sizeof(char[MAX_LEASES][256]));
    if (!seen_devices) {
        close(temp_fd);
        unlink(temp_file);
        free(buffer);
        syslog(LOG_ERR, "Failed to allocate seen_devices array");
        return -1;
    }
    
    int seen_count = 0;

    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);

    while (line != NULL && seen_count < MAX_LEASES) {
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }
        
        char device_id[256], mac[MAC_STR_LEN], ip[IP_STR_LEN], hostname[256];
        hostname[0] = '\0';
        
        /* Parse with or without hostname */
        int parsed = sscanf(line, "%255s %17s %15s %255s", device_id, mac, ip, hostname);
        
        if (parsed >= 3) {
            /* Check if we've seen this device ID */
            bool found = false;
            for (int i = 0; i < seen_count; i++) {
                if (strcmp(seen_devices[i], device_id) == 0) {
                    found = true;
                    break;
                }
            }
            
            if (!found) {
                /* Keep this entry */
                write(temp_fd, line, strlen(line));
                write(temp_fd, "\n", 1);
                if (seen_count < MAX_LEASES) {
                    strncpy(seen_devices[seen_count], device_id, 256);
                    seen_devices[seen_count][255] = '\0';
                    seen_count++;
                }
            }
        }

        line = strtok_r(NULL, "\n", &save_ptr);
    }

    close(temp_fd);
    free(buffer);
    free(seen_devices);

    /* Replace old file with new */
    if (rename(temp_file, lease_db_file) < 0) {
        syslog(LOG_ERR, "Failed to replace lease database: %s", strerror(errno));
        unlink(temp_file);
        return -1;
    }

    syslog(LOG_INFO, "Compacted lease database: %d unique entries", seen_count);
    return 0;
}

/* Load static IP assignments */
int load_static_assignments(dhcp_config_t *config) {
    (void)config;

    char static_file_path[256];
    snprintf(static_file_path, sizeof(static_file_path), "%s%s", SERVER_PATH, STATIC_FILE);
    
    int fd = open(static_file_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    char buffer[MAXLINE];
    ssize_t bytes_read = read(fd, buffer, MAXLINE - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        return -1;
    }
    buffer[bytes_read] = '\0';

    syslog(LOG_INFO, "Loaded static assignments from %s", STATIC_FILE);
    return 0;
}

/* Add a static IP assignment */
int add_static_assignment(const char *mac, const char *ip, dhcp_config_t *config) {
    (void)config;
    
    if (!mac || !ip) {
        return -1;
    }
    
    char static_file_path[256];
    snprintf(static_file_path, sizeof(static_file_path), "%s%s", SERVER_PATH, STATIC_FILE);
    
    int fd = open(static_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open static assignments file: %s", strerror(errno));
        return -1;
    }

    char buffer[256];
    snprintf(buffer, sizeof(buffer), "device %s %s\n", mac, ip);
    
    ssize_t written = write(fd, buffer, strlen(buffer));
    close(fd);

    if (written > 0) {
        syslog(LOG_INFO, "Added static assignment: %s -> %s", mac, ip);
        return 0;
    }
    
    return -1;
}

/* Load blacklist from file */
int load_blacklist(dhcp_config_t *config) {
    if (!config || !config->blacklist) {
        return -1;
    }
    
    char blacklist_file_path[256];
    snprintf(blacklist_file_path, sizeof(blacklist_file_path), "%s%s", SERVER_PATH, BLACKLIST_FILE);
    
    int fd = open(blacklist_file_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    char buffer[MAXLINE];
    ssize_t bytes_read = read(fd, buffer, MAXLINE - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        return -1;
    }
    buffer[bytes_read] = '\0';

    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);
    int loaded = 0;

    while (line != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* Extract MAC address (first token) */
        char *mac = strtok(line, " \t\r\n");
        if (mac && strlen(mac) > 0) {
            add_tree_node(config->blacklist, hash_string(mac), NULL);
            loaded++;
            syslog(LOG_DEBUG, "Added to blacklist: %s", mac);
        }

        line = strtok_r(NULL, "\n", &save_ptr);
    }

    syslog(LOG_INFO, "Loaded %d entries from blacklist", loaded);
    return 0;
}

/* Add a MAC address to the blacklist */
int add_to_blacklist(const char *mac, dhcp_config_t *config) {
    if (!mac || !config || !config->blacklist) {
        return -1;
    }
    
    char blacklist_file_path[256];
    snprintf(blacklist_file_path, sizeof(blacklist_file_path), "%s%s", SERVER_PATH, BLACKLIST_FILE);
    
    int fd = open(blacklist_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open blacklist file: %s", strerror(errno));
        return -1;
    }

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "%s\n", mac);
    
    ssize_t written = write(fd, buffer, strlen(buffer));
    close(fd);

    if (written > 0) {
        add_tree_node(config->blacklist, hash_string((char *)mac), NULL);
        syslog(LOG_INFO, "Added to blacklist: %s", mac);
        return 0;
    }

    return -1;
}

/* Check if a MAC address is blacklisted */
bool is_blacklisted(dhcp_config_t *config, const char *mac) {
    if (!mac || !config || !config->blacklist) {
        return false;
    }
    
    struct Tree_Node *node = find_node(config->blacklist, hash_string((char *)mac));
    return (node != NULL);
}