#include <ctype.h>
#include "lease.h"

extern char *get_device_identifier(const char *mac, dhcp_options_t *opts,
                                   char *buffer, size_t buflen);
extern int update_lease_expiry(const char *device_id, time_t expires,
                               dhcp_config_t *config);

/* Lease file format (one entry per line):
 *   device_id  mac  ip  hostname  expiry_unix_timestamp
 *
 * The expiry column was added after the initial release.  Entries that
 * lack it (parsed < 5) are treated as newly issued so existing leases
 * survive a first upgrade restart.
 * expiry == 0 means no expiry (static-like). */

/* --------------------------------------------------------------------------
 * load_lease_database
 * -------------------------------------------------------------------------- */
int load_lease_database(dhcp_config_t *config) {
    char lease_db_file[256];
    snprintf(lease_db_file, sizeof(lease_db_file), "%s%s",
             SERVER_PATH, LEASE_DB_FILE);

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
    if (bytes_read <= 0) { free(buffer); return 0; }
    buffer[bytes_read] = '\0';

    time_t now    = time(NULL);
    int    loaded = 0;

    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);

    while (line) {
        if (line[0] == '\0' || line[0] == '#') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        char device_id[256], mac[MAC_STR_LEN], ip[IP_STR_LEN], hostname[256];
        long expiry_ts = 0;
        hostname[0] = '\0';

        int parsed = sscanf(line, "%255s %17s %15s %255s %ld",
                            device_id, mac, ip, hostname, &expiry_ts);
        if (parsed < 3) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        if (expiry_ts > 0 && expiry_ts <= now) {
            syslog(LOG_DEBUG, "Skipping expired lease for %s (IP %s)",
                   device_id, ip);
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* For old-format entries (no expiry column) assign a fresh window */
        time_t expires = (expiry_ts > 0) ? (time_t)expiry_ts
                                         : now + config->lease_time;

        if (!find_node(config->mac_table, hash_string(device_id))) {
            char *ip_copy = strdup(ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, hash_string(device_id),
                              ip_copy, expires);
                add_word(config->ip_table, ip);
                loaded++;
                syslog(LOG_DEBUG, "Loaded lease: %s (MAC: %s) -> %s [%s]",
                       device_id, mac, ip,
                       hostname[0] ? hostname : "(no hostname)");
            }
        }
        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    syslog(LOG_INFO, "Loaded %d active leases from database", loaded);
    return 0;
}

/* --------------------------------------------------------------------------
 * update_lease_database
 * Called after sending DHCPACK.  Always appends so the latest renewal is
 * captured on disk; compact_lease_database deduplicates.
 * -------------------------------------------------------------------------- */
int update_lease_database(const char *mac, dhcp_options_t *opts,
                          dhcp_config_t *config) {
    if (!mac || !config) {
        syslog(LOG_ERR, "update_lease_database: NULL parameter");
        return -1;
    }

    char device_id[256];
    get_device_identifier(mac, opts, device_id, sizeof(device_id));

    struct Tree_Node *node = find_node(config->mac_table,
                                       hash_string(device_id));
    if (!node || !node->ip) {
        syslog(LOG_ERR,
               "Cannot update lease: device %s not found in table",
               device_id);
        return -1;
    }

    char ip_addr[IP_STR_LEN];
    strncpy(ip_addr, node->ip, IP_STR_LEN - 1);
    ip_addr[IP_STR_LEN - 1] = '\0';

    const char *hostname = "Unknown";
    if (opts && opts->found_hostname && opts->hostname[0] != '\0')
        hostname = opts->hostname;

    /* Sanitise hostname for single-column storage */
    char safe_hostname[256];
    strncpy(safe_hostname, hostname, sizeof(safe_hostname) - 1);
    safe_hostname[sizeof(safe_hostname) - 1] = '\0';
    for (char *p = safe_hostname; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            *p = '_';
    }

    time_t now     = time(NULL);
    time_t expires = now + config->lease_time;

    update_lease_expiry(device_id, expires, config);

    /* Always append – compact_lease_database will keep only the latest */
    char lease_db_file[256];
    snprintf(lease_db_file, sizeof(lease_db_file), "%s%s",
             SERVER_PATH, LEASE_DB_FILE);

    int fd = open(lease_db_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open lease database: %s", strerror(errno));
        return -1;
    }

    char line_buf[1024];
    snprintf(line_buf, sizeof(line_buf), "%s %s %s %s %ld\n",
             device_id, mac, ip_addr, safe_hostname, (long)expires);
    if (write(fd, line_buf, strlen(line_buf)) < 0)
        syslog(LOG_ERR, "Failed to write lease entry: %s", strerror(errno));
    close(fd);

    /* Log the confirmed lease to server.log */
    char server_log[256];
    snprintf(server_log, sizeof(server_log), "%s%s", SERVER_PATH, SERVER_LOG_FILE);
    fd = open(server_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        struct tm *tm_now = localtime(&now);
        struct tm *tm_exp = gmtime(&expires);
        if (tm_now && tm_exp) {
            char time_now[64], time_exp[64];
            strftime(time_now, sizeof(time_now), "%Y-%m-%d %H:%M:%S", tm_now);
            strftime(time_exp, sizeof(time_exp),
                     "%a, %d %b %Y %H:%M:%S GMT", tm_exp);
            char log_entry[512];
            snprintf(log_entry, sizeof(log_entry),
                     "[%s] LEASE: %s (MAC: %s) -> %s (expires: %s)\n",
                     time_now, hostname, mac, ip_addr, time_exp);
            if (write(fd, log_entry, strlen(log_entry)) < 0)
                syslog(LOG_WARNING, "Failed to write lease log: %s", strerror(errno));
        }
        close(fd);
    }

    syslog(LOG_INFO, "Updated lease: device %s (MAC: %s) -> %s [%s]",
           device_id, mac, ip_addr, hostname);
    return 0;
}

/* --------------------------------------------------------------------------
 * compact_lease_database
 * Removes duplicate entries (keeping the latest for each device_id) and
 * drops entries whose lease has expired.
 * -------------------------------------------------------------------------- */
int compact_lease_database(dhcp_config_t *config) {
    if (!config) return -1;

    char lease_db_file[256];
    snprintf(lease_db_file, sizeof(lease_db_file), "%s%s",
             SERVER_PATH, LEASE_DB_FILE);

    int fd = open(lease_db_file, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_INFO, "No lease database to compact");
        return 0;
    }

    char *buffer = malloc(MAXLINE * 4);
    if (!buffer) { close(fd); return -1; }

    ssize_t bytes_read = read(fd, buffer, MAXLINE * 4 - 1);
    close(fd);
    if (bytes_read <= 0) { free(buffer); return 0; }
    buffer[bytes_read] = '\0';

    /* Temporary output file */
    char temp_file[256];
    snprintf(temp_file, sizeof(temp_file), "%s%s.tmp",
             SERVER_PATH, LEASE_DB_FILE);

    int temp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (temp_fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file: %s", strerror(errno));
        free(buffer);
        return -1;
    }

#define MAX_LEASES   1000
#define LINE_MAX_LEN  600

    char (*seen_devices)[256]      = malloc(MAX_LEASES * sizeof(char[256]));
    char (*seen_lines)[LINE_MAX_LEN] = malloc(MAX_LEASES * sizeof(char[LINE_MAX_LEN]));

    if (!seen_devices || !seen_lines) {
        syslog(LOG_ERR, "compact_lease_database: malloc failed");
        free(seen_devices); free(seen_lines);
        close(temp_fd); unlink(temp_file);
        free(buffer);
        return -1;
    }

    int    seen_count = 0;
    time_t now        = time(NULL);

    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);

    while (line && seen_count < MAX_LEASES) {
        if (line[0] == '\0' || line[0] == '#') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        char device_id[256], mac[MAC_STR_LEN], ip[IP_STR_LEN], hostname[256];
        long expiry_ts = 0;
        hostname[0] = '\0';

        int parsed = sscanf(line, "%255s %17s %15s %255s %ld",
                            device_id, mac, ip, hostname, &expiry_ts);
        if (parsed < 3) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* Drop expired entries */
        if (expiry_ts > 0 && expiry_ts <= now) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* If old format (no expiry), assign one so the compact file is valid */
        if (expiry_ts == 0 && parsed < 5) {
            /* Rewrite line with a calculated expiry */
            char new_line[LINE_MAX_LEN];
            long new_exp = (long)(now + config->lease_time);
            snprintf(new_line, sizeof(new_line), "%s %s %s %s %ld",
                     device_id, mac, ip,
                     hostname[0] ? hostname : "Unknown", new_exp);
            line = new_line;  /* use rewritten line below */
        }

        /* Keep latest entry per device_id (later in file wins) */
        int existing = -1;
        for (int i = 0; i < seen_count; i++) {
            if (strcmp(seen_devices[i], device_id) == 0) {
                existing = i;
                break;
            }
        }

        if (existing >= 0) {
            snprintf(seen_lines[existing], LINE_MAX_LEN, "%s", line);
        } else {
            snprintf(seen_devices[seen_count], 256, "%s", device_id);
            snprintf(seen_lines[seen_count],   LINE_MAX_LEN, "%s", line);
            seen_count++;
        }

        line = strtok_r(NULL, "\n", &save_ptr);
    }

    bool write_ok = true;
    for (int i = 0; i < seen_count; i++) {
        if (write(temp_fd, seen_lines[i], strlen(seen_lines[i])) < 0 ||
            write(temp_fd, "\n", 1) < 0) {
            syslog(LOG_ERR, "compact: write to temp file failed: %s",
                   strerror(errno));
            write_ok = false;
            break;
        }
    }

    close(temp_fd);
    free(buffer);
    free(seen_devices);
    free(seen_lines);

#undef MAX_LEASES
#undef LINE_MAX_LEN

    if (!write_ok) {
        unlink(temp_file);
        return -1;
    }

    if (rename(temp_file, lease_db_file) < 0) {
        syslog(LOG_ERR, "Failed to replace lease database: %s", strerror(errno));
        unlink(temp_file);
        return -1;
    }

    syslog(LOG_INFO, "Compacted lease database: %d unique active entries",
           seen_count);
    return 0;
}

/* --------------------------------------------------------------------------
 * Static assignments
 * -------------------------------------------------------------------------- */
/* Load static MAC→IP assignments into config->mac_table (expires=0 = permanent). */

int load_static_assignments(dhcp_config_t *config) {
    if (!config || !config->mac_table || !config->ip_table) return -1;

    char static_file_path[256];
    snprintf(static_file_path, sizeof(static_file_path), "%s%s",
             SERVER_PATH, STATIC_FILE);

    int fd = open(static_file_path, O_RDONLY);
    if (fd < 0) return -1;

    char *buffer = malloc(MAXLINE);
    if (!buffer) { close(fd); return -1; }

    ssize_t n = read(fd, buffer, MAXLINE - 1);
    close(fd);
    if (n <= 0) { free(buffer); return -1; }
    buffer[n] = '\0';

    int loaded = 0;
    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);

    while (line) {
        /* Skip comments and blank lines */
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

        char *mac = strtok(NULL, " \t");
        char *ip  = strtok(NULL, " \t\r\n");
        if (!mac || !ip) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* Normalise MAC to uppercase to match format_mac_address() output */
        for (char *p = mac; *p; p++)
            *p = (char)toupper((unsigned char)*p);

        /* Add to mac_table with expires=0 (permanent — never reclaimed) */
        if (!find_node(config->mac_table, hash_string(mac))) {
            char *ip_copy = strdup(ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, hash_string(mac), ip_copy, 0);
                if (!test_ip(config->ip_table, ip))
                    add_word(config->ip_table, ip);
                loaded++;
                syslog(LOG_INFO, "Static assignment: %s -> %s", mac, ip);
            }
        }

        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    syslog(LOG_INFO, "Loaded %d static assignments", loaded);
    return loaded > 0 ? 0 : -1;
}

int add_static_assignment(const char *mac, const char *ip,
                          dhcp_config_t *config) {
    (void)config;
    if (!mac || !ip) return -1;

    char static_file_path[256];
    snprintf(static_file_path, sizeof(static_file_path), "%s%s",
             SERVER_PATH, STATIC_FILE);

    int fd = open(static_file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open static assignments file: %s",
               strerror(errno));
        return -1;
    }

    char buf[256];
    snprintf(buf, sizeof(buf), "device %s %s\n", mac, ip);
    ssize_t written = write(fd, buf, strlen(buf));
    close(fd);

    if (written > 0) {
        syslog(LOG_INFO, "Added static assignment: %s -> %s", mac, ip);
        return 0;
    }
    return -1;
}

/* --------------------------------------------------------------------------
 * Blacklist
 * -------------------------------------------------------------------------- */
int load_blacklist(dhcp_config_t *config) {
    if (!config || !config->blacklist) return -1;

    char blacklist_path[256];
    snprintf(blacklist_path, sizeof(blacklist_path), "%s%s",
             SERVER_PATH, BLACKLIST_FILE);

    int fd = open(blacklist_path, O_RDONLY);
    if (fd < 0) return -1;

    char buffer[MAXLINE];
    ssize_t n = read(fd, buffer, MAXLINE - 1);
    close(fd);
    if (n <= 0) return -1;
    buffer[n] = '\0';

    char *save_ptr;
    char *line    = strtok_r(buffer, "\n", &save_ptr);
    int   loaded  = 0;

    while (line) {
        if (line[0] == '#' || line[0] == '\0') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }
        char *mac = strtok(line, " \t\r\n");
        if (mac && strlen(mac) > 0) {
            add_tree_node(config->blacklist, hash_string(mac), NULL, 0);
            loaded++;
            syslog(LOG_DEBUG, "Added to blacklist: %s", mac);
        }
        line = strtok_r(NULL, "\n", &save_ptr);
    }

    syslog(LOG_INFO, "Loaded %d entries from blacklist", loaded);
    return 0;
}

int add_to_blacklist(const char *mac, dhcp_config_t *config) {
    if (!mac || !config || !config->blacklist) return -1;

    char blacklist_path[256];
    snprintf(blacklist_path, sizeof(blacklist_path), "%s%s",
             SERVER_PATH, BLACKLIST_FILE);

    int fd = open(blacklist_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open blacklist: %s", strerror(errno));
        return -1;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "%s\n", mac);
    ssize_t written = write(fd, buf, strlen(buf));
    close(fd);

    if (written > 0) {
        add_tree_node(config->blacklist, hash_string(mac), NULL, 0);
        syslog(LOG_INFO, "Added to blacklist: %s", mac);
        return 0;
    }
    return -1;
}

bool is_blacklisted(dhcp_config_t *config, const char *mac) {
    if (!mac || !config || !config->blacklist) return false;
    return find_node(config->blacklist, hash_string(mac)) != NULL;
}
