#include <ctype.h>
#include <sys/stat.h>
#include <pthread.h>
#include "lease.h"

extern int update_lease_expiry(const char *device_id, time_t expires,
                               dhcp_config_t *config);
extern void update_node_hostname(struct Tree *tree, const char *key,
                                 const char *hostname);

/* Prevents two workers from writing members.txt at the same time.
 * Defined in main.c, referenced here. */
extern pthread_mutex_t g_file_mutex;

/* members.txt format — one line per active device:
 *   device_id  mac  ip  hostname  expiry_unix_timestamp
 *
 * expiry == 0 means no expiry (static assignments).
 * Old entries without an expiry column are given a fresh window on load. */
int load_lease_database(dhcp_config_t *config) {
    if (!config || !config->lease_db_path) return -1;

    int fd = open(config->lease_db_path, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_INFO, "No existing lease database found");
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        close(fd);
        return 0;
    }
    size_t buf_size = (size_t)st.st_size + 1;

    char *buffer = malloc(buf_size);
    if (!buffer) {
        close(fd);
        syslog(LOG_ERR, "Failed to allocate buffer for lease database");
        return -1;
    }

    ssize_t bytes_read = read(fd, buffer, buf_size - 1);
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

        /* No expiry column — this is an old-format entry; give it a fresh window */
        time_t expires = (expiry_ts > 0) ? (time_t)expiry_ts
                                         : now + config->lease_time;

        if (!find_node(config->mac_table, device_id)) {
            char *ip_copy = strdup(ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, device_id, ip_copy, expires);
                add_word(config->ip_table, ip);
                if (hostname[0] != '\0')
                    update_node_hostname(config->mac_table, device_id, hostname);
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

/* Writes the new content to a temp file and atomically renames it over the
 * live database.  Caller must hold g_file_mutex. */
static int rewrite_lease_db_locked(dhcp_config_t *config,
                                   const char *new_buf, size_t new_len) {
    char temp_path[280];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", config->lease_db_path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "lease_db rewrite: open temp failed: %s", strerror(errno));
        return -1;
    }
    if (new_len > 0 && write(fd, new_buf, new_len) < 0) {
        syslog(LOG_ERR, "lease_db rewrite: write failed: %s", strerror(errno));
        close(fd); unlink(temp_path);
        return -1;
    }
    close(fd);
    if (rename(temp_path, config->lease_db_path) < 0) {
        syslog(LOG_ERR, "lease_db rewrite: rename failed: %s", strerror(errno));
        unlink(temp_path);
        return -1;
    }
    return 0;
}

/* Update the lease file for one device.  Reads the whole file, replaces or
 * inserts this device's line, then rewrites atomically.  This keeps
 * members.txt as a clean one-entry-per-device canonical file. */
int update_lease_database(const char *mac, const char *device_id,
                          const char *ip, const char *hostname,
                          dhcp_config_t *config) {
    if (!mac || !device_id || !ip || !config || !config->lease_db_path) {
        syslog(LOG_ERR, "update_lease_database: NULL parameter");
        return -1;
    }

    const char *hn = (hostname && hostname[0]) ? hostname : "Unknown";

    char safe_hostname[256];
    strncpy(safe_hostname, hn, sizeof(safe_hostname) - 1);
    safe_hostname[sizeof(safe_hostname) - 1] = '\0';
    for (char *p = safe_hostname; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            *p = '_';
    }

    time_t expires = time(NULL) + config->lease_time;

    pthread_mutex_lock(&g_file_mutex);

    /* Read the current file so we can copy all other devices' entries */
    char *old_buf  = NULL;
    size_t old_len = 0;
    int fd = open(config->lease_db_path, O_RDONLY);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0 && st.st_size > 0) {
            old_len = (size_t)st.st_size;
            old_buf = malloc(old_len + 1);
            if (old_buf) {
                ssize_t n = read(fd, old_buf, old_len);
                if (n > 0) old_buf[n] = '\0';
                else { free(old_buf); old_buf = NULL; old_len = 0; }
            }
        }
        close(fd);
    }

    /* Copy every line except the one belonging to this device, then add the new one */
    size_t new_cap = old_len + 512;
    char  *new_buf = malloc(new_cap);
    if (!new_buf) {
        free(old_buf);
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }
    size_t new_len = 0;

    if (old_buf) {
        char *save_ptr, *line = strtok_r(old_buf, "\n", &save_ptr);
        while (line) {
            if (line[0] && line[0] != '#') {
                char entry_dev[256];
                if (sscanf(line, "%255s", entry_dev) == 1 &&
                    strcmp(entry_dev, device_id) != 0) {
                    size_t ll = strlen(line);
                    if (new_len + ll + 2 > new_cap) {
                        new_cap = new_cap * 2 + ll + 2;
                        char *p = realloc(new_buf, new_cap);
                        if (!p) { free(new_buf); free(old_buf); pthread_mutex_unlock(&g_file_mutex); return -1; }
                        new_buf = p;
                    }
                    memcpy(new_buf + new_len, line, ll);
                    new_len += ll;
                    new_buf[new_len++] = '\n';
                }
            }
            line = strtok_r(NULL, "\n", &save_ptr);
        }
        free(old_buf);
    }

    /* Append the fresh entry for this device */
    char new_line[1024];
    int  nl = snprintf(new_line, sizeof(new_line), "%s %s %s %s %ld\n",
                       device_id, mac, ip, safe_hostname, (long)expires);
    if (nl > 0) {
        if (new_len + (size_t)nl + 1 > new_cap) {
            new_cap = new_len + (size_t)nl + 1;
            char *p = realloc(new_buf, new_cap);
            if (!p) { free(new_buf); pthread_mutex_unlock(&g_file_mutex); return -1; }
            new_buf = p;
        }
        memcpy(new_buf + new_len, new_line, (size_t)nl);
        new_len += (size_t)nl;
    }

    int rc = rewrite_lease_db_locked(config, new_buf, new_len);
    free(new_buf);
    pthread_mutex_unlock(&g_file_mutex);

    if (rc == 0)
        syslog(LOG_INFO, "Lease DB: %s -> %s", device_id, ip);
    return rc;
}

/* Remove a device's entry from members.txt on DHCPRELEASE.  Same
 * read-modify-write approach as update_lease_database. */
int remove_lease_from_database(const char *device_id, dhcp_config_t *config) {
    if (!device_id || !config || !config->lease_db_path) return -1;

    pthread_mutex_lock(&g_file_mutex);

    int fd = open(config->lease_db_path, O_RDONLY);
    if (fd < 0) { pthread_mutex_unlock(&g_file_mutex); return 0; }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        close(fd); pthread_mutex_unlock(&g_file_mutex); return 0;
    }
    size_t buf_size = (size_t)st.st_size + 1;
    char *old_buf = malloc(buf_size);
    if (!old_buf) { close(fd); pthread_mutex_unlock(&g_file_mutex); return -1; }
    ssize_t n = read(fd, old_buf, buf_size - 1);
    close(fd);
    if (n <= 0) { free(old_buf); pthread_mutex_unlock(&g_file_mutex); return 0; }
    old_buf[n] = '\0';

    char  *new_buf = malloc(buf_size);
    if (!new_buf) { free(old_buf); pthread_mutex_unlock(&g_file_mutex); return -1; }
    size_t new_len = 0;
    bool   found   = false;

    char *save_ptr, *line = strtok_r(old_buf, "\n", &save_ptr);
    while (line) {
        if (line[0] && line[0] != '#') {
            char entry_dev[256];
            if (sscanf(line, "%255s", entry_dev) == 1 &&
                strcmp(entry_dev, device_id) == 0) {
                found = true;
                line = strtok_r(NULL, "\n", &save_ptr);
                continue;
            }
        }
        size_t ll = strlen(line);
        memcpy(new_buf + new_len, line, ll);
        new_len += ll;
        new_buf[new_len++] = '\n';
        line = strtok_r(NULL, "\n", &save_ptr);
    }
    free(old_buf);

    int rc = 0;
    if (found)
        rc = rewrite_lease_db_locked(config, new_buf, new_len);
    free(new_buf);
    pthread_mutex_unlock(&g_file_mutex);

    if (found && rc == 0)
        syslog(LOG_INFO, "Lease DB: removed %s", device_id);
    return rc;
}

/* Deduplicates members.txt keeping the latest entry per device and dropping
 * anything that has expired.  Not normally needed since update_lease_database
 * is already a read-modify-write, but kept as a recovery tool. */
int compact_lease_database(dhcp_config_t *config) {
    if (!config || !config->lease_db_path) return -1;

    /* Hold g_file_mutex for the full read→write→rename so nothing else can
     * touch the file while we're rebuilding it. */
    pthread_mutex_lock(&g_file_mutex);

    int fd = open(config->lease_db_path, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_INFO, "No lease database to compact");
        pthread_mutex_unlock(&g_file_mutex);
        return 0;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        close(fd);
        pthread_mutex_unlock(&g_file_mutex);
        return 0;
    }
    size_t buf_size = (size_t)st.st_size + 1;

    char *buffer = malloc(buf_size);
    if (!buffer) { close(fd); pthread_mutex_unlock(&g_file_mutex); return -1; }

    ssize_t bytes_read = read(fd, buffer, buf_size - 1);
    close(fd);
    if (bytes_read <= 0) {
        free(buffer);
        pthread_mutex_unlock(&g_file_mutex);
        return 0;
    }
    buffer[bytes_read] = '\0';

    /* Write to a temp file first so the rename is atomic — no partial reads */
    char temp_file[270];
    snprintf(temp_file, sizeof(temp_file), "%s.tmp", config->lease_db_path);

    int temp_fd = open(temp_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (temp_fd < 0) {
        syslog(LOG_ERR, "Failed to create temp file: %s", strerror(errno));
        free(buffer);
        return -1;
    }

#define MAX_LEASES  10000
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

        /* Skip anything that has already expired */
        if (expiry_ts > 0 && expiry_ts <= now) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* Old format with no expiry column — invent one so the output is valid */
        if (expiry_ts == 0 && parsed < 5) {
            char new_line[LINE_MAX_LEN];
            long new_exp = (long)(now + config->lease_time);
            snprintf(new_line, sizeof(new_line), "%s %s %s %s %ld",
                     device_id, mac, ip,
                     hostname[0] ? hostname : "Unknown", new_exp);
            line = new_line;  /* use rewritten line below */
        }

        /* If we've seen this device already, replace the earlier entry with this one */
        int existing = -1;
        for (int i = 0; i < seen_count; i++) {
            if (strcmp(seen_devices[i], device_id) == 0) {
                existing = i;
                break;
            }
        }

        if (existing >= 0) {
            snprintf(seen_lines[existing], LINE_MAX_LEN, "%s", line);
        } else if (seen_count < MAX_LEASES) {
            snprintf(seen_devices[seen_count], 256, "%s", device_id);
            snprintf(seen_lines[seen_count],   LINE_MAX_LEN, "%s", line);
            seen_count++;
        } else {
            syslog(LOG_WARNING,
                   "compact_lease_database: MAX_LEASES (%d) reached, "
                   "device %s dropped", MAX_LEASES, device_id);
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
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }

    if (rename(temp_file, config->lease_db_path) < 0) {
        syslog(LOG_ERR, "Failed to replace lease database: %s", strerror(errno));
        unlink(temp_file);
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }

    pthread_mutex_unlock(&g_file_mutex);

    syslog(LOG_INFO, "Compacted lease database: %d unique active entries",
           seen_count);
    return 0;
}

/* Load static MAC→IP assignments into memory.  expires=0 marks them permanent
 * so the lease sweeper never reclaims them. */

int load_static_assignments(dhcp_config_t *config) {
    if (!config || !config->mac_table || !config->ip_table ||
        !config->static_path) return -1;

    int fd = open(config->static_path, O_RDONLY);
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

        /* Each line is:  label  MAC  IP
         * The label is just a human name — stored as hostname for the dump view */
        char line_copy[256];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *label = strtok(line_copy, " \t");
        if (!label) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        char *mac = strtok(NULL, " \t");
        char *ip  = strtok(NULL, " \t\r\n");
        if (!mac || !ip) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        /* Uppercase MAC so it matches what format_mac_address() produces */
        for (char *p = mac; *p; p++)
            *p = (char)toupper((unsigned char)*p);

        /* expires=0 means this slot is never swept out by the lease expiry code */
        if (!find_node(config->mac_table, mac)) {
            char *ip_copy = strdup(ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, mac, ip_copy, 0);
                update_node_hostname(config->mac_table, mac, label);
                if (!test_ip(config->ip_table, ip))
                    add_word(config->ip_table, ip);
                loaded++;
                syslog(LOG_INFO, "Static assignment: %s (%s) -> %s",
                       mac, label, ip);
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
    if (!mac || !ip || !config || !config->static_path) return -1;

    int fd = open(config->static_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
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

int load_blacklist(dhcp_config_t *config) {
    if (!config || !config->blacklist || !config->blacklist_path) return -1;

    int fd = open(config->blacklist_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return -1; }
    size_t buf_size = (size_t)st.st_size + 1;

    char *buffer = malloc(buf_size);
    if (!buffer) { close(fd); return -1; }

    ssize_t n = read(fd, buffer, buf_size - 1);
    close(fd);
    if (n <= 0) { free(buffer); return -1; }
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
            add_tree_node(config->blacklist, mac, NULL, 0);
            loaded++;
            syslog(LOG_DEBUG, "Added to blacklist: %s", mac);
        }
        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    syslog(LOG_INFO, "Loaded %d entries from blacklist", loaded);
    return 0;
}

int add_to_blacklist(const char *mac, dhcp_config_t *config) {
    if (!mac || !config || !config->blacklist || !config->blacklist_path) return -1;

    int fd = open(config->blacklist_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "Failed to open blacklist: %s", strerror(errno));
        return -1;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "%s\n", mac);
    ssize_t written = write(fd, buf, strlen(buf));
    close(fd);

    if (written > 0) {
        add_tree_node(config->blacklist, mac, NULL, 0);
        syslog(LOG_INFO, "Added to blacklist: %s", mac);
        return 0;
    }
    return -1;
}

bool is_blacklisted(dhcp_config_t *config, const char *mac) {
    if (!mac || !config || !config->blacklist) return false;
    return find_node(config->blacklist, mac) != NULL;
}

/* Re-read static_list.txt without restarting.  New MACs are added immediately;
 * existing ones get their hostname refreshed and are marked permanent again.
 * If an IP changed in the file the device keeps its old IP until it next
 * renews — at that point it'll get the new one.  Call under g_server_mutex. */
int reload_static_assignments(dhcp_config_t *config) {
    if (!config || !config->mac_table || !config->ip_table ||
        !config->static_path) return -1;

    int fd = open(config->static_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return 0; }
    size_t buf_size = (size_t)st.st_size + 1;

    char *buffer = malloc(buf_size);
    if (!buffer) { close(fd); return -1; }

    ssize_t n = read(fd, buffer, buf_size - 1);
    close(fd);
    if (n <= 0) { free(buffer); return 0; }
    buffer[n] = '\0';

    int added = 0, updated = 0;
    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);

    while (line) {
        if (line[0] == '#' || line[0] == '\0' || line[0] == '\n') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        char line_copy[256];
        strncpy(line_copy, line, sizeof(line_copy) - 1);
        line_copy[sizeof(line_copy) - 1] = '\0';

        char *label = strtok(line_copy, " \t");
        char *mac   = strtok(NULL, " \t");
        char *ip    = strtok(NULL, " \t\r\n");
        if (!label || !mac || !ip) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        for (char *p = mac; *p; p++)
            *p = (char)toupper((unsigned char)*p);

        struct Tree_Node *node = find_node(config->mac_table, mac);
        if (!node) {
            char *ip_copy = strdup(ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, mac, ip_copy, 0);
                update_node_hostname(config->mac_table, mac, label);
                if (!test_ip(config->ip_table, ip))
                    add_word(config->ip_table, ip);
                added++;
                syslog(LOG_INFO, "SIGHUP: new static: %s (%s) -> %s",
                       mac, label, ip);
            }
        } else {
            /* Already in memory — just refresh its hostname and keep it permanent */
            node->expires = 0;
            free(node->hostname);
            node->hostname = strdup(label);
            updated++;
            syslog(LOG_DEBUG, "SIGHUP: updated static: %s (%s) -> %s (lazy IP)",
                   mac, label, node->ip ? node->ip : "?");
        }

        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    syslog(LOG_INFO, "SIGHUP static reload: %d added, %d updated", added, updated);
    return 0;
}

/* Re-read blacklist.txt and add any new MACs.  We never remove entries at
 * runtime — once blocked, always blocked until the server restarts.
 * Call under g_server_mutex. */
int reload_blacklist(dhcp_config_t *config) {
    if (!config || !config->blacklist || !config->blacklist_path) return -1;

    int fd = open(config->blacklist_path, O_RDONLY);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) { close(fd); return 0; }
    size_t buf_size = (size_t)st.st_size + 1;

    char *buffer = malloc(buf_size);
    if (!buffer) { close(fd); return -1; }

    ssize_t n = read(fd, buffer, buf_size - 1);
    close(fd);
    if (n <= 0) { free(buffer); return 0; }
    buffer[n] = '\0';

    int added = 0;
    char *save_ptr;
    char *line = strtok_r(buffer, "\n", &save_ptr);

    while (line) {
        if (line[0] == '#' || line[0] == '\0') {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }
        char *mac = strtok(line, " \t\r\n");
        if (mac && strlen(mac) > 0 && !find_node(config->blacklist, mac)) {
            add_tree_node(config->blacklist, mac, NULL, 0);
            added++;
            syslog(LOG_INFO, "SIGHUP: blacklisted %s", mac);
        }
        line = strtok_r(NULL, "\n", &save_ptr);
    }

    free(buffer);
    syslog(LOG_INFO, "SIGHUP blacklist reload: %d new entries", added);
    return 0;
}

/* Write a human-readable snapshot of every active lease to the dump file.
 * Tree traversal isn't thread-safe so the caller must hold g_server_mutex.
 * The actual file write uses g_file_mutex internally. */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} dump_ctx_t;

static void dump_ctx_append(dump_ctx_t *ctx, const char *s, size_t slen) {
    if (ctx->len + slen + 1 > ctx->cap) {
        size_t new_cap = ctx->cap * 2 + slen + 256;
        char  *p       = realloc(ctx->buf, new_cap);
        if (!p) return;
        ctx->buf = p;
        ctx->cap = new_cap;
    }
    memcpy(ctx->buf + ctx->len, s, slen);
    ctx->len += slen;
    ctx->buf[ctx->len] = '\0';
}

static int dump_visitor(struct Tree_Node *node, void *ctx_ptr) {
    dump_ctx_t *ctx = (dump_ctx_t *)ctx_ptr;
    time_t now = time(NULL);

    char expires_str[32];
    if (node->expires == 0) {
        snprintf(expires_str, sizeof(expires_str), "%-20s", "permanent");
    } else if (node->expires <= now) {
        snprintf(expires_str, sizeof(expires_str), "%-20s", "expired");
    } else {
        struct tm tm_buf;
        struct tm *tm = localtime_r(&node->expires, &tm_buf);
        if (tm)
            strftime(expires_str, sizeof(expires_str), "%Y-%m-%d %H:%M:%S", tm);
        else
            snprintf(expires_str, sizeof(expires_str), "%-20s", "?");
    }

    char line[256];
    int len = snprintf(line, sizeof(line), "%-40s %-15s %-24s %s\n",
                       node->key    ? node->key    : "-",
                       node->ip     ? node->ip     : "-",
                       node->hostname ? node->hostname : "-",
                       expires_str);
    if (len > 0)
        dump_ctx_append(ctx, line, (size_t)len);
    return 0;
}

int dump_lease_table(dhcp_config_t *config) {
    if (!config || !config->mac_table || !config->dump_path) return -1;

    /* Build the whole output in memory first, then write once */
    dump_ctx_t ctx;
    ctx.cap = 65536;
    ctx.len = 0;
    ctx.buf = malloc(ctx.cap);
    if (!ctx.buf) return -1;
    ctx.buf[0] = '\0';

    /* Header */
    const char *header =
        "Device ID / Client ID                    IP              Hostname                 Expires\n"
        "-----------------------------------------------------------------------------------------------\n";
    dump_ctx_append(&ctx, header, strlen(header));

    traverse_tree(config->mac_table, dump_visitor, &ctx);

    /* Atomic rename so nothing ever reads a half-written dump file */
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", config->dump_path);

    pthread_mutex_lock(&g_file_mutex);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "dump_lease_table: open %s failed: %s",
               temp_path, strerror(errno));
        free(ctx.buf);
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }

    bool ok = true;
    if (ctx.len > 0 && write(fd, ctx.buf, ctx.len) < 0) {
        syslog(LOG_ERR, "dump_lease_table: write failed: %s", strerror(errno));
        ok = false;
    }
    close(fd);
    free(ctx.buf);

    if (!ok || rename(temp_path, config->dump_path) < 0) {
        syslog(LOG_ERR, "dump_lease_table: rename failed: %s", strerror(errno));
        unlink(temp_path);
        pthread_mutex_unlock(&g_file_mutex);
        return -1;
    }

    pthread_mutex_unlock(&g_file_mutex);

    syslog(LOG_INFO, "Lease table dumped to %s", config->dump_path);
    return 0;
}
