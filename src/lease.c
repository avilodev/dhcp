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

/* members.txt is a CSV snapshot:  device_id,mac,ip,hostname  (no timestamps).
 * On load we give each entry a fresh lease window; DHCP traffic and the hourly
 * cleanup keep it accurate from there.  Legacy space-separated rows still load. */
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

        /* Accept both CSV and the legacy space-separated form */
        char parse[600];
        strncpy(parse, line, sizeof(parse) - 1);
        parse[sizeof(parse) - 1] = '\0';
        for (char *p = parse; *p; p++) if (*p == ',') *p = ' ';

        char device_id[256] = "", ip[IP_STR_LEN] = "", hostname[256] = "";
        /* field 2 (mac) is skipped — the node is keyed by device_id */
        int parsed = sscanf(parse, "%255s %*s %15s %255s",
                            device_id, ip, hostname);
        if (parsed < 2) {
            line = strtok_r(NULL, "\n", &save_ptr);
            continue;
        }

        if (!find_node(config->mac_table, device_id)) {
            char *ip_copy = strdup(ip);
            if (ip_copy) {
                add_tree_node(config->mac_table, device_id, ip_copy,
                              now + config->lease_time);
                if (!test_ip(config->ip_table, ip))
                    add_word(config->ip_table, ip);
                if (hostname[0] != '\0')
                    update_node_hostname(config->mac_table, device_id, hostname);
                loaded++;
                syslog(LOG_DEBUG, "Loaded lease: %s -> %s [%s]",
                       device_id, ip, hostname[0] ? hostname : "(no hostname)");
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

/* members.txt is a CSV snapshot — one current lease per line, no header, no
 * timestamps:   device_id,mac,ip,hostname
 * (Same CSV convention as the DNS server's logs.) */

/* Read members.txt, drop any row matching drop_id (device_id) or drop_ip,
 * append add_line if non-NULL, rewrite atomically.  Takes g_file_mutex.  Does
 * NOT touch the lease tree, so it's safe on the DHCPACK / RELEASE paths which
 * run after g_server_mutex is released. */
static int rewrite_members(dhcp_config_t *config,
                           const char *drop_id, const char *drop_ip,
                           const char *add_line) {
    if (!config || !config->lease_db_path) return -1;

    pthread_mutex_lock(&g_file_mutex);

    char  *old_buf = NULL;
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

    size_t add_len = add_line ? strlen(add_line) : 0;
    size_t cap     = old_len + add_len + 2;
    char  *buf     = malloc(cap);
    if (!buf) { free(old_buf); pthread_mutex_unlock(&g_file_mutex); return -1; }
    size_t len = 0;

    if (old_buf) {
        char *save, *line = strtok_r(old_buf, "\n", &save);
        while (line) {
            if (line[0] && line[0] != '#') {
                char parse[600];
                strncpy(parse, line, sizeof(parse) - 1);
                parse[sizeof(parse) - 1] = '\0';
                for (char *p = parse; *p; p++) if (*p == ',') *p = ' ';
                char dev[256] = "", mac[64] = "", ip[64] = "";
                sscanf(parse, "%255s %63s %63s", dev, mac, ip);

                bool drop = (drop_id && dev[0] && strcmp(dev, drop_id) == 0) ||
                            (drop_ip && ip[0]  && strcmp(ip,  drop_ip) == 0);
                if (!drop && dev[0]) {
                    size_t ll = strlen(line);
                    memcpy(buf + len, line, ll); len += ll;
                    buf[len++] = '\n';
                }
            }
            line = strtok_r(NULL, "\n", &save);
        }
        free(old_buf);
    }

    if (add_line && add_len) { memcpy(buf + len, add_line, add_len); len += add_len; }

    int rc = rewrite_lease_db_locked(config, buf, len);
    free(buf);
    pthread_mutex_unlock(&g_file_mutex);
    return rc;
}

/* Rewrite members.txt as the live snapshot: keep only rows whose device still
 * holds that exact IP and isn't expired, re-emitting each in canonical CSV.
 * This is the hourly self-cleanup.  Caller holds g_server_mutex. */
int cleanup_members_database(dhcp_config_t *config) {
    if (!config || !config->lease_db_path || !config->mac_table) return -1;

    pthread_mutex_lock(&g_file_mutex);

    char  *old_buf = NULL;
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
    if (!old_buf) { pthread_mutex_unlock(&g_file_mutex); return 0; }

    size_t cap = old_len * 2 + 64;          /* re-emitted CSV ≤ ~1.1× original */
    char  *buf = malloc(cap);
    if (!buf) { free(old_buf); pthread_mutex_unlock(&g_file_mutex); return -1; }
    size_t len = 0;
    int kept = 0, dropped = 0;
    time_t now = time(NULL);

    char *save, *line = strtok_r(old_buf, "\n", &save);
    while (line) {
        if (line[0] && line[0] != '#') {
            char parse[600];
            strncpy(parse, line, sizeof(parse) - 1);
            parse[sizeof(parse) - 1] = '\0';
            for (char *p = parse; *p; p++) if (*p == ',') *p = ' ';

            char dev[256] = "", mac[64] = "", ip[64] = "", host[256] = "";
            int got = sscanf(parse, "%255s %63s %63s %255s", dev, mac, ip, host);
            if (got >= 3) {
                struct Tree_Node *node = find_node(config->mac_table, dev);
                bool live = node && node->ip && strcmp(node->ip, ip) == 0 &&
                            (node->expires == 0 || node->expires > now);
                if (live) {
                    if (host[0] == '\0') { host[0] = '-'; host[1] = '\0'; }
                    int n = snprintf(buf + len, cap - len, "%s,%s,%s,%s\n",
                                     dev, mac, ip, host);
                    if (n > 0 && (size_t)n < cap - len) len += (size_t)n;
                    kept++;
                } else dropped++;
            }
        }
        line = strtok_r(NULL, "\n", &save);
    }
    free(old_buf);

    int rc = rewrite_lease_db_locked(config, buf, len);
    free(buf);
    pthread_mutex_unlock(&g_file_mutex);

    if (rc == 0 && dropped)
        syslog(LOG_INFO, "members.txt cleanup: kept %d, dropped %d stale", kept, dropped);
    return rc;
}

/* Update the lease file for one device on DHCPACK.  Drops this device's old row
 * AND any row already on this IP, then writes the fresh CSV row. */
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
    /* Keep every field one CSV token: no commas or whitespace */
    for (char *p = safe_hostname; *p; p++)
        if (*p == ',' || *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
            *p = '_';

    char new_line[700];
    snprintf(new_line, sizeof(new_line), "%s,%s,%s,%s\n",
             device_id, mac, ip, safe_hostname);

    int rc = rewrite_members(config, device_id, ip, new_line);
    if (rc == 0)
        syslog(LOG_INFO, "Lease DB: %s -> %s", device_id, ip);
    return rc;
}

/* Remove a device's entry from members.txt on DHCPRELEASE. */
int remove_lease_from_database(const char *device_id, dhcp_config_t *config) {
    if (!device_id || !config || !config->lease_db_path) return -1;
    int rc = rewrite_members(config, device_id, NULL, NULL);
    if (rc == 0)
        syslog(LOG_INFO, "Lease DB: removed %s", device_id);
    return rc;
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
