#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "utils.h"
#include "ha.h"
#include <time.h>
#include <stdarg.h>

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
        /* Static assignments are never wiped — only a stale *dynamic*
         * MAC-keyed lease should be cleaned up here. */
        if (mac_node && id_node && mac_node != id_node &&
            !mac_node->is_static && mac_node->ip) {
            syslog(LOG_WARNING,
                   "Client-ID collision: MAC %s has different lease than "
                   "Client ID %s", mac, device_id);
            lease_drop_ip(config, mac_node);
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
        /* A client that sends a Client-ID gets its own node keyed by that id;
         * mark it static too so it never expires out from under the MAC entry.
         * The MAC node stays the IP's owner. */
        struct Tree_Node *node = get_or_create_node(config->mac_table, device_id);
        if (node && !node->is_static) {
            if (node->ip) lease_drop_ip(config, node);
            node->ip        = strdup(static_ip);
            node->is_static = true;
            node->expires   = 0;
        }
        return static_ip;
    }

    /* New device — find a free IP.  Short expiry means if the client goes
     * silent the slot comes back after OFFER_TENTATIVE_SECS seconds. */
    char *new_ip = find_free_ip(config, device_id);
    if (new_ip) {
        struct Tree_Node *node = get_or_create_node(config->mac_table, device_id);
        if (!node) {
            free(new_ip);
            return NULL;
        }
        lease_bind_ip(config, node, new_ip);
        node->bound      = false;
        node->unverified = true;       /* the worker probes it before offering */
        node->expires    = time(NULL) + OFFER_TENTATIVE_SECS;
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

    if (!node->is_static && node->expires > 0 && node->expires <= time(NULL)) {
        syslog(LOG_INFO, "Lease for device %s (IP %s) expired — reclaiming",
               device_id, node->ip);
        lease_drop_ip(config, node);
        return NULL;
    }

    return strdup(node->ip);
}

/* Static assignments are flagged is_static and keyed by MAC.  They're already
 * in memory from startup, so no file access needed here. */
char *check_static_assignment(const char *mac, dhcp_config_t *config) {
    if (!mac || !config || !config->mac_table) return NULL;

    struct Tree_Node *node = find_node(config->mac_table, mac);
    if (node && node->ip && node->is_static)
        return strdup(node->ip);

    return NULL;
}

char *find_free_ip(dhcp_config_t *config, const char *device_id) {
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

    /* Sticky, deterministic allocation: an identity always probes the pool from
     * the same offset, so a device that lapses and returns lands back on its old
     * IP if it's still free.  Replaces the old random offset that scattered a
     * returning client onto a new address every time.  A randomized MAC is a new
     * device_id and gets its own slot — we never fingerprint across identities,
     * so this stays privacy-safe on sensitive networks. */
    uint32_t offset = (device_id && device_id[0])
                    ? (hash_string(device_id) % pool_size)
                    : ((uint32_t)rand() % pool_size);

    /* In a cluster each node hands out new addresses only from its own slice
     * of the pool, so two nodes can never offer the same address. */
    ha_alloc_ctx_t slice;
    ha_alloc_begin(&slice);
    if (slice.frozen) {
        syslog(LOG_WARNING, "Not allocating new addresses: peers are running a "
               "different cluster config (waiting for it to settle)");
        return NULL;
    }

    char *new_ip = malloc(IP_STR_LEN);
    if (!new_ip) return NULL;

    for (uint32_t i = 0; i < pool_size; i++) {
        uint32_t v = start + ((offset + i) % pool_size);
        if (!ha_alloc_ok(&slice, v))
            continue;
        snprintf(new_ip, IP_STR_LEN, "%u.%u.%u.%u",
                 (v >> 24) & 0xFF, (v >> 16) & 0xFF,
                 (v >>  8) & 0xFF,  v        & 0xFF);
        if (!test_ip(config->ip_table, new_ip))
            return new_ip;
    }

    free(new_ip);
    syslog(LOG_ERR, "No free IP address in range %s – %s%s",
           config->start_ip, config->end_ip,
           slice.enabled ? " (this node's slice is full)" : "");
    return NULL;
}

int update_lease_expiry(const char *device_id, time_t expires,
                        dhcp_config_t *config) {
    if (!device_id || !config || !config->mac_table) return -1;

    struct Tree_Node *node = find_node(config->mac_table, device_id);
    if (!node) return -1;

    /* Statics stay permanent (expires == 0) no matter how often they renew */
    if (!node->is_static)
        node->expires = expires;
    return 0;
}

static int sweep_node(dhcp_config_t *config, struct Tree_Node *node, time_t now) {
    if (!node) return 0;
    int dropped = sweep_node(config, node->left, now);
    dropped += sweep_node(config, node->right, now);
    /* Walk this BST node and anything chained off it (hash collisions) */
    for (struct Tree_Node *n = node; n; n = n->chain) {
        if (n->ip && !n->is_static && n->expires > 0 && n->expires <= now) {
            if (n->bound) dropped++;
            lease_drop_ip(config, n);
        }
    }
    return dropped;
}

int sweep_expired_leases(dhcp_config_t *config) {
    if (!config || !config->mac_table || !config->ip_table) return 0;
    int dropped = sweep_node(config, config->mac_table->head, time(NULL));
    syslog(LOG_DEBUG, "Expired lease sweep complete (%d leases dropped)", dropped);
    return dropped;
}

/* ---- IP ownership -------------------------------------------------------- */

static struct Tree_Node *owner_entry(dhcp_config_t *config, const char *ip) {
    return config->ip_owner ? find_node(config->ip_owner, ip) : NULL;
}

static void owner_set(dhcp_config_t *config, const char *ip, const char *key) {
    if (!config->ip_owner) return;
    struct Tree_Node *o = find_node(config->ip_owner, ip);
    if (!o) o = add_tree_node(config->ip_owner, ip, NULL, 0);
    if (!o) return;
    free(o->ip);
    o->ip = key ? strdup(key) : NULL;
}

struct Tree_Node *ip_holder(dhcp_config_t *config, const char *ip) {
    if (!config || !ip) return NULL;
    struct Tree_Node *o = owner_entry(config, ip);
    if (!o || !o->ip) return NULL;
    struct Tree_Node *n = find_node(config->mac_table, o->ip);
    return (n && n->ip && strcmp(n->ip, ip) == 0) ? n : NULL;
}

void lease_bind_ip(dhcp_config_t *config, struct Tree_Node *node, const char *ip) {
    if (!config || !node || !ip) return;
    if (node->ip && strcmp(node->ip, ip) != 0)
        lease_drop_ip(config, node);
    if (!node->ip) {
        node->ip = strdup(ip);
        if (!node->ip) return;
    }
    if (!test_ip(config->ip_table, (char *)ip))
        add_word(config->ip_table, (char *)ip);
    owner_set(config, ip, node->key);
}

void lease_drop_ip(dhcp_config_t *config, struct Tree_Node *node) {
    if (!config || !node || !node->ip) return;
    /* Only free the address if this node is its registered owner.  A
     * Client-ID copy of a static assignment points at the same IP without
     * owning it — dropping the copy must not release the static address. */
    struct Tree_Node *o = owner_entry(config, node->ip);
    if (!o || !o->ip || strcmp(o->ip, node->key) == 0) {
        remove_word(config->ip_table, node->ip);
        if (o) { free(o->ip); o->ip = NULL; }
    }
    free(node->ip);
    node->ip         = NULL;
    node->expires    = 0;
    node->bound      = false;
    node->unverified = false;
}

struct Tree_Node *get_or_create_node(struct Tree *tree, const char *key) {
    struct Tree_Node *n = find_node(tree, key);
    return n ? n : add_tree_node(tree, key, NULL, 0);
}

bool ip_in_pool(dhcp_config_t *config, uint32_t ip) {
    if (!config || !config->start_ip || !config->end_ip) return false;
    uint32_t v     = ntohl(ip);
    uint32_t start = ntohl(inet_addr(config->start_ip));
    uint32_t end   = ntohl(inet_addr(config->end_ip));
    return v >= start && v <= end;
}

/* ---- Files and tokens ---------------------------------------------------- */

int write_file_atomic(const char *path, const char *buf, size_t len) {
    char temp_path[4096];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp", path);

    int fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        syslog(LOG_ERR, "write %s: open temp failed: %s", path, strerror(errno));
        return -1;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "write %s: %s", path, strerror(errno));
            close(fd); unlink(temp_path);
            return -1;
        }
        off += (size_t)n;
    }
    /* Without this a power cut can leave the renamed file empty */
    if (fsync(fd) < 0)
        syslog(LOG_WARNING, "write %s: fsync failed: %s", path, strerror(errno));
    close(fd);

    if (rename(temp_path, path) < 0) {
        syslog(LOG_ERR, "write %s: rename failed: %s", path, strerror(errno));
        unlink(temp_path);
        return -1;
    }

    /* Make the rename itself durable */
    char dir[4096];
    snprintf(dir, sizeof(dir), "%s", path);
    char *slash = strrchr(dir, '/');
    if (slash) {
        if (slash == dir) slash[1] = '\0'; else *slash = '\0';
        int dfd = open(dir, O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { fsync(dfd); close(dfd); }
    }
    return 0;
}

void sb_append(strbuf_t *sb, const char *s, size_t n) {
    if (sb->failed) return;
    if (sb->len + n + 1 > sb->cap) {
        size_t cap = sb->cap ? sb->cap : 1024;
        while (cap < sb->len + n + 1) cap *= 2;
        char *p = realloc(sb->buf, cap);
        if (!p) { sb->failed = true; return; }
        sb->buf = p;
        sb->cap = cap;
    }
    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
}

void sb_printf(strbuf_t *sb, const char *fmt, ...) {
    char tmp[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) { sb_append(sb, tmp, (size_t)n); return; }
    char *big = malloc((size_t)n + 1);
    if (!big) { sb->failed = true; return; }
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    sb_append(sb, big, (size_t)n);
    free(big);
}

void sb_free(strbuf_t *sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->len = sb->cap = 0;
}

bool valid_node_id(const char *id) {
    if (!id || !id[0]) return false;
    size_t len = strlen(id);
    if (len >= NODE_ID_LEN) return false;
    for (size_t i = 0; i < len; i++) {
        char c = id[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-'))
            return false;
    }
    return true;
}

void sanitize_token(const char *s, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    size_t j = 0;
    if (s) {
        for (size_t i = 0; s[i] && j < outlen - 1; i++) {
            char c = s[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
            out[j++] = ok ? c : '_';
        }
    }
    if (j == 0 && outlen >= 2) out[j++] = '-';
    out[j] = '\0';
}

void format_mac_address(const uint8_t *mac, char *buf, size_t buflen) {
    if (!mac || !buf || buflen < MAC_STR_LEN) return;
    snprintf(buf, buflen, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
