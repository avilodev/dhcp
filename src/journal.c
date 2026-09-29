#define _GNU_SOURCE
#include <pthread.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "journal.h"
#include "lease.h"
#include "utils.h"

/* Guards the journal fd, the write offsets and the high-water table.  It's a
 * leaf lock: taken after g_server_mutex (never before) and nothing else is
 * taken while it's held. */
static pthread_mutex_t g_jmutex = PTHREAD_MUTEX_INITIALIZER;

static int      g_fd     = -1;
static char    *g_path   = NULL;
static uint32_t g_gen    = 1;   /* bumped on compaction: old tickets are then durable */
static off_t    g_end    = 0;   /* bytes written (page cache) */
static off_t    g_synced = 0;   /* bytes known to be on disk */
static char     g_self[NODE_ID_LEN] = "local";

#define MAX_ORIGINS 64
static struct {
    char     id[NODE_ID_LEN];
    uint64_t hw;
} g_hw[MAX_ORIGINS];
static int g_hw_n = 0;

static const char *JOURNAL_HEADER = "# dhcp lease journal v1\n";

/* Caller holds g_jmutex (or is single-threaded startup) */
static uint64_t *hw_slot(const char *id) {
    for (int i = 0; i < g_hw_n; i++)
        if (strcmp(g_hw[i].id, id) == 0) return &g_hw[i].hw;
    if (g_hw_n >= MAX_ORIGINS) return NULL;
    snprintf(g_hw[g_hw_n].id, sizeof(g_hw[g_hw_n].id), "%s", id);
    g_hw[g_hw_n].hw = 0;
    return &g_hw[g_hw_n++].hw;
}

static void hw_bump(const char *id, uint64_t seq) {
    uint64_t *h = hw_slot(id);
    if (h && seq > *h) *h = seq;
}

const char *journal_self(void) { return g_self; }

const char *journal_op_name(int op) {
    switch (op) {
        case JOP_LEASE:   return "LEASE";
        case JOP_RELEASE: return "RELEASE";
        case JOP_DECLINE: return "DECLINE";
        default:          return "?";
    }
}

static int op_from_name(const char *s) {
    if (strcmp(s, "LEASE")   == 0) return JOP_LEASE;
    if (strcmp(s, "RELEASE") == 0) return JOP_RELEASE;
    if (strcmp(s, "DECLINE") == 0) return JOP_DECLINE;
    return 0;
}

int journal_format(const lease_record_t *r, char *buf, size_t buflen) {
    int n = snprintf(buf, buflen, "%s %" PRIu64 " %lld %s %s %s %s %lld %s\n",
                     r->origin, r->seq, (long long)r->time,
                     journal_op_name(r->op),
                     r->device_id[0] ? r->device_id : "-",
                     r->mac[0]       ? r->mac       : "-",
                     r->ip[0]        ? r->ip        : "-",
                     (long long)r->expires,
                     r->hostname[0]  ? r->hostname  : "-");
    return (n > 0 && (size_t)n < buflen) ? n : -1;
}

int journal_parse(const char *line, lease_record_t *r) {
    char origin[64], op[16], dev[600], mac[32], ip[32], host[128];
    unsigned long long seq;
    long long t, exp;

    if (!line || !r) return -1;
    if (sscanf(line, "%63s %llu %lld %15s %599s %31s %31s %lld %127s",
               origin, &seq, &t, op, dev, mac, ip, &exp, host) != 9)
        return -1;
    if (!valid_node_id(origin) || seq == 0) return -1;
    int opn = op_from_name(op);
    if (!opn) return -1;
    if (strlen(dev) >= sizeof(r->device_id) || strlen(mac) >= sizeof(r->mac) ||
        strlen(host) >= sizeof(r->hostname))
        return -1;
    struct in_addr a;
    if (strcmp(ip, "-") != 0 && inet_pton(AF_INET, ip, &a) != 1) return -1;
    if (opn != JOP_RELEASE && strcmp(ip, "-") == 0) return -1;
    if (opn != JOP_DECLINE && strcmp(dev, "-") == 0) return -1;

    memset(r, 0, sizeof(*r));
    snprintf(r->origin, sizeof(r->origin), "%.15s", origin);   /* validated above */
    r->seq     = seq;
    r->time    = (time_t)t;
    r->op      = opn;
    r->expires = (time_t)exp;
    if (strcmp(dev,  "-") != 0) snprintf(r->device_id, sizeof(r->device_id), "%.255s", dev);
    if (strcmp(mac,  "-") != 0) snprintf(r->mac,       sizeof(r->mac),       "%.17s", mac);
    if (strcmp(ip,   "-") != 0) snprintf(r->ip,        sizeof(r->ip),        "%.15s", ip);
    if (strcmp(host, "-") != 0) snprintf(r->hostname,  sizeof(r->hostname),  "%.63s", host);
    return 0;
}

static int write_all(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

/* Caller holds g_jmutex */
static int append_locked(const char *line, size_t len) {
    if (g_fd < 0) return -1;
    if (write_all(g_fd, line, len) < 0) {
        syslog(LOG_ERR, "journal: write failed: %s", strerror(errno));
        return -1;
    }
    g_end += (off_t)len;
    return 0;
}

int journal_write_local(lease_record_t *r, journal_ticket_t *ticket) {
    char line[JOURNAL_LINE_MAX];

    pthread_mutex_lock(&g_jmutex);
    uint64_t *h = hw_slot(g_self);
    if (!h) { pthread_mutex_unlock(&g_jmutex); return -1; }
    snprintf(r->origin, sizeof(r->origin), "%s", g_self);
    r->seq = ++(*h);
    int n = journal_format(r, line, sizeof(line));
    int rc = (n > 0) ? append_locked(line, (size_t)n) : -1;
    if (ticket) {
        ticket->gen = g_gen;
        ticket->end = g_end;
    }
    pthread_mutex_unlock(&g_jmutex);
    return rc;
}

int journal_write_remote(const lease_record_t *r) {
    char line[JOURNAL_LINE_MAX];

    pthread_mutex_lock(&g_jmutex);
    uint64_t *h = hw_slot(r->origin);
    if (h && r->seq > *h) *h = r->seq;
    int n = journal_format(r, line, sizeof(line));
    if (n > 0) append_locked(line, (size_t)n);
    /* No fsync: if this is lost in a crash our high-water mark drops with it,
     * and the peer simply sends the record again on reconnect. */
    pthread_mutex_unlock(&g_jmutex);
    return 1;
}

/* Group commit: whoever syncs first covers everything written so far, so
 * later tickets inside that range return immediately.  The fdatasync runs on
 * a dup'd fd with no lock held — compaction may swap files underneath us. */
void journal_sync(const journal_ticket_t *ticket) {
    if (!ticket) return;

    pthread_mutex_lock(&g_jmutex);
    if (g_fd < 0 || ticket->gen != g_gen || g_synced >= ticket->end) {
        pthread_mutex_unlock(&g_jmutex);
        return;
    }
    int      fd     = dup(g_fd);
    off_t    target = g_end;
    uint32_t gen    = g_gen;
    pthread_mutex_unlock(&g_jmutex);

    if (fd < 0) return;
    if (fdatasync(fd) < 0)
        syslog(LOG_ERR, "journal: fdatasync failed: %s", strerror(errno));
    close(fd);

    pthread_mutex_lock(&g_jmutex);
    if (gen == g_gen && target > g_synced) g_synced = target;
    pthread_mutex_unlock(&g_jmutex);
}

uint64_t journal_hw(const char *origin) {
    uint64_t v = 0;
    pthread_mutex_lock(&g_jmutex);
    for (int i = 0; i < g_hw_n; i++)
        if (strcmp(g_hw[i].id, origin) == 0) { v = g_hw[i].hw; break; }
    pthread_mutex_unlock(&g_jmutex);
    return v;
}

void journal_note_hw(const char *origin, uint64_t hw) {
    pthread_mutex_lock(&g_jmutex);
    uint64_t *h = hw_slot(origin);
    if (h && hw > *h) {
        *h = hw;
        char line[64];
        int n = snprintf(line, sizeof(line), "# hw %s=%" PRIu64 "\n", origin, hw);
        if (n > 0) append_locked(line, (size_t)n);
    }
    pthread_mutex_unlock(&g_jmutex);
}

/* Caller holds g_jmutex */
static void hw_string_locked(char *buf, size_t buflen, const char *sep,
                             const char *kv) {
    size_t len = 0;
    buf[0] = '\0';
    for (int i = 0; i < g_hw_n; i++) {
        int n = snprintf(buf + len, buflen - len, "%s%s%s%" PRIu64,
                         len ? sep : "", g_hw[i].id, kv, g_hw[i].hw);
        if (n < 0 || (size_t)n >= buflen - len) break;
        len += (size_t)n;
    }
    if (len == 0 && buflen >= 2) snprintf(buf, buflen, "-");
}

void journal_hw_string(char *buf, size_t buflen) {
    pthread_mutex_lock(&g_jmutex);
    hw_string_locked(buf, buflen, ",", ":");
    pthread_mutex_unlock(&g_jmutex);
}

bool journal_record_from_node(const struct Tree_Node *n, lease_record_t *r) {
    if (!n || !n->rec_op) return false;
    memset(r, 0, sizeof(*r));
    snprintf(r->origin, sizeof(r->origin), "%s", n->origin);
    r->seq     = n->seq;
    r->time    = n->rec_time;
    r->op      = n->rec_op;
    r->expires = n->rec_expires;
    if (!n->is_decline)
        snprintf(r->device_id, sizeof(r->device_id), "%s", n->key);
    if (n->mac)
        snprintf(r->mac, sizeof(r->mac), "%s", n->mac);
    snprintf(r->ip, sizeof(r->ip), "%s", n->rec_ip);
    if (n->hostname)
        sanitize_token(n->hostname, r->hostname, sizeof(r->hostname));
    return true;
}

bool journal_record_is_live(const struct Tree_Node *n, time_t now,
                            uint32_t lease_time) {
    if (!n || !n->rec_op) return false;
    switch (n->rec_op) {
        case JOP_LEASE:
        case JOP_DECLINE:
            return n->rec_expires > now;
        case JOP_RELEASE:
            /* Keep release tombstones for one lease period so a peer that
             * missed the release doesn't keep the old lease alive. */
            return n->rec_time + (time_t)lease_time > now;
    }
    return false;
}

/* ---- startup ------------------------------------------------------------- */

static void parse_hw_comment(const char *line) {
    /* "# hw A=12 B=7" */
    const char *p = line + 4;
    char tok[64];
    int  used;
    while (sscanf(p, "%63s%n", tok, &used) == 1) {
        p += used;
        char *eq = strchr(tok, '=');
        if (!eq) continue;
        *eq = '\0';
        if (valid_node_id(tok))
            hw_bump(tok, strtoull(eq + 1, NULL, 10));
    }
}

static int replay(dhcp_config_t *config, char *buf, size_t len) {
    int applied = 0, bad = 0, lines = 0;
    char *save = NULL;
    (void)len;
    for (char *line = strtok_r(buf, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        if (line[0] == '\0') continue;
        if (line[0] == '#') {
            if (strncmp(line, "# hw ", 5) == 0) parse_hw_comment(line);
            continue;
        }
        lines++;
        lease_record_t r;
        if (journal_parse(line, &r) < 0) {
            bad++;
            syslog(LOG_WARNING, "journal: skipping unreadable line: %.80s", line);
            continue;
        }
        hw_bump(r.origin, r.seq);
        if (lease_apply_record(config, &r) > 0) applied++;
    }
    syslog(LOG_INFO, "journal: replayed %d records (%d applied, %d unreadable)",
           lines, applied, bad);
    return 0;
}

static void pick_self_id(dhcp_config_t *config) {
    if (config->node_id && valid_node_id(config->node_id)) {
        snprintf(g_self, sizeof(g_self), "%s", config->node_id);
        return;
    }
    /* Single-server mode: stamp records with the (short) hostname so two
     * standalone servers merged into a cluster later never share an origin. */
    char host[256] = "";
    if (gethostname(host, sizeof(host) - 1) == 0) {
        char *dot = strchr(host, '.');
        if (dot) *dot = '\0';
        size_t j = 0;
        for (size_t i = 0; host[i] && j < NODE_ID_LEN - 1; i++) {
            char c = host[i];
            bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '_' || c == '-';
            g_self[j++] = ok ? c : '-';
        }
        g_self[j] = '\0';
    }
    if (!valid_node_id(g_self))
        snprintf(g_self, sizeof(g_self), "local");
}

int journal_init(dhcp_config_t *config) {
    if (!config || !config->journal_path) return -1;
    pick_self_id(config);
    free(g_path);
    g_path = strdup(config->journal_path);
    if (!g_path) return -1;

    bool fresh = true;
    int rfd = open(g_path, O_RDONLY);
    if (rfd >= 0) {
        struct stat st;
        if (fstat(rfd, &st) == 0 && st.st_size > 0) {
            size_t size = (size_t)st.st_size;
            char  *buf  = malloc(size + 1);
            ssize_t got = buf ? read(rfd, buf, size) : -1;
            if (got > 0) {
                buf[got] = '\0';
                fresh = false;
                /* A crash mid-append can leave a partial last line.  Cut it
                 * off, or the next record would be glued onto it. */
                size_t good = (size_t)got;
                while (good > 0 && buf[good - 1] != '\n') good--;
                if (good < (size_t)got) {
                    syslog(LOG_WARNING, "journal: dropping %zu-byte partial last line",
                           (size_t)got - good);
                    if (truncate(g_path, (off_t)good) < 0)
                        syslog(LOG_ERR, "journal: truncate failed: %s", strerror(errno));
                    buf[good] = '\0';
                }
                replay(config, buf, good);
            }
            free(buf);
        }
        close(rfd);
    }

    g_fd = open(g_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (g_fd < 0) {
        syslog(LOG_ERR, "journal: cannot open %s: %s", g_path, strerror(errno));
        return -1;
    }
    struct stat st;
    g_end = (fstat(g_fd, &st) == 0) ? st.st_size : 0;
    g_synced = g_end;

    if (fresh) {
        pthread_mutex_lock(&g_jmutex);
        append_locked(JOURNAL_HEADER, strlen(JOURNAL_HEADER));
        pthread_mutex_unlock(&g_jmutex);
        int imported = lease_import_legacy(config);
        if (imported > 0)
            syslog(LOG_INFO, "journal: imported %d leases from %s",
                   imported, config->lease_db_path);
        journal_ticket_t t = { g_gen, g_end };
        journal_sync(&t);
    }

    syslog(LOG_INFO, "journal: %s open as origin '%s'", g_path, g_self);
    return 0;
}

void journal_close(void) {
    pthread_mutex_lock(&g_jmutex);
    if (g_fd >= 0) {
        fdatasync(g_fd);
        close(g_fd);
        g_fd = -1;
    }
    pthread_mutex_unlock(&g_jmutex);
}

/* ---- compaction ---------------------------------------------------------- */

typedef struct {
    strbuf_t *sb;
    time_t    now;
    uint32_t  lease_time;
    int       kept;
} compact_ctx_t;

static int compact_visitor(struct Tree_Node *n, void *p) {
    compact_ctx_t *c = p;
    if (!journal_record_is_live(n, c->now, c->lease_time)) return 0;
    lease_record_t r;
    char line[JOURNAL_LINE_MAX];
    if (journal_record_from_node(n, &r)) {
        int len = journal_format(&r, line, sizeof(line));
        if (len > 0) { sb_append(c->sb, line, (size_t)len); c->kept++; }
    }
    return 0;
}

int journal_compact(dhcp_config_t *config) {
    if (!config || !g_path) return -1;

    strbuf_t sb = {0};
    compact_ctx_t c = { &sb, time(NULL), config->lease_time, 0 };

    pthread_mutex_lock(&g_jmutex);

    char hw[1024];
    hw_string_locked(hw, sizeof(hw), " ", "=");
    sb_append(&sb, JOURNAL_HEADER, strlen(JOURNAL_HEADER));
    if (strcmp(hw, "-") != 0) sb_printf(&sb, "# hw %s\n", hw);
    traverse_tree(config->mac_table, compact_visitor, &c);

    if (sb.failed) {
        pthread_mutex_unlock(&g_jmutex);
        sb_free(&sb);
        syslog(LOG_ERR, "journal: compaction out of memory — skipped");
        return -1;
    }

    off_t before = g_end;
    int rc = write_file_atomic(g_path, sb.buf, sb.len);
    if (rc == 0) {
        int nfd = open(g_path, O_WRONLY | O_APPEND);
        if (nfd >= 0) {
            if (g_fd >= 0) close(g_fd);
            g_fd = nfd;
            g_gen++;
            g_end = g_synced = (off_t)sb.len;
        } else {
            syslog(LOG_ERR, "journal: reopen after compaction failed: %s",
                   strerror(errno));
            rc = -1;
        }
    }
    pthread_mutex_unlock(&g_jmutex);
    size_t after = sb.len;
    sb_free(&sb);

    if (rc == 0)
        syslog(LOG_INFO, "journal: compacted %lld → %zu bytes (%d live records)",
               (long long)before, after, c.kept);
    return rc;
}
