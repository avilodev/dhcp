#define _GNU_SOURCE
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include "cluster.h"
#include "config.h"
#include "ha.h"
#include "lease.h"

extern pthread_mutex_t g_server_mutex;

const char *const CLUSTER_FILES[CLUSTER_NFILES] = {
    "cluster.conf", "static_list.txt", "blacklist.txt",
};

static char *dupstr(const char *s) { return s ? strdup(s) : NULL; }

static void replace(char **dst, const char *src) {
    if (!src) return;
    free(*dst);
    *dst = strdup(src);
}

void cluster_config_free(cluster_config_t *cc) {
    free(cc->start_ip); free(cc->end_ip); free(cc->subnet_mask);
    free(cc->gateway);  free(cc->domain);
    for (int i = 0; i < 4; i++) { free(cc->dns[i]); free(cc->ntp[i]); }
    memset(cc, 0, sizeof(*cc));
}

int cluster_parse(const char *text, int default_port, cluster_config_t *cc,
                  char *err, size_t errlen) {
    memset(cc, 0, sizeof(*cc));
    if (!text) { snprintf(err, errlen, "empty cluster.conf"); return -1; }

    char *copy = strdup(text);
    if (!copy) { snprintf(err, errlen, "out of memory"); return -1; }

    int lineno = 0;
    char *save;
    for (char *line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0' || *p == '\r') continue;

        char key[64] = "", a[256] = "", b[256] = "", c[64] = "";
        int got = sscanf(p, "%63s %255s %255s %63s", key, a, b, c);
        if (got < 2) continue;

        if (strcmp(key, "node") == 0 || strcmp(key, "controller") == 0) {
            if (got < 3) {
                snprintf(err, errlen, "line %d: expected '%s <id> <ip> [port]'",
                         lineno, key);
                goto fail;
            }
            if (cc->n_members >= MAX_MEMBERS) {
                snprintf(err, errlen, "more than %d members", MAX_MEMBERS);
                goto fail;
            }
            if (!valid_node_id(a)) {
                snprintf(err, errlen, "line %d: bad id '%s' (1–15 of A-Z a-z 0-9 _ -)",
                         lineno, a);
                goto fail;
            }
            if (!validate_ip_address(b)) {
                snprintf(err, errlen, "line %d: bad IP '%s'", lineno, b);
                goto fail;
            }
            int port = (got >= 4) ? atoi(c) : default_port;
            if (port <= 0 || port > 65535) {
                snprintf(err, errlen, "line %d: bad port '%s'", lineno, c);
                goto fail;
            }
            for (int i = 0; i < cc->n_members; i++) {
                if (strcmp(cc->members[i].id, a) == 0) {
                    snprintf(err, errlen, "line %d: duplicate id %s", lineno, a);
                    goto fail;
                }
            }
            cluster_member_t *m = &cc->members[cc->n_members++];
            snprintf(m->id, sizeof(m->id), "%.15s", a);
            snprintf(m->ip, sizeof(m->ip), "%.15s", b);
            m->port = port;
            m->role = key[0] == 'n' ? ROLE_NODE : ROLE_CONTROLLER;
            continue;
        }

        bool ip_key = strcmp(key, "start_ip") == 0 || strcmp(key, "end_ip") == 0 ||
                      strcmp(key, "subnet_mask") == 0 || strcmp(key, "gateway") == 0 ||
                      strcmp(key, "dns") == 0 || strcmp(key, "ntp") == 0;
        if (ip_key && !validate_ip_address(a)) {
            snprintf(err, errlen, "line %d: bad IP for %s: '%s'", lineno, key, a);
            goto fail;
        }

        if      (strcmp(key, "start_ip")    == 0) replace(&cc->start_ip, a);
        else if (strcmp(key, "end_ip")      == 0) replace(&cc->end_ip, a);
        else if (strcmp(key, "subnet_mask") == 0) replace(&cc->subnet_mask, a);
        else if (strcmp(key, "gateway")     == 0) replace(&cc->gateway, a);
        else if (strcmp(key, "domain")      == 0) replace(&cc->domain, a);
        else if (strcmp(key, "dns") == 0) {
            if (cc->dns_count < 4) cc->dns[cc->dns_count++] = dupstr(a);
        }
        else if (strcmp(key, "ntp") == 0) {
            if (cc->ntp_count < 4) cc->ntp[cc->ntp_count++] = dupstr(a);
        }
        else if (strcmp(key, "lease_time") == 0)   cc->lease_time   = (uint32_t)strtoul(a, NULL, 10);
        else if (strcmp(key, "mclt") == 0)         cc->mclt         = (uint32_t)strtoul(a, NULL, 10);
        else if (strcmp(key, "peer_timeout") == 0) cc->peer_timeout = (uint32_t)strtoul(a, NULL, 10);
        else if (strcmp(key, "auto_partner_down") == 0) {
            cc->auto_partner_down     = (uint32_t)strtoul(a, NULL, 10);
            cc->has_auto_partner_down = true;
        }
        else if (strcmp(key, "server_ip") == 0 || strcmp(key, "node_id") == 0 ||
                 strcmp(key, "role") == 0) {
            syslog(LOG_WARNING, "cluster.conf line %d: '%s' is per-node — it "
                   "belongs in that node's dhcp.conf; ignored", lineno, key);
        }
        else {
            syslog(LOG_WARNING, "cluster.conf line %d: unknown key '%s'", lineno, key);
        }
    }
    free(copy);

    int nodes = 0;
    for (int i = 0; i < cc->n_members; i++)
        if (cc->members[i].role == ROLE_NODE) nodes++;
    if (nodes == 0) {
        snprintf(err, errlen, "no 'node' lines — a cluster needs at least one DHCP node");
        cluster_config_free(cc);
        return -1;
    }
    if (cc->start_ip && cc->end_ip &&
        ntohl(inet_addr(cc->start_ip)) > ntohl(inet_addr(cc->end_ip))) {
        snprintf(err, errlen, "start_ip is after end_ip");
        cluster_config_free(cc);
        return -1;
    }
    return 0;

fail:
    free(copy);
    cluster_config_free(cc);
    return -1;
}

bool cluster_same_members(const cluster_config_t *a, const cluster_config_t *b) {
    if (a->n_members != b->n_members) return false;
    for (int i = 0; i < a->n_members; i++) {
        bool found = false;
        for (int j = 0; j < b->n_members && !found; j++)
            found = strcmp(a->members[i].id, b->members[j].id) == 0 &&
                    a->members[i].role == b->members[j].role;
        if (!found) return false;
    }
    return true;
}

/* ---- bundle -------------------------------------------------------------- */

static int read_into(const char *path, strbuf_t *sb) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char chunk[4096];
    ssize_t n;
    while ((n = read(fd, chunk, sizeof(chunk))) > 0)
        sb_append(sb, chunk, (size_t)n);
    close(fd);
    return n < 0 ? -1 : 0;
}

void cluster_bundle_free(cluster_bundle_t *b) {
    for (int i = 0; i < CLUSTER_NFILES; i++) sb_free(&b->file[i]);
    b->sha[0] = '\0';
}

void cluster_bundle_hash(cluster_bundle_t *b) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { b->sha[0] = '\0'; return; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    for (int i = 0; i < CLUSTER_NFILES; i++) {
        char hdr[64];
        int n = snprintf(hdr, sizeof(hdr), "%s\n%zu\n", CLUSTER_FILES[i], b->file[i].len);
        EVP_DigestUpdate(ctx, hdr, (size_t)n);
        if (b->file[i].len) EVP_DigestUpdate(ctx, b->file[i].buf, b->file[i].len);
    }
    EVP_DigestFinal_ex(ctx, md, &mdlen);
    EVP_MD_CTX_free(ctx);
    for (int i = 0; i < 8; i++) snprintf(b->sha + i * 2, 3, "%02x", md[i]);
}

int cluster_bundle_read(const char *dir, cluster_bundle_t *b) {
    memset(b, 0, sizeof(*b));
    for (int i = 0; i < CLUSTER_NFILES; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, CLUSTER_FILES[i]);
        if (read_into(path, &b->file[i]) < 0 && i == 0) {
            cluster_bundle_free(b);
            return -1;               /* cluster.conf is required; the lists aren't */
        }
        /* Files travel line by line, so normalise the final newline — both
         * ends must hash identical bytes. */
        strbuf_t *f = &b->file[i];
        if (f->len > 0 && f->buf[f->len - 1] != '\n')
            sb_append(f, "\n", 1);
    }
    cluster_bundle_hash(b);
    return 0;
}

int cluster_bundle_write(const char *dir, const cluster_bundle_t *b) {
    mkdir(dir, 0755);
    for (int i = 0; i < CLUSTER_NFILES; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, CLUSTER_FILES[i]);
        if (write_file_atomic(path, b->file[i].buf ? b->file[i].buf : "",
                              b->file[i].len) < 0)
            return -1;
    }
    return 0;
}

int cluster_version_read(const char *dir, uint32_t *ver, char *sha, size_t shalen) {
    char path[4096];
    snprintf(path, sizeof(path), "%s/version", dir);
    FILE *fp = fopen(path, "r");
    *ver = 0;
    if (sha && shalen) sha[0] = '\0';
    if (!fp) return -1;
    unsigned long v = 0;
    char s[64] = "";
    int got = fscanf(fp, "%lu %63s", &v, s);
    fclose(fp);
    if (got < 1) return -1;
    *ver = (uint32_t)v;
    if (sha && shalen && got == 2) snprintf(sha, shalen, "%s", s);
    return 0;
}

int cluster_version_write(const char *dir, uint32_t ver, const char *sha) {
    char path[4096], buf[128];
    snprintf(path, sizeof(path), "%s/version", dir);
    int n = snprintf(buf, sizeof(buf), "%u %s\n", ver, sha);
    return write_file_atomic(path, buf, (size_t)n);
}

/* ---- apply --------------------------------------------------------------- */

/* Caller holds g_server_mutex */
static void apply_shared(dhcp_config_t *config, const cluster_config_t *cc) {
    replace(&config->start_ip,    cc->start_ip);
    replace(&config->end_ip,      cc->end_ip);
    replace(&config->subnet_mask, cc->subnet_mask);
    replace(&config->gateway,     cc->gateway);
    replace(&config->domain_name, cc->domain);
    if (cc->dns_count > 0) {
        for (int i = 0; i < 4; i++) {
            free(config->dns_servers[i]);
            config->dns_servers[i] = dupstr(i < cc->dns_count ? cc->dns[i] : NULL);
        }
        config->dns_count = cc->dns_count;
    }
    if (cc->ntp_count > 0) {
        for (int i = 0; i < 4; i++) {
            free(config->ntp_servers[i]);
            config->ntp_servers[i] = dupstr(i < cc->ntp_count ? cc->ntp[i] : NULL);
        }
        config->ntp_count = cc->ntp_count;
    }
    if (cc->lease_time)   config->lease_time   = cc->lease_time;
    if (cc->mclt)         config->mclt         = cc->mclt;
    if (cc->peer_timeout) config->peer_timeout = cc->peer_timeout;
    if (cc->has_auto_partner_down) config->auto_partner_down = cc->auto_partner_down;
}

int cluster_load(dhcp_config_t *config, uint32_t *ver_out, char *sha_out, size_t shalen) {
    if (!config->cluster_dir) return -1;

    cluster_bundle_t b;
    if (cluster_bundle_read(config->cluster_dir, &b) < 0) {
        syslog(LOG_WARNING, "cluster: no %s/cluster.conf yet%s", config->cluster_dir,
               config->controller_ip ? " — waiting for the controller to push one" : "");
        return -1;
    }

    char err[256];
    cluster_config_t cc;
    if (cluster_parse(b.file[0].buf, config->peer_port, &cc, err, sizeof(err)) < 0) {
        syslog(LOG_ERR, "cluster: %s/cluster.conf rejected: %s", config->cluster_dir, err);
        cluster_bundle_free(&b);
        return -1;
    }

    uint32_t ver = 0;
    char stored_sha[64];
    cluster_version_read(config->cluster_dir, &ver, stored_sha, sizeof(stored_sha));

    char path[4096];
    pthread_mutex_lock(&g_server_mutex);
    apply_shared(config, &cc);
    snprintf(path, sizeof(path), "%s/static_list.txt", config->cluster_dir);
    replace(&config->static_path, path);
    snprintf(path, sizeof(path), "%s/blacklist.txt", config->cluster_dir);
    replace(&config->blacklist_path, path);
    reload_static_assignments(config);
    reload_blacklist(config);
    ha_set_timers(config->mclt, config->peer_timeout, config->auto_partner_down);
    ha_configure(cc.members, cc.n_members, ver, b.sha);
    lease_drop_foreign_offers(config);
    pthread_mutex_unlock(&g_server_mutex);
    snapshot_mark_dirty();

    syslog(LOG_INFO, "cluster: loaded config v%u/%s — %d members, pool %s–%s",
           ver, b.sha, cc.n_members, config->start_ip, config->end_ip);
    if (ver_out) *ver_out = ver;
    if (sha_out) snprintf(sha_out, shalen, "%s", b.sha);
    cluster_config_free(&cc);
    cluster_bundle_free(&b);
    return 0;
}
