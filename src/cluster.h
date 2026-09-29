#ifndef CLUSTER_H
#define CLUSTER_H

#include "types.h"
#include "utils.h"

/* Shared cluster configuration: cluster_dir/cluster.conf plus the shared
 * static list and blacklist.  On the controller these files are the source;
 * on nodes they're copies the controller pushed (or you copied by hand). */

#define CLUSTER_NFILES 3
extern const char *const CLUSTER_FILES[CLUSTER_NFILES];  /* cluster.conf, static_list.txt, blacklist.txt */

typedef struct {
    cluster_member_t members[MAX_MEMBERS];
    int      n_members;
    char    *start_ip, *end_ip, *subnet_mask, *gateway, *domain;
    char    *dns[4];
    int      dns_count;
    char    *ntp[4];
    int      ntp_count;
    uint32_t lease_time, mclt, peer_timeout, auto_partner_down;
    bool     has_auto_partner_down;
} cluster_config_t;

/* Parse + validate cluster.conf text.  default_port is used for members
 * without an explicit port. */
int  cluster_parse(const char *text, int default_port, cluster_config_t *cc,
                   char *err, size_t errlen);
void cluster_config_free(cluster_config_t *cc);
bool cluster_same_members(const cluster_config_t *a, const cluster_config_t *b);

typedef struct {
    strbuf_t file[CLUSTER_NFILES];
    char     sha[17];            /* first 16 hex chars of SHA-256 over all files */
} cluster_bundle_t;

int  cluster_bundle_read(const char *dir, cluster_bundle_t *b);  /* -1 if no cluster.conf */
void cluster_bundle_hash(cluster_bundle_t *b);
void cluster_bundle_free(cluster_bundle_t *b);
int  cluster_bundle_write(const char *dir, const cluster_bundle_t *b);

int  cluster_version_read(const char *dir, uint32_t *ver, char *sha, size_t shalen);
int  cluster_version_write(const char *dir, uint32_t ver, const char *sha);

/* Read cluster_dir and apply it: shared settings, member list, static list
 * and blacklist.  Takes g_server_mutex.  ver_out/sha_out may be NULL. */
int  cluster_load(dhcp_config_t *config, uint32_t *ver_out, char *sha_out, size_t shalen);

#endif /* CLUSTER_H */
