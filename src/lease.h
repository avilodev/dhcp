#ifndef LEASE_H
#define LEASE_H

#include "types.h"
#include "node.h"
#include "trie.h"
#include "utils.h"
#include "journal.h"

/* ---- Journal-backed lease changes -----------------------------------------
 * Every function here runs under g_server_mutex. */

/* A local change that has been written to the journal (not yet fsync'd).
 * The worker must journal_sync(&ticket) BEFORE replying to the client, then
 * hand `line` to peer_broadcast_record() so the other nodes learn about it. */
typedef struct {
    bool             has;
    char             line[JOURNAL_LINE_MAX];
    journal_ticket_t ticket;
} lease_commit_t;

/* DHCPACK: node already holds its IP and expiry; record it */
int lease_commit_ack(dhcp_config_t *config, struct Tree_Node *node,
                     const char *mac, lease_commit_t *out);
/* DHCPRELEASE */
int lease_commit_release(dhcp_config_t *config, struct Tree_Node *node,
                         lease_commit_t *out);
/* DHCPDECLINE: hold ip out of the pool for one lease period */
int lease_commit_decline(dhcp_config_t *config, const char *ip,
                         struct Tree_Node *decliner, lease_commit_t *out);

/* Apply one journal record (replay or from a peer).  Newest record per key
 * wins; if two devices claim one IP, the newer lease keeps it.
 * Returns 1 if it changed state, 0 if it was stale or ignored. */
int lease_apply_record(dhcp_config_t *config, const lease_record_t *r);

/* One-time import of an old-format members.txt into a fresh journal */
int lease_import_legacy(dhcp_config_t *config);

/* In a cluster, accept a lease we have no record of (e.g. the issuing node
 * died before its journal line reached us) if the address is ours to give:
 * inside the pool, not held by anyone else, not static.  ip is network order. */
bool lease_adopt(dhcp_config_t *config, const char *device_id, uint32_t ip);

/* Conflict check results for a fresh offer (see probe.c) */
void lease_offer_verified(dhcp_config_t *config, const char *device_id, const char *ip);
/* Something answered for ip: hold it back (journaled like a DECLINE) */
int  lease_offer_conflict(dhcp_config_t *config, const char *device_id,
                          const char *ip, const char *who, lease_commit_t *out);

/* After the member list changes: drop un-ACKed offers for addresses that are
 * no longer in this node's slice, so we never ACK them. */
int lease_drop_foreign_offers(dhcp_config_t *config);

/* ---- members.txt snapshot ---------------------------------------------- */

/* Any thread: "members.txt is out of date".  The main loop rewrites it at
 * most once a second. */
void snapshot_mark_dirty(void);
bool snapshot_take_dirty(void);

/* Build the snapshot text (caller holds g_server_mutex); free() the result */
char *snapshot_build(dhcp_config_t *config, size_t *len);
/* Write it atomically (takes g_file_mutex) */
int   snapshot_save(dhcp_config_t *config, const char *buf, size_t len);

/* ---- static list / blacklist ------------------------------------------- */

int load_static_assignments(dhcp_config_t *config);

int load_blacklist(dhcp_config_t *config);
bool is_blacklisted(dhcp_config_t *config, const char *mac);

/* Hot-reload under g_server_mutex — add/update entries only, never remove */
int reload_static_assignments(dhcp_config_t *config);
int reload_blacklist(dhcp_config_t *config);

/* Write formatted lease table to dump_path (uses g_file_mutex internally) */
int dump_lease_table(dhcp_config_t *config);

#endif /* LEASE_H */
