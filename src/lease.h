#ifndef LEASE_H
#define LEASE_H

#include "journal.h"
#include "node.h"
#include "trie.h"
#include "types.h"
#include "utils.h"

// Journal-backed lease changes

// A local change that has been written to the journal (not yet fsync'd).
typedef struct {
	bool has;
	char line[JOURNAL_LINE_MAX];
	journal_ticket_t ticket;
} lease_commit_t;

// DHCPACK: node already holds its IP and expiry; record it
int lease_commit_ack(dhcp_config_t *config, struct tree_node *node,
					 const char *mac, lease_commit_t *out);
// DHCPRELEASE
int lease_commit_release(dhcp_config_t *config, struct tree_node *node,
						 lease_commit_t *out);
// DHCPDECLINE: hold ip out of the pool for one lease period
int lease_commit_decline(dhcp_config_t *config, const char *ip,
						 struct tree_node *decliner, lease_commit_t *out);

// Apply a journal record using newest-record-wins ordering.
int lease_apply_record(dhcp_config_t *config, const lease_record_t *r);

// One-time import of an old-format members.txt into a fresh journal
int lease_import_legacy(dhcp_config_t *config);

// Adopt an unrecorded lease when the address is available locally.
bool lease_adopt(dhcp_config_t *config, const char *device_id, uint32_t ip);

// Conflict check results for a fresh offer (see probe.c)
void lease_offer_verified(dhcp_config_t *config, const char *device_id, const char *ip);
// Something answered for ip: hold it back (journaled like a DECLINE)
int lease_offer_conflict(dhcp_config_t *config, const char *device_id,
						 const char *ip, const char *who, lease_commit_t *out);

// Drop offers outside this node's current slice.
int lease_drop_foreign_offers(dhcp_config_t *config);

// Members snapshot

// Any thread: "members.txt is out of date".
void snapshot_mark_dirty(void);
bool snapshot_take_dirty(void);

// Build the snapshot text (caller holds g_server_mutex); free() the result
char *snapshot_build(dhcp_config_t *config, size_t *len);
// Write it atomically (takes g_file_mutex)
int snapshot_save(dhcp_config_t *config, const char *buf, size_t len);

// Static list and blacklist

int load_static_assignments(dhcp_config_t *config);

int load_blacklist(dhcp_config_t *config);
bool is_blacklisted(dhcp_config_t *config, const char *mac);

// Hot-reload under g_server_mutex — add/update entries only, never remove
int reload_static_assignments(dhcp_config_t *config);
int reload_blacklist(dhcp_config_t *config);

// Write formatted lease table to dump_path (uses g_file_mutex internally)
int dump_lease_table(dhcp_config_t *config);

#endif /* LEASE_H */
