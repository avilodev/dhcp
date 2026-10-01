#ifndef UTILS_H
#define UTILS_H

#include "node.h"
#include "trie.h"
#include "types.h"

// Identifies devices by Client ID when present, otherwise by MAC.
char *get_device_identifier(const char *mac, dhcp_options_t *opts,
							char *buffer, size_t buflen);

char *allocate_ip_address(const char *mac, dhcp_options_t *opts,
						  dhcp_config_t *config);
char *find_existing_lease(const char *device_id, dhcp_config_t *config);
char *check_static_assignment(const char *mac, dhcp_config_t *config);
char *find_free_ip(dhcp_config_t *config, const char *device_id);

// IP ownership
void lease_bind_ip(dhcp_config_t *config, struct tree_node *node, const char *ip);
void lease_drop_ip(dhcp_config_t *config, struct tree_node *node);
// The lease-tree node currently holding ip, or NULL if it's free
struct tree_node *ip_holder(dhcp_config_t *config, const char *ip);
struct tree_node *get_or_create_node(struct tree *tree, const char *key);
// ip in network byte order; true if inside start_ip..end_ip
bool ip_in_pool(dhcp_config_t *config, uint32_t ip);

// Write-temp + fsync + rename + fsync(dir): the file is either the old version
int write_file_atomic(const char *path, const char *buf, size_t len);

// Growable string buffer for building files/messages in memory
typedef struct {
	char *buf;
	size_t len;
	size_t cap;
	bool failed; // an allocation failed — contents are incomplete
} strbuf_t;
void sb_append(strbuf_t *sb, const char *s, size_t n);
void sb_printf(strbuf_t *sb, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void sb_free(strbuf_t *sb);

// Cluster node ids: 1–15 chars of [A-Za-z0-9_-]
bool valid_node_id(const char *id);
// Copy s into out as a safe token.
void sanitize_token(const char *s, char *out, size_t outlen);

// Returns how many ACKed leases were dropped (so the snapshot can refresh)
int sweep_expired_leases(dhcp_config_t *config);

int update_lease_expiry(const char *device_id, time_t expires,
						dhcp_config_t *config);

void format_mac_address(const uint8_t *mac, char *buf, size_t buflen);

#endif /* UTILS_H */
