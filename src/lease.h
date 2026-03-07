#ifndef LEASE_H
#define LEASE_H

#include "types.h"
#include "node.h"
#include "trie.h"
#include "utils.h"

int load_lease_database(dhcp_config_t *config);
/* mac, device_id, ip, and hostname are all explicit — no mac_table access
 * so this can be called safely outside g_server_mutex. */
int update_lease_database(const char *mac, const char *device_id,
                          const char *ip, const char *hostname,
                          dhcp_config_t *config);
int compact_lease_database(dhcp_config_t *config);
/* Remove a single entry from the lease database by device_id (for DHCPRELEASE) */
int remove_lease_from_database(const char *device_id, dhcp_config_t *config);

int load_static_assignments(dhcp_config_t *config);
int add_static_assignment(const char *mac, const char *ip, dhcp_config_t *config);

int load_blacklist(dhcp_config_t *config);
int add_to_blacklist(const char *mac, dhcp_config_t *config);
bool is_blacklisted(dhcp_config_t *config, const char *mac);

/* Hot-reload under g_server_mutex — add/update entries only, never remove */
int reload_static_assignments(dhcp_config_t *config);
int reload_blacklist(dhcp_config_t *config);

/* Write formatted lease table to dump_path (uses g_file_mutex internally) */
int dump_lease_table(dhcp_config_t *config);

#endif /* LEASE_H */ 