#ifndef LEASE_H
#define LEASE_H

#include "types.h"
#include "node.h"
#include "trie.h"
#include "utils.h"

int load_lease_database(dhcp_config_t *config);
int update_lease_database(const char *mac, dhcp_options_t *opts, dhcp_config_t *config);
int compact_lease_database(dhcp_config_t *config); 

int load_static_assignments(dhcp_config_t *config);
int add_static_assignment(const char *mac, const char *ip, dhcp_config_t *config);

int load_blacklist(dhcp_config_t *config);
int add_to_blacklist(const char *mac, dhcp_config_t *config);
bool is_blacklisted(dhcp_config_t *config, const char *mac);

#endif /* LEASE_H */ 