#ifndef UTILS_H
#define UTILS_H

#include "types.h"
#include "trie.h"
#include "node.h"

/* Device identification - uses Client ID (Option 61) if present, else MAC */
char *get_device_identifier(const char *mac, dhcp_options_t *opts,
                            char *buffer, size_t buflen);

char *allocate_ip_address(const char *mac, dhcp_options_t *opts,
                          dhcp_config_t *config);
char *find_existing_lease(const char *device_id, dhcp_config_t *config);
char *check_static_assignment(const char *mac, dhcp_config_t *config);
char *find_free_ip(dhcp_config_t *config, const char *device_id);

int release_ip_address(const char *device_id, dhcp_config_t *config);
void sweep_expired_leases(dhcp_config_t *config);

int mark_ip_declined(uint32_t ip, const char *device_id,
                     dhcp_config_t *config);

int update_lease_expiry(const char *device_id, time_t expires,
                        dhcp_config_t *config);

void format_mac_address(const uint8_t *mac, char *buf, size_t buflen);

#endif /* UTILS_H */
