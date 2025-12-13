#ifndef UTILS_H
#define UTILS_H

#include "types.h"
#include "trie.h"
#include "node.h"

/* Device identification - uses Client ID (Option 61) if available, else MAC */
char *get_device_identifier(const char *mac, dhcp_options_t *opts, char *buffer, size_t buflen);

/* IP address allocation and management */
char *allocate_ip_address(const char *mac, dhcp_options_t *opts, dhcp_config_t *config);
char *find_existing_lease(const char *device_id, dhcp_config_t *config);
char *check_static_assignment(const char *mac, dhcp_config_t *config);
char *find_free_ip(dhcp_config_t *config);
int release_ip_address(const char *mac, dhcp_config_t *config);
int mark_ip_declined(uint32_t ip, dhcp_config_t *config);
bool is_ip_available(const char *ip, dhcp_config_t *config);

/* Validation functions */
bool validate_mac_address(const char *mac); 

/* Time utilities */
char *format_timestamp(time_t t);
time_t parse_timestamp(const char *str);

/* IP conversion utilities */
uint32_t ip_string_to_uint32(const char *ip);
void uint32_to_ip_string(uint32_t ip, char *buf, size_t buflen);
void format_mac_address(const uint8_t *mac, char *buf, size_t buflen);

#endif /* UTILS_H */