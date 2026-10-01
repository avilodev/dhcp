#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>

#include "lease.h"
#include "node.h"
#include "trie.h"
#include "types.h"

typedef struct {
	const char *conf_path; // NULL = built-in default path
	const char *node_id;   // --node-id overrides dhcp.conf
	bool controller;	   // --controller
} cli_options_t;

int init_config(const cli_options_t *opts);
void cleanup_config(void);

int init_data_structures(void);
bool validate_ip_address(const char *ip);

int create_server_socket(void);
int create_own_socket(const char *server_ip);

#endif /* CONFIG_H */
