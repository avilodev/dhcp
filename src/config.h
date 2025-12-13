#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <string.h>

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h> 
#include <stdint.h>
#include <syslog.h>

#include "types.h" 
#include "node.h"
#include "trie.h"
#include "lease.h"

int init_config(int argc, char **argv);
void cleanup_config(void);

int init_data_structures(void);
bool validate_ip_address(const char *ip);

int create_server_socket(void);

#endif /* CONFIG_H */