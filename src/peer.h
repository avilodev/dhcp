#ifndef PEER_H
#define PEER_H

#include "types.h"

// Peer link between cluster members.

// Load the key and bind the listen socket — before dropping root
int peer_init(dhcp_config_t *config);
int peer_start(void);
void peer_stop(void);

// Worker threads: send a freshly committed journal line to every peer
void peer_broadcast_record(const char *line);

// Forward DHCP packets to the owning sibling.
int peer_forward_packet(const char *node_id, const void *pkt, size_t len, int ifindex);

// Where packets forwarded to us go (main.c queues them for the workers)
typedef void (*peer_packet_handler_t)(const void *pkt, size_t len, int ifindex);
void peer_set_packet_handler(peer_packet_handler_t fn);

// Controller: (re)read cluster_dir and push it if it changed
int peer_controller_load(bool force, char *msg, size_t msglen);

// `dhcp_server --ctl <conf> <command...>` — talk to the local server
int peer_ctl_main(dhcp_config_t *config, int argc, char **argv);

#endif /* PEER_H */
