#ifndef PEER_H
#define PEER_H

#include "types.h"

/* The peer link: one TCP connection per pair of cluster members, carrying
 * one text line per message, each signed with HMAC-SHA256 under the shared
 * peer_key.  It carries:
 *
 *   HELLO / HB          identity, state, clock, config version, high-water marks
 *   ENTRY <journal>     a lease change (live, or in answer to SYNC)
 *   SYNC / SYNCDONE     "send me origin X's records after seq N"
 *   CFG*                the controller pushing cluster.conf + shared lists
 *   FWD                 a DHCP packet handed to the sibling (same address) that owns it
 *   PDOWN / STATUS / PUSH   operator commands (from the controller or --ctl)
 *
 * Signatures cover a per-connection nonce pair and a message counter, so a
 * recorded conversation can't be replayed or reordered. */

/* Load the key and bind the listen socket — before dropping root */
int  peer_init(dhcp_config_t *config);
int  peer_start(void);
void peer_stop(void);

/* Worker threads: send a freshly committed journal line to every peer */
void peer_broadcast_record(const char *line);

/* Hand a received DHCP packet to a sibling node sharing our address (it owns
 * the client).  Returns 0 if queued for sending. */
int  peer_forward_packet(const char *node_id, const void *pkt, size_t len, int ifindex);

/* Where packets forwarded to us go (main.c queues them for the workers) */
typedef void (*peer_packet_handler_t)(const void *pkt, size_t len, int ifindex);
void peer_set_packet_handler(peer_packet_handler_t fn);

/* Controller: (re)read cluster_dir and push it if it changed */
int  peer_controller_load(bool force, char *msg, size_t msglen);

/* `dhcp_server --ctl <conf> <command...>` — talk to the local server */
int  peer_ctl_main(dhcp_config_t *config, int argc, char **argv);

#endif /* PEER_H */
