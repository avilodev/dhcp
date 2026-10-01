#ifndef HA_H
#define HA_H

#include "types.h"

// High availability: who answers which client, who may hand out which address

// This node's own state
#define HA_STARTING 0 // syncing with peers — not answering DHCP yet
#define HA_NORMAL 1 // answering
#define HA_ORPHAN 2 // not in the member list (or no config yet)

// How this node sees a peer
#define PEER_DOWN 0 // never connected, or heartbeats stopped
#define PEER_STARTING 1 // connected, still syncing
#define PEER_UP 2 // connected and answering
#define PEER_PARTNER_DOWN 3 // declared down: we may use its slice after MCLT

void ha_setup(dhcp_config_t *config); // once at startup

// (Re)load the member list.  Returns 0, or -1 if this node isn't in it.
int ha_configure(const cluster_member_t *members, int n,
				 uint32_t cfgver, const char *cfgsha);

bool ha_enabled(void); // cluster mode at all
bool ha_is_controller(void);
bool ha_serving(void); // answer DHCP right now? (always true standalone)
int ha_self_state(void);
const char *ha_state_name(int s);
const char *ha_peer_state_name(int s);

// Does this node own the client's bucket?
bool ha_owns_client(const char *device_id);
// Is the owner a node on OUR address
bool ha_address_owns_client(const char *device_id);
// The id of the node that owns this client's bucket (false if none serving)
bool ha_bucket_owner(const char *device_id, char *id, size_t idlen);
// Does another DHCP node in cluster.conf use our server address?
bool ha_address_shared(void);
uint32_t ha_lease_time(uint32_t configured);

// Snapshot of slice ownership for one find_free_ip() scan, so we don't take the
typedef struct {
	bool enabled;
	bool frozen; // peers disagree about config → no new addresses
	int n;
	char ids[MAX_MEMBERS][NODE_ID_LEN];
	bool usable[MAX_MEMBERS]; // self, or partner-down for longer than MCLT
} ha_alloc_ctx_t;
void ha_alloc_begin(ha_alloc_ctx_t *ctx);
bool ha_alloc_ok(const ha_alloc_ctx_t *ctx, uint32_t ip_host);
bool ha_slice_is_mine(uint32_t ip_host);

// Peer link

int ha_member_count(void);
bool ha_member(int i, cluster_member_t *out);
int ha_member_index(const char *id);
void ha_config_version(uint32_t *ver, char *sha, size_t shalen);

void ha_peer_seen(const char *id, int remote_state, time_t remote_time,
				  uint32_t cfgver, const char *cfgsha);
void ha_peer_lost(const char *id);
int ha_partner_down(const char *id, char *err, size_t errlen);

int ha_peer_view(const char *id); // PEER_* (PEER_DOWN if unknown)

// Peer link reports: have all connected peers caught us up, and is every member
void ha_sync_status(bool caught_up, bool all_connected);
void ha_set_timers(uint32_t mclt, uint32_t peer_timeout, uint32_t auto_pd);
// State machine; call about once a second.
bool ha_tick(time_t now);

// Human-readable status (for `--ctl status`)
void ha_status(char *buf, size_t buflen);

#endif /* HA_H */
