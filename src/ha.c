#define _GNU_SOURCE
#include "ha.h"
#include "journal.h"
#include "utils.h"
#include <inttypes.h>
#include <pthread.h>

#define SKEW_WARN_SECS 5
#define SKEW_REFUSE_SECS 30

typedef struct {
	cluster_member_t m;
	int view; // PEER_*
	bool connected;
	time_t last_heard;
	time_t down_since;
	int remote_state; // HA_* as the peer reports it
	uint32_t cfgver;
	char cfgsha[17];
	long skew; // their clock minus ours, seconds
	bool skew_warned;
	time_t pdown_since;
} peer_t;

static pthread_mutex_t g_ha = PTHREAD_MUTEX_INITIALIZER;

static bool g_enabled = false;
static int g_role = ROLE_NODE;
static char g_self[NODE_ID_LEN];
static int g_state = HA_ORPHAN;
static time_t g_started = 0;
static bool g_caught_up = false;
static bool g_all_connected = false;

static peer_t g_peers[MAX_MEMBERS]; // every member, self included
static int g_n = 0;
static int g_self_idx = -1;
static uint32_t g_cfgver = 0;
static char g_cfgsha[17] = "";

static uint32_t g_mclt = DEFAULT_MCLT;
static uint32_t g_peer_timeout = DEFAULT_PEER_TIMEOUT;
static uint32_t g_auto_pd = 0;

static bool g_own_bucket[256];
static bool g_addr_bucket[256]; // owned by a node sharing our address (us included)
static int g_bucket_owner[256]; // member index, -1 = nobody serving
static int g_owned_buckets = 0;
static bool g_addr_shared = false; // another DHCP node uses our server address

// Hashing

static uint64_t fnv1a64(const char *s) {
	uint64_t h = 0xcbf29ce484222325ULL;

	for(; *s; s++) {
		h ^= (unsigned char)*s;
		h *= 0x100000001b3ULL;
	}

	return h;
}

static uint64_t mix64(uint64_t z) {
	z += 0x9e3779b97f4a7c15ULL;
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;

	return z ^ (z >> 31);
}

// Rendezvous (highest-random-weight) score: the member with the highest score
static uint64_t score(uint64_t key, const char *id) {
	return mix64(fnv1a64(id) ^ mix64(key));
}

static int bucket_of(const char *device_id) {
	return (int)(mix64(fnv1a64(device_id)) >> 56);
}

// Helpers

static int find_locked(const char *id) {
	for(int i = 0; i < g_n; i++)
		if(strcmp(g_peers[i].m.id, id) == 0)
			return i;

	return -1;
}

static bool is_dhcp_node(int i) {
	return g_peers[i].m.role == ROLE_NODE;
}

static bool serving_locked(int i) {
	if(!is_dhcp_node(i))
		return false;
	if(i == g_self_idx)
		return g_state == HA_NORMAL;

	return g_peers[i].view == PEER_UP;
}

static void recompute_buckets_locked(void) {
	g_owned_buckets = 0;

	for(int b = 0; b < 256; b++) {
		int best = -1;
		uint64_t best_score = 0;

		for(int i = 0; i < g_n; i++) {
			if(!serving_locked(i))
				continue;
			uint64_t s = score((uint64_t)b | 0x100000000ULL, g_peers[i].m.id);
			if(best < 0 || s > best_score ||
			   (s == best_score && strcmp(g_peers[i].m.id, g_peers[best].m.id) > 0)) {
				best = i;
				best_score = s;
			}
		}

		g_bucket_owner[b] = best;
		g_own_bucket[b] = (best >= 0 && best == g_self_idx);
		g_addr_bucket[b] = best >= 0 && g_self_idx >= 0 &&
						   strcmp(g_peers[best].m.ip, g_peers[g_self_idx].m.ip) == 0;
		if(g_own_bucket[b])
			g_owned_buckets++;
	}
}

static int slice_owner_locked(uint32_t ip_host) {
	int best = -1;
	uint64_t best_score = 0;

	for(int i = 0; i < g_n; i++) {
		if(!is_dhcp_node(i))
			continue;
		uint64_t s = score(ip_host, g_peers[i].m.id);
		if(best < 0 || s > best_score ||
		   (s == best_score && strcmp(g_peers[i].m.id, g_peers[best].m.id) > 0)) {
			best = i;
			best_score = s;
		}
	}

	return best;
}

static void set_view_locked(int i, int view, time_t now, const char *why) {
	peer_t *p = &g_peers[i];

	if(p->view == view)
		return;
	syslog(view == PEER_UP ? LOG_INFO : LOG_WARNING, "cluster: peer %s %s → %s%s%s",
		   p->m.id, ha_peer_state_name(p->view), ha_peer_state_name(view),
		   why ? " — " : "", why ? why : "");
	if(view == PEER_DOWN)
		p->down_since = now;
	if(view == PEER_PARTNER_DOWN)
		p->pdown_since = now;
	p->view = view;
}

// Setup and configuration

void ha_setup(dhcp_config_t *config) {
	pthread_mutex_lock(&g_ha);
	g_enabled = config->node_id && config->node_id[0];
	g_role = config->role;
	snprintf(g_self, sizeof(g_self), "%s", g_enabled ? config->node_id : "");
	g_mclt = config->mclt ? config->mclt : DEFAULT_MCLT;
	g_peer_timeout = config->peer_timeout ? config->peer_timeout : DEFAULT_PEER_TIMEOUT;
	g_auto_pd = config->auto_partner_down;
	g_state = g_enabled ? HA_ORPHAN : HA_NORMAL;
	g_started = time(NULL);
	pthread_mutex_unlock(&g_ha);
}

int ha_configure(const cluster_member_t *members, int n,
				 uint32_t cfgver, const char *cfgsha) {
	if(n > MAX_MEMBERS)
		n = MAX_MEMBERS;
	time_t now = time(NULL);

	pthread_mutex_lock(&g_ha);
	peer_t old[MAX_MEMBERS];
	int old_n = g_n;
	memcpy(old, g_peers, sizeof(old));

	g_n = 0;
	g_self_idx = -1;

	for(int i = 0; i < n; i++) {
		peer_t *p = &g_peers[g_n];
		memset(p, 0, sizeof(*p));
		p->m = members[i];

		// Keep what we already know about members that stay
		for(int j = 0; j < old_n; j++) {
			if(strcmp(old[j].m.id, members[i].id) == 0) {
				*p = old[j];
				p->m = members[i];
				break;
			}
		}

		if(!p->last_heard && p->view == PEER_DOWN && !p->down_since)
			p->down_since = g_started;
		if(strcmp(p->m.id, g_self) == 0)
			g_self_idx = g_n;
		g_n++;
	}

	g_cfgver = cfgver;
	snprintf(g_cfgsha, sizeof(g_cfgsha), "%s", cfgsha ? cfgsha : "");

	g_addr_shared = false;
	for(int i = 0; g_self_idx >= 0 && i < g_n; i++)
		if(i != g_self_idx && is_dhcp_node(i) &&
		   strcmp(g_peers[i].m.ip, g_peers[g_self_idx].m.ip) == 0)
			g_addr_shared = true;

	int rc = 0;

	if(g_self_idx < 0) {
		if(g_state != HA_ORPHAN) {
			syslog(LOG_ERR, "cluster: this node (%s) is not in the member list — "
							"no longer answering DHCP",
				   g_self);
		}
		g_state = HA_ORPHAN;
		rc = -1;
	} else if(g_peers[g_self_idx].m.role != g_role) {
		syslog(LOG_ERR, "cluster: member list says %s is a %s but it was started "
						"as a %s — not serving",
			   g_self,
			   g_peers[g_self_idx].m.role == ROLE_CONTROLLER ? "controller" : "node",
			   g_role == ROLE_CONTROLLER ? "controller" : "node");
		g_state = HA_ORPHAN;
		rc = -1;
	} else if(g_state == HA_ORPHAN) {
		g_state = (g_role == ROLE_CONTROLLER) ? HA_NORMAL : HA_STARTING;
		g_started = now;
		g_caught_up = false;
		for(int i = 0; i < g_n; i++)
			if(!g_peers[i].last_heard)
				g_peers[i].down_since = now;
	}

	recompute_buckets_locked();
	pthread_mutex_unlock(&g_ha);

	return rc;
}

// Timers come from the shared config; called whenever it's (re)applied
void ha_set_timers(uint32_t mclt, uint32_t peer_timeout, uint32_t auto_pd) {
	pthread_mutex_lock(&g_ha);
	if(mclt)
		g_mclt = mclt;
	if(peer_timeout)
		g_peer_timeout = peer_timeout;
	g_auto_pd = auto_pd;
	pthread_mutex_unlock(&g_ha);
}

bool ha_enabled(void) {
	return g_enabled;
}

bool ha_is_controller(void) {
	return g_enabled && g_role == ROLE_CONTROLLER;
}

bool ha_serving(void) {
	if(!g_enabled)
		return true;
	pthread_mutex_lock(&g_ha);
	bool s = g_role == ROLE_NODE && g_state == HA_NORMAL;
	pthread_mutex_unlock(&g_ha);

	return s;
}

int ha_self_state(void) {
	pthread_mutex_lock(&g_ha);
	int s = g_state;
	pthread_mutex_unlock(&g_ha);

	return s;
}

const char *ha_state_name(int s) {
	switch(s) {
	case HA_STARTING:

		return "STARTING";
	case HA_NORMAL:

		return "NORMAL";
	case HA_ORPHAN:

		return "ORPHAN";
	}

	return "?";
}

const char *ha_peer_state_name(int s) {
	switch(s) {
	case PEER_DOWN:

		return "DOWN";
	case PEER_STARTING:

		return "STARTING";
	case PEER_UP:

		return "UP";
	case PEER_PARTNER_DOWN:

		return "PARTNER-DOWN";
	}

	return "?";
}

bool ha_owns_client(const char *device_id) {
	if(!g_enabled)
		return true;
	int b = bucket_of(device_id ? device_id : "");
	pthread_mutex_lock(&g_ha);
	bool mine = g_own_bucket[b];
	pthread_mutex_unlock(&g_ha);

	return mine;
}

bool ha_address_owns_client(const char *device_id) {
	if(!g_enabled)
		return true;
	int b = bucket_of(device_id ? device_id : "");
	pthread_mutex_lock(&g_ha);
	bool ours = g_addr_bucket[b];
	pthread_mutex_unlock(&g_ha);

	return ours;
}

bool ha_bucket_owner(const char *device_id, char *id, size_t idlen) {
	if(!g_enabled)
		return false;
	int b = bucket_of(device_id ? device_id : "");
	pthread_mutex_lock(&g_ha);
	int o = g_bucket_owner[b];
	bool ok = o >= 0 && o < g_n;
	if(ok)
		snprintf(id, idlen, "%s", g_peers[o].m.id);
	pthread_mutex_unlock(&g_ha);

	return ok;
}

bool ha_address_shared(void) {
	if(!g_enabled)
		return false;
	pthread_mutex_lock(&g_ha);
	bool shared = g_addr_shared;
	pthread_mutex_unlock(&g_ha);

	return shared;
}

uint32_t ha_lease_time(uint32_t configured) {
	if(!g_enabled)
		return configured;
	pthread_mutex_lock(&g_ha);
	bool cap = false;
	for(int i = 0; i < g_n; i++)
		if(i != g_self_idx && is_dhcp_node(i) && g_peers[i].view != PEER_UP)
			cap = true;
	uint32_t mclt = g_mclt;
	pthread_mutex_unlock(&g_ha);

	return (cap && mclt < configured) ? mclt : configured;
}

void ha_alloc_begin(ha_alloc_ctx_t *ctx) {
	memset(ctx, 0, sizeof(*ctx));
	if(!g_enabled)
		return;
	ctx->enabled = true;
	time_t now = time(NULL);

	pthread_mutex_lock(&g_ha);
	if(g_role != ROLE_NODE || g_state != HA_NORMAL)
		ctx->frozen = true;

	for(int i = 0; i < g_n; i++) {
		peer_t *p = &g_peers[i];
		if(!is_dhcp_node(i))
			continue;
		// A connected peer on a different config may be using different slices
		if(i != g_self_idx && p->connected && p->cfgsha[0] && g_cfgsha[0] &&
		   strcmp(p->cfgsha, g_cfgsha) != 0)
			ctx->frozen = true;
		int k = ctx->n++;
		snprintf(ctx->ids[k], sizeof(ctx->ids[k]), "%s", p->m.id);
		ctx->usable[k] = (i == g_self_idx) ||
						 (p->view == PEER_PARTNER_DOWN &&
						  now - p->pdown_since >= (time_t)g_mclt);
	}

	pthread_mutex_unlock(&g_ha);
}

bool ha_alloc_ok(const ha_alloc_ctx_t *ctx, uint32_t ip_host) {
	if(!ctx->enabled)
		return true;
	if(ctx->frozen || ctx->n == 0)
		return false;
	int best = -1;
	uint64_t best_score = 0;

	for(int i = 0; i < ctx->n; i++) {
		uint64_t s = score(ip_host, ctx->ids[i]);
		if(best < 0 || s > best_score ||
		   (s == best_score && strcmp(ctx->ids[i], ctx->ids[best]) > 0)) {
			best = i;
			best_score = s;
		}
	}

	return ctx->usable[best];
}

bool ha_slice_is_mine(uint32_t ip_host) {
	if(!g_enabled)
		return true;
	pthread_mutex_lock(&g_ha);
	bool mine = g_self_idx >= 0 && slice_owner_locked(ip_host) == g_self_idx;
	pthread_mutex_unlock(&g_ha);

	return mine;
}

// Peer link

int ha_member_count(void) {
	pthread_mutex_lock(&g_ha);
	int n = g_n;
	pthread_mutex_unlock(&g_ha);

	return n;
}

bool ha_member(int i, cluster_member_t *out) {
	pthread_mutex_lock(&g_ha);
	bool ok = i >= 0 && i < g_n;
	if(ok)
		*out = g_peers[i].m;
	pthread_mutex_unlock(&g_ha);

	return ok;
}

int ha_member_index(const char *id) {
	pthread_mutex_lock(&g_ha);
	int i = find_locked(id);
	pthread_mutex_unlock(&g_ha);

	return i;
}

void ha_config_version(uint32_t *ver, char *sha, size_t shalen) {
	pthread_mutex_lock(&g_ha);
	if(ver)
		*ver = g_cfgver;
	if(sha)
		snprintf(sha, shalen, "%s", g_cfgsha[0] ? g_cfgsha : "-");
	pthread_mutex_unlock(&g_ha);
}

void ha_peer_seen(const char *id, int remote_state, time_t remote_time,
				  uint32_t cfgver, const char *cfgsha) {
	time_t now = time(NULL);

	pthread_mutex_lock(&g_ha);
	int i = find_locked(id);
	if(i < 0 || i == g_self_idx) {
		pthread_mutex_unlock(&g_ha);

		return;
	}
	peer_t *p = &g_peers[i];
	p->connected = true;
	p->last_heard = now;
	p->remote_state = remote_state;
	p->cfgver = cfgver;
	snprintf(p->cfgsha, sizeof(p->cfgsha), "%s",
			 (cfgsha && strcmp(cfgsha, "-") != 0) ? cfgsha : "");
	p->skew = (long)(remote_time - now);
	long abs_skew = p->skew < 0 ? -p->skew : p->skew;
	if(abs_skew > SKEW_WARN_SECS && !p->skew_warned) {
		syslog(LOG_WARNING, "cluster: clock on %s differs from ours by %lds — "
							"check NTP on both",
			   id, p->skew);
		p->skew_warned = true;
	} else if(abs_skew <= SKEW_WARN_SECS) {
		p->skew_warned = false;
	}

	int view = (remote_state == HA_NORMAL) ? PEER_UP : PEER_STARTING;
	if(p->view != view) {
		set_view_locked(i, view, now, p->view == PEER_PARTNER_DOWN ? "it's back; its slice is its own again" : NULL);
		recompute_buckets_locked();
	}
	pthread_mutex_unlock(&g_ha);
}

// The connection closed.
void ha_peer_lost(const char *id) {
	time_t now = time(NULL);

	pthread_mutex_lock(&g_ha);
	int i = find_locked(id);

	if(i >= 0 && i != g_self_idx) {
		g_peers[i].connected = false;
		if(g_peers[i].view == PEER_UP || g_peers[i].view == PEER_STARTING) {
			set_view_locked(i, PEER_DOWN, now, "connection closed");
			recompute_buckets_locked();
		}
	}

	pthread_mutex_unlock(&g_ha);
}

int ha_partner_down(const char *id, char *err, size_t errlen) {
	time_t now = time(NULL);

	pthread_mutex_lock(&g_ha);
	int i = find_locked(id);
	int rc = -1;

	if(i < 0) {
		snprintf(err, errlen, "unknown member %s", id);
	} else if(i == g_self_idx) {
		snprintf(err, errlen, "%s is this node", id);
	} else if(!is_dhcp_node(i)) {
		snprintf(err, errlen, "%s is a controller, not a DHCP node", id);
	} else if(g_peers[i].view == PEER_UP || g_peers[i].view == PEER_STARTING) {
		snprintf(err, errlen, "%s is up — refusing", id);
	} else if(labs(g_peers[i].skew) > SKEW_REFUSE_SECS) {
		snprintf(err, errlen, "clock skew with %s is %lds — fix NTP first",
				 id, g_peers[i].skew);
	} else if(g_peers[i].view == PEER_PARTNER_DOWN) {
		snprintf(err, errlen, "%s already partner-down", id);
		rc = 0;
	} else {
		set_view_locked(i, PEER_PARTNER_DOWN, now, "declared by operator");
		syslog(LOG_WARNING, "cluster: will start using %s's slice in %us (MCLT)",
			   id, g_mclt);
		snprintf(err, errlen, "%s is partner-down; its slice is usable in %us",
				 id, g_mclt);
		rc = 0;
	}

	pthread_mutex_unlock(&g_ha);

	return rc;
}

int ha_peer_view(const char *id) {
	pthread_mutex_lock(&g_ha);
	int i = find_locked(id);
	int v = (i >= 0) ? g_peers[i].view : PEER_DOWN;
	pthread_mutex_unlock(&g_ha);

	return v;
}

void ha_sync_status(bool caught_up, bool all_connected) {
	pthread_mutex_lock(&g_ha);
	g_caught_up = caught_up;
	g_all_connected = all_connected;
	pthread_mutex_unlock(&g_ha);
}

bool ha_tick(time_t now) {
	if(!g_enabled)
		return false;
	pthread_mutex_lock(&g_ha);
	bool changed = false, self_changed = false;

	for(int i = 0; i < g_n; i++) {
		if(i == g_self_idx)
			continue;
		peer_t *p = &g_peers[i];

		if((p->view == PEER_UP || p->view == PEER_STARTING) &&
		   now - p->last_heard > (time_t)g_peer_timeout) {
			char why[64];
			snprintf(why, sizeof(why), "no heartbeat for %lds",
					 (long)(now - p->last_heard));
			set_view_locked(i, PEER_DOWN, now, why);
			changed = true;
		}

		if(p->view == PEER_DOWN && g_auto_pd > 0 && is_dhcp_node(i) &&
		   now - p->down_since >= (time_t)g_auto_pd &&
		   labs(p->skew) <= SKEW_REFUSE_SECS) {
			set_view_locked(i, PEER_PARTNER_DOWN, now, "auto_partner_down");
			changed = true;
		}
	}

	// Leave STARTING once every peer we can reach has caught us up
	if(g_state == HA_STARTING && g_caught_up &&
	   (g_all_connected || now - g_started >= (time_t)g_peer_timeout)) {
		g_state = HA_NORMAL;
		syslog(LOG_INFO, "cluster: %s is NORMAL — answering DHCP", g_self);
		changed = self_changed = true;
	}

	if(changed)
		recompute_buckets_locked();
	pthread_mutex_unlock(&g_ha);

	return self_changed;
}

void ha_status(char *buf, size_t buflen) {
	time_t now = time(NULL);
	size_t len = 0;

#define OUT(...)                                                 \
	do {                                                         \
		int _n = snprintf(buf + len, buflen - len, __VA_ARGS__); \
		if(_n > 0 && (size_t)_n < buflen - len)                  \
			len += (size_t)_n;                                   \
	} while(0)

	char hw[512];

	journal_hw_string(hw, sizeof(hw));

	pthread_mutex_lock(&g_ha);
	bool cap = false;
	for(int i = 0; i < g_n; i++)
		if(i != g_self_idx && is_dhcp_node(i) && g_peers[i].view != PEER_UP)
			cap = true;
	OUT("self %s role=%s state=%s buckets=%d/256 config=v%u/%s mclt=%us%s journal=%s\n",
		g_self, g_role == ROLE_CONTROLLER ? "controller" : "node",
		ha_state_name(g_state), g_owned_buckets, g_cfgver,
		g_cfgsha[0] ? g_cfgsha : "-", g_mclt,
		(cap && g_role == ROLE_NODE) ? " leases=capped" : "", hw);

	for(int i = 0; i < g_n; i++) {
		if(i == g_self_idx)
			continue;
		peer_t *p = &g_peers[i];
		char heard[32] = "never";
		if(p->last_heard)
			snprintf(heard, sizeof(heard), "%lds ago", (long)(now - p->last_heard));
		char extra[64] = "";
		if(p->view == PEER_PARTNER_DOWN) {
			long left = (long)g_mclt - (long)(now - p->pdown_since);
			snprintf(extra, sizeof(extra), left > 0 ? " slice-usable-in=%lds" : " slice=in-use", left);
		}
		OUT("peer %s %s %s:%d %s heard=%s skew=%lds config=v%u/%s%s\n",
			p->m.id, p->m.role == ROLE_CONTROLLER ? "controller" : "node",
			p->m.ip, p->m.port, ha_peer_state_name(p->view), heard, p->skew,
			p->cfgver, p->cfgsha[0] ? p->cfgsha : "-", extra);
	}

	pthread_mutex_unlock(&g_ha);
#undef OUT
}
