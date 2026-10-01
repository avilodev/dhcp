#define _GNU_SOURCE
#include "peer.h"
#include "cluster.h"
#include "ha.h"
#include "journal.h"
#include "lease.h"
#include <inttypes.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <sys/stat.h>

extern pthread_mutex_t g_server_mutex;

#define ROLE_CLI 2
#define NONCE_BYTES 16
#define HB_INTERVAL 1 // seconds between heartbeats
#define RECONNECT_SECS 2
#define HELLO_TIMEOUT 10
#define CONNECT_TIMEOUT 5
#define CLI_IDLE 30
#define SYNC_TIMEOUT 30
#define PUSH_RETRY 10
#define LAG_GRACE 2 // a peer may be briefly ahead while live ENTRYs are in flight
#define MAX_LINE 8192
#define MAX_INBUF (1 << 20)
#define MAX_OUTBUF (64u << 20)
#define MAX_ORIGINS 64

typedef struct {
	char id[NODE_ID_LEN];
	uint64_t hw;
} hw_t;

typedef struct conn {
	struct conn *next;
	int fd;
	bool outgoing, connecting, dead;
	char target_ip[IP_STR_LEN];
	int target_port;
	char addr[INET_ADDRSTRLEN]; // remote address

	// Identity + authentication
	char id[NODE_ID_LEN];
	int role; // ROLE_NODE / ROLE_CONTROLLER / ROLE_CLI
	bool hello_sent, hello_rx, authed, fresh;
	char my_nonce[NONCE_BYTES * 2 + 1];
	char their_nonce[NONCE_BYTES * 2 + 1];
	uint64_t tx_ctr, rx_ctr;

	// What the peer last told us (HELLO / HB)
	int peer_state;
	time_t peer_time;
	uint32_t peer_cfgver;
	char peer_cfgsha[17];
	hw_t hw[MAX_ORIGINS];
	int hw_n;

	strbuf_t in, out;
	size_t out_off;
	time_t opened, last_rx, last_tx;

	// Config bundle being received from the controller
	bool cfg_active;
	uint32_t cfg_ver;
	char cfg_sha[17];
	int cfg_file;
	cluster_bundle_t cfg;

	// Controller: what we last pushed to this node
	char pushed_sha[17];
	time_t pushed_at;
} conn_t;

static dhcp_config_t *g_cfg;
static pthread_mutex_t g_pm = PTHREAD_MUTEX_INITIALIZER; // conn list + out buffers
static conn_t *g_conns = NULL;
static int g_listen = -1;
static int g_wake[2] = {-1, -1};
static pthread_t g_thread;
static volatile int g_run = 0;
static unsigned char g_key[512];
static size_t g_keylen = 0;

static struct {
	char ip[IP_STR_LEN];
	int port;
	time_t last;
} g_attempts[MAX_MEMBERS + 1];
static int g_nattempts = 0;

// Outstanding SYNC requests and "a peer is ahead of us" timers, per origin
static struct {
	char origin[NODE_ID_LEN];
	conn_t *conn;
	time_t since;
} g_pending[MAX_ORIGINS];
static int g_npending = 0;
static struct {
	char origin[NODE_ID_LEN];
	time_t since;
} g_lag[MAX_ORIGINS];
static int g_nlag = 0;

static peer_packet_handler_t g_packet_handler = NULL;
#define MAX_FWD_PACKET 1500 // hex-encoded it still fits in one line

// Controller: the bundle we serve
static cluster_bundle_t g_bundle;
static cluster_config_t g_bundle_cc;
static uint32_t g_bundle_ver = 0;
static bool g_have_bundle = false;

// Helpers

static const char *role_name(int r) {
	return r == ROLE_CONTROLLER ? "controller" : r == ROLE_CLI ? "cli"
															   : "node";
}

static int role_from(const char *s) {
	if(strcmp(s, "node") == 0)
		return ROLE_NODE;
	if(strcmp(s, "controller") == 0)
		return ROLE_CONTROLLER;
	if(strcmp(s, "cli") == 0)
		return ROLE_CLI;

	return -1;
}

static int state_from(const char *s) {
	if(strcmp(s, "NORMAL") == 0)
		return HA_NORMAL;
	if(strcmp(s, "STARTING") == 0)
		return HA_STARTING;

	return HA_ORPHAN;
}

static void wake(void) {
	if(g_wake[1] >= 0) {
		char c = 1;
		if(write(g_wake[1], &c, 1) < 0) { // pipe full — thread is awake anyway
		}
	}
}

static void hex(const unsigned char *in, size_t n, char *out) {
	for(size_t i = 0; i < n; i++)
		snprintf(out + i * 2, 3, "%02x", in[i]);
}

static void set_nonblock(int fd) {
	int fl = fcntl(fd, F_GETFL, 0);

	if(fl >= 0)
		fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int load_key(const char *path) {
	if(!path) {
		fprintf(stderr, "cluster mode needs peer_key in dhcp.conf\n");

		return -1;
	}
	int fd = open(path, O_RDONLY);
	if(fd < 0) {
		fprintf(stderr, "Cannot read peer key %s: %s\n", path, strerror(errno));
		syslog(LOG_ERR, "cannot read peer key %s: %s", path, strerror(errno));

		return -1;
	}

	struct stat st;
	if(fstat(fd, &st) == 0 && (st.st_mode & 077))
		syslog(LOG_WARNING, "peer key %s is readable by other users — chmod 600 it", path);
	ssize_t n = read(fd, g_key, sizeof(g_key) - 1);
	close(fd);
	if(n < 0)
		n = 0;
	while(n > 0 && (g_key[n - 1] == '\n' || g_key[n - 1] == '\r' ||
					g_key[n - 1] == ' ' || g_key[n - 1] == '\t'))
		n--;

	if(n < 16) {
		fprintf(stderr, "Peer key %s is too short (need at least 16 characters)\n", path);
		syslog(LOG_ERR, "peer key %s is too short", path);

		return -1;
	}

	g_keylen = (size_t)n;

	return 0;
}

// HMAC over  <prefix><body>.
static void sign(const char *prefix, const char *body, char out[65]) {
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int mdlen = 0;
	size_t plen = strlen(prefix), blen = strlen(body);
	char *data = malloc(plen + blen + 1);

	if(!data) {
		out[0] = '\0';

		return;
	}
	memcpy(data, prefix, plen);
	memcpy(data + plen, body, blen + 1);
	HMAC(EVP_sha256(), g_key, (int)g_keylen, (unsigned char *)data, plen + blen,
		 md, &mdlen);
	free(data);
	hex(md, 32, out);
}

// Sending

static void send_body(conn_t *c, const char *body) {
	if(c->dead)
		return;
	char prefix[160], mac[65];

	if(!c->hello_sent) {
		snprintf(prefix, sizeof(prefix), "HELLO|");
		c->hello_sent = true;
	} else {
		if(!c->hello_rx)
			return; // can't sign until we have their nonce
		snprintf(prefix, sizeof(prefix), "%s%s|%" PRIu64 "|",
				 c->my_nonce, c->their_nonce, ++c->tx_ctr);
	}

	sign(prefix, body, mac);
	sb_append(&c->out, body, strlen(body));
	sb_append(&c->out, " ", 1);
	sb_append(&c->out, mac, strlen(mac));
	sb_append(&c->out, "\n", 1);
	if(c->out.failed || c->out.len > MAX_OUTBUF) {
		syslog(LOG_WARNING, "peer %s: send buffer overflow — dropping connection",
			   c->id[0] ? c->id : c->addr);
		c->dead = true;
	}
	c->last_tx = time(NULL);
}

static void sendf(conn_t *c, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
static void sendf(conn_t *c, const char *fmt, ...) {
	char body[MAX_LINE];
	va_list ap;

	va_start(ap, fmt);
	int n = vsnprintf(body, sizeof(body), fmt, ap);
	va_end(ap);
	if(n < 0 || (size_t)n >= sizeof(body)) {
		syslog(LOG_ERR, "peer: message too long, not sent");

		return;
	}
	send_body(c, body);
}

static void my_status_fields(char *buf, size_t len) {
	uint32_t ver = 0;
	char sha[20], hw[2048];

	if(g_have_bundle) {
		ver = g_bundle_ver;
		snprintf(sha, sizeof(sha), "%s", g_bundle.sha);
	} else {
		ha_config_version(&ver, sha, sizeof(sha));
	}

	journal_hw_string(hw, sizeof(hw));
	snprintf(buf, len, "%s %lld %u %s %s", ha_state_name(ha_self_state()),
			 (long long)time(NULL), ver, sha[0] ? sha : "-", hw);
}

static void send_hello(conn_t *c, int role, const char *id) {
	unsigned char nonce[NONCE_BYTES];

	if(RAND_bytes(nonce, sizeof(nonce)) != 1) {
		syslog(LOG_ERR, "peer: RAND_bytes failed");
		c->dead = true;

		return;
	}

	hex(nonce, sizeof(nonce), c->my_nonce);
	char st[2300];
	if(role == ROLE_CLI)
		snprintf(st, sizeof(st), "- 0 0 - -");
	else
		my_status_fields(st, sizeof(st));
	sendf(c, "HELLO %s %s %s %s", id, role_name(role), c->my_nonce, st);
}

static void send_hb(conn_t *c) {
	char st[2300];

	my_status_fields(st, sizeof(st));
	sendf(c, "HB %s", st);
}

static void broadcast_hb_locked(void) {
	for(conn_t *c = g_conns; c; c = c->next)
		if(c->hello_rx && !c->dead)
			send_hb(c);
}

// Connections

static conn_t *conn_new(int fd, bool outgoing) {
	conn_t *c = calloc(1, sizeof(*c));

	if(!c) {
		close(fd);

		return NULL;
	}
	c->fd = fd;
	c->outgoing = outgoing;
	c->role = -1;
	c->opened = c->last_rx = c->last_tx = time(NULL);
	c->cfg_file = -1;
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	return c;
}

static void conn_free(conn_t *c) {
	if(c->fd >= 0)
		close(c->fd);
	sb_free(&c->in);
	sb_free(&c->out);
	cluster_bundle_free(&c->cfg);
	free(c);
}

// Caller holds g_pm
static bool has_authed(const char *id, const conn_t *except) {
	for(conn_t *c = g_conns; c; c = c->next)
		if(c != except && !c->dead && c->authed && strcmp(c->id, id) == 0)
			return true;

	return false;
}

// Caller holds g_pm.  Unlink and free dead connections.
static void reap(void) {
	conn_t **pp = &g_conns;

	while(*pp) {
		conn_t *c = *pp;
		if(!c->dead) {
			pp = &c->next;
			continue;
		}
		*pp = c->next;
		if(c->authed && c->role != ROLE_CLI) {
			syslog(LOG_INFO, "peer %s disconnected", c->id);
			if(!has_authed(c->id, c))
				ha_peer_lost(c->id);
		}

		for(int i = 0; i < g_npending;) {
			if(g_pending[i].conn == c)
				g_pending[i] = g_pending[--g_npending];
			else
				i++;
		}

		conn_free(c);
	}
}

static time_t *attempt_slot(const char *ip, int port) {
	for(int i = 0; i < g_nattempts; i++)
		if(g_attempts[i].port == port && strcmp(g_attempts[i].ip, ip) == 0)
			return &g_attempts[i].last;
	if(g_nattempts >= MAX_MEMBERS + 1)
		return NULL;
	snprintf(g_attempts[g_nattempts].ip, IP_STR_LEN, "%s", ip);
	g_attempts[g_nattempts].port = port;
	g_attempts[g_nattempts].last = 0;

	return &g_attempts[g_nattempts++].last;
}

// Caller holds g_pm
static void connect_to(const char *ip, int port, time_t now) {
	for(conn_t *c = g_conns; c; c = c->next)
		if(c->outgoing && !c->dead && c->target_port == port &&
		   strcmp(c->target_ip, ip) == 0)
			return;
	time_t *last = attempt_slot(ip, port);
	if(!last || now - *last < RECONNECT_SECS)
		return;
	*last = now;

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if(fd < 0)
		return;
	set_nonblock(fd);
	struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
	if(inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
		close(fd);

		return;
	}
	int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
	if(rc < 0 && errno != EINPROGRESS) {
		close(fd);

		return;
	}

	conn_t *c = conn_new(fd, true);
	if(!c)
		return;
	snprintf(c->target_ip, sizeof(c->target_ip), "%s", ip);
	snprintf(c->addr, sizeof(c->addr), "%s", ip);
	c->target_port = port;
	c->connecting = (rc < 0);
	c->next = g_conns;
	g_conns = c;
	if(!c->connecting)
		send_hello(c, g_cfg->role, g_cfg->node_id);
}

// Caller holds g_pm.
static void maintain_connections(time_t now) {
	if(g_cfg->role != ROLE_NODE)
		return;
	if(g_cfg->controller_ip)
		connect_to(g_cfg->controller_ip, g_cfg->controller_port, now);
	int n = ha_member_count();

	for(int i = 0; i < n; i++) {
		cluster_member_t m;
		if(!ha_member(i, &m))
			continue;
		if(strcmp(m.id, g_cfg->node_id) == 0)
			continue;
		if(m.role == ROLE_CONTROLLER ||
		   (m.role == ROLE_NODE && strcmp(m.id, g_cfg->node_id) > 0))
			connect_to(m.ip, m.port, now);
	}
}

static bool is_loopback(const char *addr) {
	return strncmp(addr, "127.", 4) == 0;
}

// Synchronization

static void parse_hw(conn_t *c, const char *s) {
	c->hw_n = 0;
	if(!s || strcmp(s, "-") == 0)
		return;
	char buf[4096];
	snprintf(buf, sizeof(buf), "%s", s);
	char *save;
	for(char *tok = strtok_r(buf, ",", &save); tok && c->hw_n < MAX_ORIGINS;
		tok = strtok_r(NULL, ",", &save)) {
		char *colon = strchr(tok, ':');
		if(!colon)
			continue;
		*colon = '\0';
		if(!valid_node_id(tok))
			continue;
		snprintf(c->hw[c->hw_n].id, NODE_ID_LEN, "%s", tok);
		c->hw[c->hw_n].hw = strtoull(colon + 1, NULL, 10);
		c->hw_n++;
	}
}

static int pending_find(const char *origin) {
	for(int i = 0; i < g_npending; i++)
		if(strcmp(g_pending[i].origin, origin) == 0)
			return i;

	return -1;
}

static time_t *lag_slot(const char *origin, bool create, time_t now) {
	for(int i = 0; i < g_nlag; i++)
		if(strcmp(g_lag[i].origin, origin) == 0)
			return &g_lag[i].since;
	if(!create || g_nlag >= MAX_ORIGINS)
		return NULL;
	snprintf(g_lag[g_nlag].origin, NODE_ID_LEN, "%s", origin);
	g_lag[g_nlag].since = now;

	return &g_lag[g_nlag++].since;
}

// Caller holds g_pm.
static void sync_tick(time_t now) {
	for(int i = 0; i < g_npending;) {
		if(now - g_pending[i].since > SYNC_TIMEOUT) {
			syslog(LOG_WARNING, "peer: SYNC for %s timed out", g_pending[i].origin);
			g_pending[i] = g_pending[--g_npending];
		} else {
			i++;
		}
	}

	bool starting = ha_self_state() != HA_NORMAL;
	char lagging[MAX_ORIGINS][NODE_ID_LEN];
	int nlagging = 0;

	for(conn_t *c = g_conns; c; c = c->next) {
		if(!c->authed || c->dead || c->role == ROLE_CLI)
			continue;

		for(int k = 0; k < c->hw_n; k++) {
			const char *o = c->hw[k].id;
			uint64_t mine = journal_hw(o);
			if(c->hw[k].hw <= mine)
				continue;

			bool seen = false;
			for(int j = 0; j < nlagging; j++)
				seen |= strcmp(lagging[j], o) == 0;
			if(!seen && nlagging < MAX_ORIGINS)
				snprintf(lagging[nlagging++], NODE_ID_LEN, "%s", o);

			if(pending_find(o) >= 0 || g_npending >= MAX_ORIGINS)
				continue;
			time_t *since = lag_slot(o, true, now);
			if(!since)
				continue;

			if(c->fresh || starting || now - *since >= LAG_GRACE) {
				sendf(c, "SYNC %s %" PRIu64, o, mine);
				snprintf(g_pending[g_npending].origin, NODE_ID_LEN, "%s", o);
				g_pending[g_npending].conn = c;
				g_pending[g_npending].since = now;
				g_npending++;
				syslog(LOG_INFO, "peer: catching up on %s from %s (have %" PRIu64 ", they have %" PRIu64 ")", o, c->id, mine, c->hw[k].hw);
			}
		}

		c->fresh = false;
	}

	// Forget lag timers for origins nobody is ahead on any more

	for(int i = 0; i < g_nlag;) {
		bool still = false;
		for(int j = 0; j < nlagging; j++)
			still |= strcmp(lagging[j], g_lag[i].origin) == 0;
		if(!still)
			g_lag[i] = g_lag[--g_nlag];
		else
			i++;
	}

	bool all_connected = true;
	int n = ha_member_count();

	for(int i = 0; i < n; i++) {
		cluster_member_t m;
		if(!ha_member(i, &m) || strcmp(m.id, g_cfg->node_id) == 0)
			continue;
		if(!has_authed(m.id, NULL))
			all_connected = false;
	}

	ha_sync_status(g_npending == 0 && nlagging == 0, all_connected);
}

typedef struct {
	const char *origin;
	uint64_t after;
	strbuf_t sb;
	time_t now;
	uint32_t lease_time;
} sync_ctx_t;

static int sync_visitor(struct tree_node *n, void *p) {
	sync_ctx_t *s = p;

	if(!n->rec_op || n->seq <= s->after || strcmp(n->origin, s->origin) != 0)
		return 0;
	if(!journal_record_is_live(n, s->now, s->lease_time))
		return 0;
	lease_record_t r;
	char line[JOURNAL_LINE_MAX];
	if(journal_record_from_node(n, &r) && journal_format(&r, line, sizeof(line)) > 0)
		sb_append(&s->sb, line, strlen(line));

	return 0;
}

// Answer "SYNC origin after" from the live lease table (what compaction would
static void serve_sync(conn_t *c, const char *origin, uint64_t after) {
	sync_ctx_t s = {origin, after, {0}, time(NULL), 0};

	pthread_mutex_lock(&g_server_mutex);
	s.lease_time = g_cfg->lease_time;
	traverse_tree(g_cfg->mac_table, sync_visitor, &s);
	pthread_mutex_unlock(&g_server_mutex);

	int sent = 0;
	pthread_mutex_lock(&g_pm);

	if(s.sb.buf) {
		char *save;
		for(char *line = strtok_r(s.sb.buf, "\n", &save); line;
			line = strtok_r(NULL, "\n", &save)) {
			sendf(c, "ENTRY %s", line);
			sent++;
		}
	}

	sendf(c, "SYNCDONE %s %" PRIu64, origin, journal_hw(origin));
	pthread_mutex_unlock(&g_pm);
	sb_free(&s.sb);
	syslog(LOG_INFO, "peer: sent %d %s records after %" PRIu64 " to %s",
		   sent, origin, after, c->id);
}

static void apply_entry(const char *line) {
	lease_record_t r;

	if(journal_parse(line, &r) < 0) {
		syslog(LOG_WARNING, "peer: bad ENTRY: %.80s", line);

		return;
	}
	pthread_mutex_lock(&g_server_mutex);
	// Newest-wins makes this idempotent, so duplicates (live + catch-up) are
	int applied = lease_apply_record(g_cfg, &r);
	if(applied > 0 || r.seq > journal_hw(r.origin))
		journal_write_remote(&r);
	pthread_mutex_unlock(&g_server_mutex);
	if(applied > 0)
		snapshot_mark_dirty();
}

// Configuration push

// Caller holds g_pm
static void push_bundle(conn_t *c, time_t now) {
	sendf(c, "CFGBEGIN %u %s", g_bundle_ver, g_bundle.sha);

	for(int i = 0; i < CLUSTER_NFILES; i++) {
		sendf(c, "CFGFILE %s", CLUSTER_FILES[i]);
		strbuf_t *f = &g_bundle.file[i];
		size_t start = 0;

		for(size_t j = 0; j < f->len; j++) {
			if(f->buf[j] != '\n')
				continue;
			char line[MAX_LINE - 32];
			size_t n = j - start;
			if(n >= sizeof(line))
				n = sizeof(line) - 1;
			memcpy(line, f->buf + start, n);
			line[n] = '\0';
			sendf(c, "CFGLINE %s", line);
			start = j + 1;
		}
	}

	sendf(c, "CFGEND");
	snprintf(c->pushed_sha, sizeof(c->pushed_sha), "%s", g_bundle.sha);
	c->pushed_at = now;
	syslog(LOG_INFO, "controller: pushed config v%u/%s to %s", g_bundle_ver,
		   g_bundle.sha, c->id);
}

// Caller holds g_pm
static void controller_check(conn_t *c, time_t now) {
	if(!g_have_bundle || !c->authed || c->role != ROLE_NODE || c->dead)
		return;

	if(c->peer_cfgver > g_bundle_ver) {
		// A node has a higher version than us (e.g.
		g_bundle_ver = c->peer_cfgver + 1;
		cluster_version_write(g_cfg->cluster_dir, g_bundle_ver, g_bundle.sha);
		syslog(LOG_WARNING, "controller: %s is at config v%u — bumping ours to v%u",
			   c->id, c->peer_cfgver, g_bundle_ver);
	}

	if(strcmp(c->peer_cfgsha, g_bundle.sha) == 0)
		return;
	if(strcmp(c->pushed_sha, g_bundle.sha) == 0 && now - c->pushed_at < PUSH_RETRY)
		return;
	push_bundle(c, now);
}

static int controller_load_locked(bool force, char *msg, size_t msglen);

// SIGHUP (main thread) and `--ctl push` (peer thread) can both land here
static pthread_mutex_t g_load_mutex = PTHREAD_MUTEX_INITIALIZER;

int peer_controller_load(bool force, char *msg, size_t msglen) {
	pthread_mutex_lock(&g_load_mutex);
	int rc = controller_load_locked(force, msg, msglen);
	pthread_mutex_unlock(&g_load_mutex);

	return rc;
}

static int controller_load_locked(bool force, char *msg, size_t msglen) {
	cluster_bundle_t b;

	if(cluster_bundle_read(g_cfg->cluster_dir, &b) < 0) {
		snprintf(msg, msglen, "no %s/cluster.conf", g_cfg->cluster_dir);

		return -1;
	}
	char err[256];
	cluster_config_t cc;
	if(cluster_parse(b.file[0].buf, g_cfg->peer_port, &cc, err, sizeof(err)) < 0) {
		snprintf(msg, msglen, "cluster.conf rejected: %s", err);
		cluster_bundle_free(&b);

		return -1;
	}

	if(g_have_bundle && strcmp(b.sha, g_bundle.sha) == 0) {
		snprintf(msg, msglen, "config unchanged (v%u/%s)", g_bundle_ver, g_bundle.sha);
		cluster_bundle_free(&b);
		cluster_config_free(&cc);

		return 0;
	}

	// Changing who's in the cluster moves slices.

	if(g_have_bundle && !cluster_same_members(&g_bundle_cc, &cc) && !force) {
		for(int i = 0; i < g_bundle_cc.n_members; i++) {
			const cluster_member_t *m = &g_bundle_cc.members[i];
			if(m->role != ROLE_NODE)
				continue;

			if(ha_peer_view(m->id) != PEER_UP) {
				snprintf(msg, msglen, "member list changed but node %s is not up — "
									  "not pushing (use `--ctl push --force` if it's really gone)",
						 m->id);
				cluster_bundle_free(&b);
				cluster_config_free(&cc);

				return -1;
			}
		}
	}

	uint32_t stored_ver = 0;
	char stored_sha[64];
	cluster_version_read(g_cfg->cluster_dir, &stored_ver, stored_sha, sizeof(stored_sha));
	uint32_t ver = stored_ver;
	if(strcmp(stored_sha, b.sha) != 0)
		ver = (stored_ver > g_bundle_ver ? stored_ver : g_bundle_ver) + 1;
	if(ver == 0)
		ver = 1;
	cluster_version_write(g_cfg->cluster_dir, ver, b.sha);

	pthread_mutex_lock(&g_pm);
	if(g_have_bundle) {
		cluster_bundle_free(&g_bundle);
		cluster_config_free(&g_bundle_cc);
	}
	g_bundle = b;
	g_bundle_cc = cc;
	g_bundle_ver = ver;
	g_have_bundle = true;
	pthread_mutex_unlock(&g_pm);

	cluster_load(g_cfg, NULL, NULL, 0);
	wake();
	snprintf(msg, msglen, "config v%u/%s loaded — pushing to nodes", ver, g_bundle.sha);
	syslog(LOG_INFO, "controller: %s", msg);

	return 0;
}

// A node finished receiving a bundle from the controller
static void finish_bundle(conn_t *c) {
	c->cfg_active = false;
	cluster_bundle_hash(&c->cfg);
	if(strcmp(c->cfg.sha, c->cfg_sha) != 0) {
		syslog(LOG_ERR, "peer: config from %s failed its checksum — ignored", c->id);
		cluster_bundle_free(&c->cfg);

		return;
	}

	char err[256];
	cluster_config_t cc;
	if(cluster_parse(c->cfg.file[0].buf, g_cfg->peer_port, &cc, err, sizeof(err)) < 0) {
		syslog(LOG_ERR, "peer: config v%u from %s rejected: %s", c->cfg_ver, c->id, err);
		cluster_bundle_free(&c->cfg);

		return;
	}

	cluster_config_free(&cc);

	if(cluster_bundle_write(g_cfg->cluster_dir, &c->cfg) < 0 ||
	   cluster_version_write(g_cfg->cluster_dir, c->cfg_ver, c->cfg.sha) < 0) {
		syslog(LOG_ERR, "peer: could not save config v%u to %s", c->cfg_ver,
			   g_cfg->cluster_dir);
		cluster_bundle_free(&c->cfg);

		return;
	}

	cluster_bundle_free(&c->cfg);
	syslog(LOG_INFO, "peer: received config v%u/%s from %s", c->cfg_ver, c->cfg_sha, c->id);
	cluster_load(g_cfg, NULL, NULL, 0);

	// Tell everyone our new config hash right away: peers hold off handing out new
	pthread_mutex_lock(&g_pm);
	broadcast_hb_locked();
	pthread_mutex_unlock(&g_pm);
}

// Incoming messages

static bool verify(conn_t *c, char *line, char **body_out) {
	char *sp = strrchr(line, ' ');

	if(!sp)
		return false;
	*sp = '\0';
	const char *given = sp + 1;
	char prefix[160], mac[65];
	uint64_t ctr = 0;

	if(!c->hello_rx) {
		if(strncmp(line, "HELLO ", 6) != 0)
			return false;
		snprintf(prefix, sizeof(prefix), "HELLO|");
	} else {
		ctr = c->rx_ctr + 1;
		snprintf(prefix, sizeof(prefix), "%s%s|%" PRIu64 "|",
				 c->their_nonce, c->my_nonce, ctr);
	}

	sign(prefix, line, mac);
	if(strlen(given) != 64 || CRYPTO_memcmp(mac, given, 64) != 0)
		return false;
	if(c->hello_rx)
		c->rx_ctr = ctr;
	*body_out = line;

	return true;
}

static void on_hello(conn_t *c, char *body) {
	char id[64], role[16], nonce[64], state[16], cfgsha[32], hw[4096];
	long long t;
	unsigned long cfgver;

	if(sscanf(body, "HELLO %63s %15s %63s %15s %lld %lu %31s %4095s",
			  id, role, nonce, state, &t, &cfgver, cfgsha, hw) != 8 ||
	   !valid_node_id(id) || strlen(nonce) != NONCE_BYTES * 2) {
		syslog(LOG_WARNING, "peer %s: malformed HELLO", c->addr);
		c->dead = true;

		return;
	}

	int r = role_from(role);
	const char *why = NULL;

	if(r < 0) {
		why = "unknown role";
	} else if(r == ROLE_CLI) {
		if(!is_loopback(c->addr))
			why = "control connections are only accepted locally";
	} else if(g_cfg->node_id && strcmp(id, g_cfg->node_id) == 0) {
		why = "it claims our own node id (two nodes configured with the same node_id?)";
	} else {
		int idx = ha_member_index(id);
		cluster_member_t m;

		if(idx >= 0 && ha_member(idx, &m)) {
			if(m.role != r)
				why = "its role doesn't match cluster.conf";
		} else if(!(r == ROLE_CONTROLLER && c->outgoing && g_cfg->controller_ip &&
					strcmp(c->target_ip, g_cfg->controller_ip) == 0)) {
			why = "it isn't in cluster.conf";
		}
	}

	if(why) {
		syslog(LOG_WARNING, "peer: rejecting %s (%s %s): %s", c->addr, role, id, why);
		c->dead = true;

		return;
	}

	snprintf(c->id, sizeof(c->id), "%.15s", id); // valid_node_id checked
	c->role = r;
	snprintf(c->their_nonce, sizeof(c->their_nonce), "%.32s", nonce);
	c->hello_rx = true;
	c->peer_state = state_from(state);
	c->peer_time = (time_t)t;
	c->peer_cfgver = (uint32_t)cfgver;
	snprintf(c->peer_cfgsha, sizeof(c->peer_cfgsha), "%.16s",
			 strcmp(cfgsha, "-") == 0 ? "" : cfgsha);
	parse_hw(c, hw);

	pthread_mutex_lock(&g_pm);
	if(!c->hello_sent)
		send_hello(c, g_cfg->role, g_cfg->node_id);
	send_hb(c); // our first nonce-bound message — proves we hold the key
	pthread_mutex_unlock(&g_pm);
}

static void on_authed(conn_t *c) {
	c->authed = true;
	c->fresh = true;
	if(c->role == ROLE_CLI)
		return;

	pthread_mutex_lock(&g_pm);

	// One connection per peer: a new one replaces any older one
	for(conn_t *o = g_conns; o; o = o->next) {
		if(o != c && !o->dead && o->authed && strcmp(o->id, c->id) == 0) {
			syslog(LOG_INFO, "peer %s: replacing older connection", c->id);
			o->dead = true;
		}
	}

	pthread_mutex_unlock(&g_pm);

	syslog(LOG_INFO, "peer %s (%s) connected from %s", c->id, role_name(c->role), c->addr);
	ha_peer_seen(c->id, c->peer_state, c->peer_time, c->peer_cfgver,
				 c->peer_cfgsha[0] ? c->peer_cfgsha : NULL);
}

static void reply_status(conn_t *c) {
	char buf[16384];

	ha_status(buf, sizeof(buf));
	pthread_mutex_lock(&g_pm);
	char *save;
	for(char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
		sendf(c, "STAT %s", line);

	for(conn_t *o = g_conns; o; o = o->next) {
		if(o->dead || o->role == ROLE_CLI || !o->authed)
			continue;
		sendf(c, "STAT link %s %s %s unsent=%zuB", o->id, o->outgoing ? "out" : "in",
			  o->addr, o->out.len - o->out_off);
	}

	sendf(c, "END");
	pthread_mutex_unlock(&g_pm);
}

static void handle(conn_t *c, char *line) {
	char *body = NULL;

	if(!verify(c, line, &body)) {
		syslog(LOG_WARNING, "peer %s: bad signature — dropping connection "
							"(is peer_key the same on both?)",
			   c->id[0] ? c->id : c->addr);
		c->dead = true;

		return;
	}

	c->last_rx = time(NULL);

	if(strncmp(body, "HELLO ", 6) == 0) {
		if(c->hello_rx) {
			c->dead = true;

			return;
		}
		on_hello(c, body);

		return;
	}

	if(!c->authed)
		on_authed(c);

	if(strncmp(body, "HB ", 3) == 0) {
		char state[16], cfgsha[32], hw[4096];
		long long t;
		unsigned long cfgver;
		if(sscanf(body, "HB %15s %lld %lu %31s %4095s", state, &t, &cfgver,
				  cfgsha, hw) == 5 &&
		   c->role != ROLE_CLI) {
			c->peer_state = state_from(state);
			c->peer_time = (time_t)t;
			c->peer_cfgver = (uint32_t)cfgver;
			snprintf(c->peer_cfgsha, sizeof(c->peer_cfgsha), "%.16s",
					 strcmp(cfgsha, "-") == 0 ? "" : cfgsha);
			pthread_mutex_lock(&g_pm);
			parse_hw(c, hw);
			pthread_mutex_unlock(&g_pm);
			ha_peer_seen(c->id, c->peer_state, c->peer_time, c->peer_cfgver,
						 c->peer_cfgsha[0] ? c->peer_cfgsha : NULL);
		}

		return;
	}

	if(c->role == ROLE_CLI) {
		char arg[64] = "";

		if(strcmp(body, "STATUS") == 0) {
			reply_status(c);
		} else if(sscanf(body, "PDOWN %63s", arg) == 1) {
			char msg[256];
			int rc = ha_partner_down(arg, msg, sizeof(msg));
			pthread_mutex_lock(&g_pm);

			if(rc == 0 && ha_is_controller()) {
				for(conn_t *o = g_conns; o; o = o->next)
					if(o->authed && !o->dead && o->role == ROLE_NODE)
						sendf(o, "PDOWN %s", arg);
				strncat(msg, " — sent to all nodes", sizeof(msg) - strlen(msg) - 1);
			}

			sendf(c, "%s %s", rc == 0 ? "OK" : "ERR", msg);
			pthread_mutex_unlock(&g_pm);
		} else if(strncmp(body, "PUSH", 4) == 0) {
			char msg[512];
			int rc = -1;
			if(!ha_is_controller())
				snprintf(msg, sizeof(msg), "push only works on the controller");
			else
				rc = peer_controller_load(strstr(body, "force") != NULL, msg, sizeof(msg));
			pthread_mutex_lock(&g_pm);
			sendf(c, "%s %s", rc == 0 ? "OK" : "ERR", msg);
			pthread_mutex_unlock(&g_pm);
		} else {
			pthread_mutex_lock(&g_pm);
			sendf(c, "ERR unknown command");
			pthread_mutex_unlock(&g_pm);
		}

		return;
	}

	if(strncmp(body, "ENTRY ", 6) == 0) {
		apply_entry(body + 6);

		return;
	}

	if(strncmp(body, "FWD ", 4) == 0) {
		int ifindex = 0, used = 0;
		if(c->role != ROLE_NODE || sscanf(body, "FWD %d %n", &ifindex, &used) < 1 ||
		   !used || !g_packet_handler)
			return;
		const char *hexs = body + used;
		size_t n = strlen(hexs) / 2;
		if(n == 0 || n > MAX_FWD_PACKET)
			return;
		unsigned char pkt[MAX_FWD_PACKET];

		for(size_t i = 0; i < n; i++) {
			unsigned int b;
			if(sscanf(hexs + i * 2, "%2x", &b) != 1)
				return;
			pkt[i] = (unsigned char)b;
		}

		g_packet_handler(pkt, n, ifindex);

		return;
	}

	char origin[64];
	unsigned long long n;

	if(sscanf(body, "SYNC %63s %llu", origin, &n) == 2) {
		if(valid_node_id(origin))
			serve_sync(c, origin, n);

		return;
	}

	if(sscanf(body, "SYNCDONE %63s %llu", origin, &n) == 2) {
		if(!valid_node_id(origin))
			return;
		journal_note_hw(origin, n);
		pthread_mutex_lock(&g_pm);
		int i = pending_find(origin);
		if(i >= 0 && g_pending[i].conn == c)
			g_pending[i] = g_pending[--g_npending];
		pthread_mutex_unlock(&g_pm);

		return;
	}

	// Everything below comes only from the controller
	if(c->role != ROLE_CONTROLLER) {
		syslog(LOG_WARNING, "peer %s: unexpected message: %.40s", c->id, body);

		return;
	}

	if(strncmp(body, "CFGBEGIN ", 9) == 0) {
		unsigned long ver;
		char sha[32];
		cluster_bundle_free(&c->cfg);
		memset(&c->cfg, 0, sizeof(c->cfg));
		c->cfg_active = sscanf(body, "CFGBEGIN %lu %31s", &ver, sha) == 2;
		c->cfg_ver = (uint32_t)ver;
		c->cfg_file = -1;
		snprintf(c->cfg_sha, sizeof(c->cfg_sha), "%.16s", c->cfg_active ? sha : "");
	} else if(strncmp(body, "CFGFILE ", 8) == 0 && c->cfg_active) {
		c->cfg_file = -1;
		for(int i = 0; i < CLUSTER_NFILES; i++)
			if(strcmp(body + 8, CLUSTER_FILES[i]) == 0)
				c->cfg_file = i;
		if(c->cfg_file < 0)
			c->cfg_active = false;
	} else if(strncmp(body, "CFGLINE", 7) == 0 && c->cfg_active && c->cfg_file >= 0) {
		const char *text = body[7] == ' ' ? body + 8 : "";
		sb_append(&c->cfg.file[c->cfg_file], text, strlen(text));
		sb_append(&c->cfg.file[c->cfg_file], "\n", 1);
	} else if(strcmp(body, "CFGEND") == 0 && c->cfg_active) {
		finish_bundle(c);
	} else if(strncmp(body, "PDOWN ", 6) == 0) {
		char msg[256];
		ha_partner_down(body + 6, msg, sizeof(msg));
		syslog(LOG_WARNING, "controller asked for partner-down of %s: %s", body + 6, msg);
	}
}

// Read what's available and handle every complete line.
static void read_conn(conn_t *c) {
	char buf[16384];

	for(;;) {
		ssize_t n = read(c->fd, buf, sizeof(buf));

		if(n > 0) {
			sb_append(&c->in, buf, (size_t)n);
			if(c->in.failed || c->in.len > MAX_INBUF) {
				c->dead = true;

				return;
			}
			continue;
		}

		if(n == 0) {
			c->dead = true;
			break;
		}
		if(errno == EINTR)
			continue;
		if(errno != EAGAIN && errno != EWOULDBLOCK)
			c->dead = true;
		break;
	}

	size_t start = 0;

	for(size_t i = 0; i < c->in.len && !c->dead; i++) {
		if(c->in.buf[i] != '\n')
			continue;
		c->in.buf[i] = '\0';
		if(i - start >= MAX_LINE) {
			c->dead = true;
			break;
		}
		handle(c, c->in.buf + start);
		start = i + 1;
	}

	if(start > 0 && !c->dead) {
		memmove(c->in.buf, c->in.buf + start, c->in.len - start);
		c->in.len -= start;
	}
	if(c->in.len >= MAX_LINE)
		c->dead = true;
}

// Caller holds g_pm
static void flush_conn(conn_t *c) {
	while(c->out_off < c->out.len) {
		ssize_t n = write(c->fd, c->out.buf + c->out_off, c->out.len - c->out_off);
		if(n > 0) {
			c->out_off += (size_t)n;
			continue;
		}
		if(n < 0 && errno == EINTR)
			continue;
		if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
			return;
		c->dead = true;

		return;
	}

	c->out.len = c->out_off = 0;
}

// Peer thread

static void *peer_thread(void *arg) {
	(void)arg;
	struct pollfd *pfds = NULL;
	conn_t **pconn = NULL;
	size_t cap = 0;
	time_t last_tick = 0;

	while(g_run) {
		time_t now = time(NULL);

		pthread_mutex_lock(&g_pm);
		reap();

		if(now != last_tick) {
			last_tick = now;
			maintain_connections(now);

			for(conn_t *c = g_conns; c; c = c->next) {
				if(c->dead)
					continue;

				if(c->connecting && now - c->opened > CONNECT_TIMEOUT) {
					c->dead = true;
				} else if(!c->hello_rx && now - c->opened > HELLO_TIMEOUT) {
					c->dead = true;
				} else if(c->role == ROLE_CLI && now - c->last_rx > CLI_IDLE) {
					c->dead = true;
				} else if(c->authed && c->role != ROLE_CLI &&
						  now - c->last_rx > (time_t)(2 * g_cfg->peer_timeout + 2)) {
					syslog(LOG_WARNING, "peer %s: silent for %lds — reconnecting",
						   c->id, (long)(now - c->last_rx));
					c->dead = true;
				} else if(c->hello_rx && c->role != ROLE_CLI && now - c->last_tx >= HB_INTERVAL) {
					send_hb(c);
				}

				if(ha_is_controller())
					controller_check(c, now);
			}

			sync_tick(now);
		}

		size_t n = 0;
		for(conn_t *c = g_conns; c; c = c->next)
			n++;

		if(n + 2 > cap) {
			cap = n + 16;
			pfds = realloc(pfds, cap * sizeof(*pfds));
			pconn = realloc(pconn, cap * sizeof(*pconn));
			if(!pfds || !pconn) {
				pthread_mutex_unlock(&g_pm);
				break;
			}
		}

		size_t k = 0;
		pfds[k] = (struct pollfd){.fd = g_wake[0], .events = POLLIN};
		pconn[k++] = NULL;
		pfds[k] = (struct pollfd){.fd = g_listen, .events = POLLIN};
		pconn[k++] = NULL;

		for(conn_t *c = g_conns; c; c = c->next) {
			if(c->dead)
				continue;
			short ev = POLLIN;
			if(c->connecting || c->out_off < c->out.len)
				ev |= POLLOUT;
			pfds[k] = (struct pollfd){.fd = c->fd, .events = ev};
			pconn[k++] = c;
		}

		pthread_mutex_unlock(&g_pm);

		if(ha_tick(now)) {
			// Our state changed (e.g.
			pthread_mutex_lock(&g_pm);
			broadcast_hb_locked();
			for(conn_t *c = g_conns; c; c = c->next)
				if(!c->dead && !c->connecting)
					flush_conn(c);
			pthread_mutex_unlock(&g_pm);
		}

		int rc = poll(pfds, k, 250);
		if(rc < 0) {
			if(errno == EINTR)
				continue;
			syslog(LOG_ERR, "peer: poll failed: %s", strerror(errno));
			continue;
		}

		if(pfds[0].revents & POLLIN) {
			char drain[64];
			while(read(g_wake[0], drain, sizeof(drain)) > 0) {
			}
		}

		pthread_mutex_lock(&g_pm);

		if(pfds[1].revents & POLLIN) {
			for(;;) {
				struct sockaddr_in sa;
				socklen_t sl = sizeof(sa);
				int fd = accept4(g_listen, (struct sockaddr *)&sa, &sl, SOCK_NONBLOCK);
				if(fd < 0)
					break;
				conn_t *c = conn_new(fd, false);
				if(!c)
					continue;
				inet_ntop(AF_INET, &sa.sin_addr, c->addr, sizeof(c->addr));
				c->next = g_conns;
				g_conns = c;
				send_hello(c, g_cfg->role, g_cfg->node_id);
			}
		}

		for(size_t i = 2; i < k; i++) {
			conn_t *c = pconn[i];
			if(c->dead)
				continue;

			if(c->connecting && (pfds[i].revents & (POLLOUT | POLLERR | POLLHUP))) {
				int err = 0;
				socklen_t el = sizeof(err);
				getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el);
				if(err) {
					c->dead = true;
					continue;
				}
				c->connecting = false;
				send_hello(c, g_cfg->role, g_cfg->node_id);
			}

			if(pfds[i].revents & (POLLERR | POLLHUP | POLLNVAL) && !(pfds[i].revents & POLLIN))
				c->dead = true;
		}

		pthread_mutex_unlock(&g_pm);

		for(size_t i = 2; i < k; i++) {
			conn_t *c = pconn[i];
			if(!c->dead && !c->connecting && (pfds[i].revents & POLLIN))
				read_conn(c);
		}

		pthread_mutex_lock(&g_pm);
		for(conn_t *c = g_conns; c; c = c->next)
			if(!c->dead && !c->connecting)
				flush_conn(c);
		pthread_mutex_unlock(&g_pm);
	}

	free(pfds);
	free(pconn);

	return NULL;
}

// Public functions

int peer_init(dhcp_config_t *config) {
	g_cfg = config;
	if(load_key(config->peer_key_path) < 0)
		return -1;

	if(pipe2(g_wake, O_NONBLOCK | O_CLOEXEC) < 0)
		return -1;

	g_listen = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if(g_listen < 0)
		return -1;
	int one = 1;
	setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)config->peer_port),
		.sin_addr.s_addr = INADDR_ANY,
	};

	if(bind(g_listen, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
	   listen(g_listen, 16) < 0) {
		fprintf(stderr, "Error: cannot listen on peer port %d: %s\n",
				config->peer_port, strerror(errno));
		syslog(LOG_ERR, "cannot listen on peer port %d: %s",
			   config->peer_port, strerror(errno));
		close(g_listen);
		g_listen = -1;

		return -1;
	}

	syslog(LOG_INFO, "peer link listening on port %d", config->peer_port);

	return 0;
}

int peer_start(void) {
	g_run = 1;
	if(pthread_create(&g_thread, NULL, peer_thread, NULL) != 0) {
		g_run = 0;

		return -1;
	}

	return 0;
}

void peer_stop(void) {
	if(!g_run)
		return;
	g_run = 0;
	wake();
	pthread_join(g_thread, NULL);
	pthread_mutex_lock(&g_pm);
	for(conn_t *c = g_conns; c; c = c->next) {
		flush_conn(c);
		c->dead = true;
	}
	conn_t *c = g_conns;
	while(c) {
		conn_t *next = c->next;
		conn_free(c);
		c = next;
	}
	g_conns = NULL;
	pthread_mutex_unlock(&g_pm);
	if(g_listen >= 0) {
		close(g_listen);
		g_listen = -1;
	}
}

void peer_broadcast_record(const char *line) {
	if(!g_run || !line)
		return;
	char body[JOURNAL_LINE_MAX];
	snprintf(body, sizeof(body), "%s", line);
	size_t len = strlen(body);
	while(len && (body[len - 1] == '\n' || body[len - 1] == '\r'))
		body[--len] = '\0';

	pthread_mutex_lock(&g_pm);
	for(conn_t *c = g_conns; c; c = c->next)
		if(c->authed && !c->dead && c->role != ROLE_CLI)
			sendf(c, "ENTRY %s", body);
	pthread_mutex_unlock(&g_pm);
	wake();
}

void peer_set_packet_handler(peer_packet_handler_t fn) {
	g_packet_handler = fn;
}

int peer_forward_packet(const char *node_id, const void *pkt, size_t len, int ifindex) {
	if(!g_run || !node_id || len == 0 || len > MAX_FWD_PACKET)
		return -1;
	char hexbuf[MAX_FWD_PACKET * 2 + 1];
	hex(pkt, len, hexbuf);

	int rc = -1;
	pthread_mutex_lock(&g_pm);

	for(conn_t *c = g_conns; c; c = c->next) {
		if(c->authed && !c->dead && c->role == ROLE_NODE && strcmp(c->id, node_id) == 0) {
			sendf(c, "FWD %d %s", ifindex, hexbuf);
			rc = 0;
			break;
		}
	}

	pthread_mutex_unlock(&g_pm);
	if(rc == 0)
		wake();
	else
		syslog(LOG_WARNING, "peer: can't hand packet to %s — not connected", node_id);

	return rc;
}

// Control client

static int ctl_flush(conn_t *c) {
	while(c->out_off < c->out.len) {
		ssize_t n = write(c->fd, c->out.buf + c->out_off, c->out.len - c->out_off);

		if(n <= 0) {
			if(n < 0 && errno == EINTR)
				continue;

			return -1;
		}

		c->out_off += (size_t)n;
	}

	c->out.len = c->out_off = 0;

	return 0;
}

int peer_ctl_main(dhcp_config_t *config, int argc, char **argv) {
	g_cfg = config;

	if(argc < 1) {
		fprintf(stderr, "usage: dhcp_server --ctl <dhcp.conf> status | "
						"partner-down <node> | push [--force]\n");

		return 2;
	}

	char cmd[128];

	if(strcmp(argv[0], "status") == 0) {
		snprintf(cmd, sizeof(cmd), "STATUS");
	} else if(strcmp(argv[0], "partner-down") == 0 && argc >= 2 && valid_node_id(argv[1])) {
		snprintf(cmd, sizeof(cmd), "PDOWN %s", argv[1]);
	} else if(strcmp(argv[0], "push") == 0) {
		snprintf(cmd, sizeof(cmd), "PUSH%s",
				 (argc >= 2 && strcmp(argv[1], "--force") == 0) ? " force" : "");
	} else {
		fprintf(stderr, "unknown command '%s' (status | partner-down <node> | push [--force])\n",
				argv[0]);

		return 2;
	}

	if(load_key(config->peer_key_path) < 0)
		return 2;

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct timeval tv = {.tv_sec = 5};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons((uint16_t)config->peer_port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};

	if(connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		fprintf(stderr, "cannot reach the server on 127.0.0.1:%d: %s (is it running "
						"in cluster mode?)\n",
				config->peer_port, strerror(errno));
		close(fd);

		return 2;
	}

	conn_t *c = conn_new(fd, true);
	if(!c)
		return 2;
	snprintf(c->addr, sizeof(c->addr), "127.0.0.1");
	send_hello(c, ROLE_CLI, "ctl");
	if(ctl_flush(c) < 0) {
		conn_free(c);

		return 2;
	}

	int rc = 2;
	bool sent = false, done = false;
	char buf[8192];

	while(!done) {
		ssize_t n = read(c->fd, buf, sizeof(buf));
		if(n <= 0) {
			fprintf(stderr, "connection closed without an answer (wrong peer_key?)\n");
			break;
		}
		sb_append(&c->in, buf, (size_t)n);
		size_t start = 0;

		for(size_t i = 0; i < c->in.len && !done; i++) {
			if(c->in.buf[i] != '\n')
				continue;
			c->in.buf[i] = '\0';
			char *body;
			char *line = c->in.buf + start;
			start = i + 1;
			if(!verify(c, line, &body)) {
				fprintf(stderr, "bad signature from server — peer_key mismatch?\n");
				done = true;
				break;
			}

			if(strncmp(body, "HELLO ", 6) == 0) {
				char nonce[64];
				if(sscanf(body, "HELLO %*s %*s %63s", nonce) == 1) {
					snprintf(c->their_nonce, sizeof(c->their_nonce), "%.32s", nonce);
					c->hello_rx = true;
				}
				if(!sent) {
					send_body(c, cmd);
					sent = ctl_flush(c) == 0;
				}
			} else if(strncmp(body, "STAT ", 5) == 0) {
				printf("%s\n", body + 5);
			} else if(strcmp(body, "END") == 0) {
				rc = 0;
				done = true;
			} else if(strncmp(body, "OK ", 3) == 0) {
				printf("%s\n", body + 3);
				rc = 0;
				done = true;
			} else if(strncmp(body, "ERR ", 4) == 0) {
				fprintf(stderr, "%s\n", body + 4);
				rc = 1;
				done = true;
			}
		}

		if(start > 0) {
			memmove(c->in.buf, c->in.buf + start, c->in.len - start);
			c->in.len -= start;
		}
	}

	conn_free(c);

	return rc;
}
