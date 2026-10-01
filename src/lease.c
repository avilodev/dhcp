#include "lease.h"
#include "ha.h"
#include <ctype.h>
#include <pthread.h>
#include <sys/stat.h>

// Serialises writes to members.txt and the dump file.  Defined in main.c.
extern pthread_mutex_t g_file_mutex;

#define OFFER_HOLD_SECS 60

// Read a whole file into a NUL-terminated buffer (NULL if missing/empty)
static char *slurp(const char *path, size_t *len_out) {
	int fd = open(path, O_RDONLY);

	if(fd < 0)
		return NULL;
	struct stat st;
	if(fstat(fd, &st) < 0 || st.st_size == 0) {
		close(fd);

		return NULL;
	}
	char *buf = malloc((size_t)st.st_size + 1);
	if(!buf) {
		close(fd);

		return NULL;
	}
	ssize_t n = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if(n <= 0) {
		free(buf);

		return NULL;
	}
	buf[n] = '\0';
	if(len_out)
		*len_out = (size_t)n;

	return buf;
}

static void set_str(char **dst, const char *src) {
	if(!src || !src[0])
		return;
	if(*dst && strcmp(*dst, src) == 0)
		return;
	free(*dst);
	*dst = strdup(src);
}

// Records

// Is record r newer than what node n last saw? Same origin: seq order.
static bool rec_newer(const lease_record_t *r, const struct tree_node *n) {
	if(!n->rec_op)
		return true;
	if(strcmp(r->origin, n->origin) == 0)
		return r->seq > n->seq;
	if(r->time != n->rec_time)
		return r->time > n->rec_time;

	return strcmp(r->origin, n->origin) > 0;
}

static void set_rec(struct tree_node *n, const lease_record_t *r) {
	snprintf(n->origin, sizeof(n->origin), "%s", r->origin);
	n->seq = r->seq;
	n->rec_time = r->time;
	n->rec_op = (uint8_t)r->op;
	n->rec_expires = r->expires;
	snprintf(n->rec_ip, sizeof(n->rec_ip), "%s", r->ip);
}

static void describe(const struct tree_node *n, char *buf, size_t len) {
	snprintf(buf, len, "%s (%s:%llu)",
			 n->is_decline ? "DECLINED" : n->key,
			 n->origin[0] ? n->origin : "static",
			 (unsigned long long)n->seq);
}

int lease_apply_record(dhcp_config_t *config, const lease_record_t *r) {
	if(!config || !r)
		return 0;
	time_t now = time(NULL);

	if(r->op == JOP_DECLINE) {
		char key[64];
		snprintf(key, sizeof(key), DECLINE_PREFIX "%s", r->ip);
		struct tree_node *n = get_or_create_node(config->mac_table, key);
		if(!n)
			return 0;
		n->is_decline = true;
		if(!rec_newer(r, n))
			return 0;
		set_rec(n, r);
		if(r->expires <= now) {
			lease_drop_ip(config, n);

			return 1;
		}

		struct tree_node *holder = ip_holder(config, r->ip);
		if(holder && holder != n) {
			if(holder->is_static) {
				syslog(LOG_WARNING, "DECLINE of static address %s ignored", r->ip);

				return 1;
			}
			lease_drop_ip(config, holder);
		}

		lease_bind_ip(config, n, r->ip);
		n->expires = r->expires;
		n->bound = true;

		return 1;
	}

	struct tree_node *n = get_or_create_node(config->mac_table, r->device_id);
	if(!n)
		return 0;
	if(n->is_static)
		return 0; // statics come from config, not the journal
	if(!rec_newer(r, n))
		return 0;

	set_rec(n, r);
	set_str(&n->mac, r->mac);
	set_str(&n->hostname, r->hostname);

	if(r->op == JOP_RELEASE || r->expires <= now) {
		lease_drop_ip(config, n);

		return 1;
	}

	// LEASE
	struct tree_node *holder = ip_holder(config, r->ip);

	if(holder && holder != n) {
		char a[320], b[320];
		describe(holder, a, sizeof(a));
		describe(n, b, sizeof(b));

		if(holder->is_static || (holder->bound && !rec_newer(r, holder))) {
			// Keep the address with its current holder.
			syslog(LOG_WARNING, "CONFLICT on %s: keeping %s, rejecting %s",
				   r->ip, a, b);
			lease_drop_ip(config, n);

			return 1;
		}

		if(holder->bound) {
			syslog(LOG_WARNING, "CONFLICT on %s: keeping %s, rejecting %s",
				   r->ip, b, a);
		}
		lease_drop_ip(config, holder); // newer lease, or just an OFFER
	}

	lease_bind_ip(config, n, r->ip);
	n->expires = r->expires;
	n->bound = true;

	return 1;
}

// Fill in the fields every local record shares, write it, stamp the node
static int commit(struct tree_node *n, lease_record_t *r, lease_commit_t *out) {
	time_t now = time(NULL);

	// Keep local records newer than their replacements.
	r->time = (n->rec_op && n->rec_time >= now) ? n->rec_time + 1 : now;

	journal_ticket_t t;

	if(journal_write_local(r, &t) < 0) {
		syslog(LOG_ERR, "journal write failed for %s — lease not recorded",
			   r->device_id[0] ? r->device_id : r->ip);

		return -1;
	}

	set_rec(n, r);
	if(out) {
		out->has = true;
		out->ticket = t;
		journal_format(r, out->line, sizeof(out->line));
	}

	return 0;
}

int lease_commit_ack(dhcp_config_t *config, struct tree_node *node,
					 const char *mac, lease_commit_t *out) {
	(void)config;
	if(!node || !node->ip)
		return -1;
	set_str(&node->mac, mac);
	node->bound = true;
	node->unverified = false;
	if(node->is_static)
		return 0; // statics live in config, not the journal

	lease_record_t r;
	memset(&r, 0, sizeof(r));
	r.op = JOP_LEASE;
	r.expires = node->expires;
	snprintf(r.device_id, sizeof(r.device_id), "%s", node->key);
	if(node->mac)
		snprintf(r.mac, sizeof(r.mac), "%s", node->mac);
	snprintf(r.ip, sizeof(r.ip), "%s", node->ip);
	sanitize_token(node->hostname, r.hostname, sizeof(r.hostname));

	return commit(node, &r, out);
}

int lease_commit_release(dhcp_config_t *config, struct tree_node *node,
						 lease_commit_t *out) {
	if(!node)
		return -1;
	if(node->is_static) {
		// The address stays reserved for this device; just mark it idle
		node->bound = false;

		return 0;
	}

	if(!node->ip)
		return -1;

	lease_record_t r;
	memset(&r, 0, sizeof(r));
	r.op = JOP_RELEASE;
	snprintf(r.device_id, sizeof(r.device_id), "%s", node->key);
	if(node->mac)
		snprintf(r.mac, sizeof(r.mac), "%s", node->mac);
	snprintf(r.ip, sizeof(r.ip), "%s", node->ip);
	sanitize_token(node->hostname, r.hostname, sizeof(r.hostname));

	syslog(LOG_INFO, "Released IP %s for device %s", node->ip, node->key);
	lease_drop_ip(config, node);

	return commit(node, &r, out);
}

int lease_commit_decline(dhcp_config_t *config, const char *ip,
						 struct tree_node *decliner, lease_commit_t *out) {
	if(!config || !ip)
		return -1;

	struct tree_node *holder = ip_holder(config, ip);
	if(holder && holder->is_static) {
		syslog(LOG_WARNING, "DECLINE of static address %s — check for a "
							"conflicting device on the network",
			   ip);

		return -1;
	}

	// Wipe the decliner's IP slot so its next DISCOVER gets a different address
	if(decliner && !decliner->is_static && decliner->ip)
		lease_drop_ip(config, decliner);

	char key[64];
	snprintf(key, sizeof(key), DECLINE_PREFIX "%s", ip);
	struct tree_node *n = get_or_create_node(config->mac_table, key);
	if(!n)
		return -1;
	holder = ip_holder(config, ip);
	if(holder && holder != n)
		lease_drop_ip(config, holder);

	n->is_decline = true;
	lease_bind_ip(config, n, ip);
	n->bound = true;
	n->expires = time(NULL) + (time_t)config->lease_time;
	syslog(LOG_WARNING, "IP %s marked as declined (address conflict) until it "
						"expires in %us",
		   ip, config->lease_time);

	lease_record_t r;
	memset(&r, 0, sizeof(r));
	r.op = JOP_DECLINE;
	r.expires = n->expires;
	snprintf(r.ip, sizeof(r.ip), "%s", ip);
	if(decliner) {
		snprintf(r.device_id, sizeof(r.device_id), "%s", decliner->key);
		if(decliner->mac)
			snprintf(r.mac, sizeof(r.mac), "%s", decliner->mac);
	}

	return commit(n, &r, out);
}

bool lease_adopt(dhcp_config_t *config, const char *device_id, uint32_t ip) {
	if(!config || !device_id || !ip_in_pool(config, ip))
		return false;

	char ip_str[IP_STR_LEN];
	struct in_addr a = {.s_addr = ip};
	inet_ntop(AF_INET, &a, ip_str, sizeof(ip_str));

	struct tree_node *holder = ip_holder(config, ip_str);
	if(holder && strcmp(holder->key, device_id) != 0)
		return false;
	if(!holder && test_ip(config->ip_table, ip_str))
		return false;

	struct tree_node *node = get_or_create_node(config->mac_table, device_id);
	if(!node || node->is_static)
		return false;
	if(node->ip && strcmp(node->ip, ip_str) != 0)
		return false;

	lease_bind_ip(config, node, ip_str);
	node->expires = time(NULL) + OFFER_HOLD_SECS;
	syslog(LOG_INFO, "Adopting lease %s for %s: no current record of it here "
					 "(expired, or the issuing node's record never arrived)",
		   ip_str, device_id);

	return true;
}

void lease_offer_verified(dhcp_config_t *config, const char *device_id, const char *ip) {
	struct tree_node *n = find_node(config->mac_table, device_id);

	if(n && n->ip && strcmp(n->ip, ip) == 0)
		n->unverified = false;
}

int lease_offer_conflict(dhcp_config_t *config, const char *device_id,
						 const char *ip, const char *who, lease_commit_t *out) {
	struct tree_node *n = find_node(config->mac_table, device_id);

	if(!n || !n->ip || strcmp(n->ip, ip) != 0 || n->bound)
		return -1;
	syslog(LOG_WARNING, "Address %s is already in use by %s (not one of our "
						"leases) — holding it back and offering another",
		   ip, who);

	return lease_commit_decline(config, ip, n, out);
}

static int foreign_offer_visitor(struct tree_node *n, void *ctx) {
	dhcp_config_t *config = ctx;

	if(n->ip && !n->bound && !n->is_static && !n->is_decline &&
	   !ha_slice_is_mine(ntohl(inet_addr(n->ip)))) {
		syslog(LOG_INFO, "Withdrawing offer of %s to %s (no longer our slice)",
			   n->ip, n->key);
		lease_drop_ip(config, n);
	}

	return 0;
}

int lease_drop_foreign_offers(dhcp_config_t *config) {
	traverse_tree(config->mac_table, foreign_offer_visitor, config);
	return 0;
}

// members.txt used to be the database: device_id,mac,ip,hostname (no expiry).
int lease_import_legacy(dhcp_config_t *config) {
	if(!config || !config->lease_db_path)
		return 0;
	char *buf = slurp(config->lease_db_path, NULL);
	if(!buf)
		return 0;

	time_t now = time(NULL);
	int imported = 0;
	char *save;
	for(char *line = strtok_r(buf, "\n", &save); line;
		line = strtok_r(NULL, "\n", &save)) {
		if(line[0] == '\0' || line[0] == '#')
			continue;

		char parse[600];
		snprintf(parse, sizeof(parse), "%s", line);
		for(char *p = parse; *p; p++)
			if(*p == ',')
				*p = ' ';

		char dev[256] = "", mac[64] = "", ip[64] = "", host[256] = "";
		if(sscanf(parse, "%255s %63s %63s %255s", dev, mac, ip, host) < 3)
			continue;
		struct in_addr a;
		if(inet_pton(AF_INET, ip, &a) != 1)
			continue;

		struct tree_node *n = get_or_create_node(config->mac_table, dev);
		if(!n || n->is_static || n->ip)
			continue;
		if(ip_holder(config, ip))
			continue;

		lease_bind_ip(config, n, ip);
		n->expires = now + (time_t)config->lease_time;
		if(host[0] && strcmp(host, "Unknown") != 0 && strcmp(host, "-") != 0)
			set_str(&n->hostname, host);
		if(lease_commit_ack(config, n, strlen(mac) < MAC_STR_LEN ? mac : NULL,
							NULL) == 0)
			imported++;
	}

	free(buf);

	return imported;
}

// Members snapshot

static int g_snapshot_dirty = 1;

void snapshot_mark_dirty(void) {
	__atomic_store_n(&g_snapshot_dirty, 1, __ATOMIC_RELEASE);
}

bool snapshot_take_dirty(void) {
	return __atomic_exchange_n(&g_snapshot_dirty, 0, __ATOMIC_ACQ_REL) != 0;
}

typedef struct {
	uint32_t ip;
	char line[400];
} snap_row_t;

typedef struct {
	snap_row_t *rows;
	size_t n, cap;
	time_t now;
	dhcp_config_t *config;
} snap_ctx_t;

static int snap_visitor(struct tree_node *n, void *p) {
	snap_ctx_t *c = p;

	if(n->is_decline || !n->ip)
		return 0;

	if(n->is_static) {
		// Statics are config, so every node lists them all, whether or not the device
		if(ip_holder(c->config, n->ip) != n)
			return 0;
	} else if(!n->bound || n->expires <= c->now) {
		return 0;
	}

	if(c->n == c->cap) {
		size_t cap = c->cap ? c->cap * 2 : 64;
		snap_row_t *r = realloc(c->rows, cap * sizeof(*r));
		if(!r)
			return 1;
		c->rows = r;
		c->cap = cap;
	}

	snap_row_t *row = &c->rows[c->n++];
	row->ip = ntohl(inet_addr(n->ip));

	char expires[32] = "static";
	if(!n->is_static) {
		struct tm tm_buf;
		if(localtime_r(&n->expires, &tm_buf))
			strftime(expires, sizeof(expires), "%Y-%m-%d %H:%M:%S", &tm_buf);
	}
	char host[64];
	sanitize_token(n->hostname, host, sizeof(host));
	const char *mac = n->mac ? n->mac : (n->is_static ? n->key : "-");
	snprintf(row->line, sizeof(row->line), "%s,%s,%s,%s,%s,%s\n",
			 n->key, mac, n->ip, host, expires,
			 n->origin[0] ? n->origin : "-");

	return 0;
}

static int row_cmp(const void *a, const void *b) {
	const snap_row_t *x = a, *y = b;

	return (x->ip > y->ip) - (x->ip < y->ip);
}

// members.txt
char *snapshot_build(dhcp_config_t *config, size_t *len) {
	snap_ctx_t c = {NULL, 0, 0, time(NULL), config};

	traverse_tree(config->mac_table, snap_visitor, &c);
	if(c.n)
		qsort(c.rows, c.n, sizeof(snap_row_t), row_cmp);

	strbuf_t sb = {0};
	sb_printf(&sb, "# device_id,mac,ip,hostname,expires,node\n");
	for(size_t i = 0; i < c.n; i++)
		sb_append(&sb, c.rows[i].line, strlen(c.rows[i].line));
	free(c.rows);
	if(sb.failed) {
		sb_free(&sb);

		return NULL;
	}
	*len = sb.len;

	return sb.buf;
}

int snapshot_save(dhcp_config_t *config, const char *buf, size_t len) {
	if(!config || !config->lease_db_path || !buf)
		return -1;
	pthread_mutex_lock(&g_file_mutex);
	int rc = write_file_atomic(config->lease_db_path, buf, len);
	pthread_mutex_unlock(&g_file_mutex);

	return rc;
}

// Static assignments

// Load/refresh static MAC→IP assignments.
int reload_static_assignments(dhcp_config_t *config) {
	if(!config || !config->mac_table || !config->ip_table ||
	   !config->static_path)
		return -1;

	char *buffer = slurp(config->static_path, NULL);
	if(!buffer)
		return 0;

	int added = 0, updated = 0;
	char *save_ptr;
	for(char *line = strtok_r(buffer, "\n", &save_ptr); line;
		line = strtok_r(NULL, "\n", &save_ptr)) {
		if(line[0] == '#' || line[0] == '\0' || line[0] == '\r')
			continue;

		char label[256], mac[64], ip[64];
		if(sscanf(line, "%255s %63s %63s", label, mac, ip) != 3)
			continue;
		for(char *p = mac; *p; p++)
			*p = (char)toupper((unsigned char)*p);
		struct in_addr a;
		if(inet_pton(AF_INET, ip, &a) != 1) {
			syslog(LOG_WARNING, "static list: bad IP '%s' for %s — skipped", ip, mac);
			continue;
		}

		struct tree_node *node = get_or_create_node(config->mac_table, mac);
		if(!node)
			continue;

		if(node->is_static && node->ip && strcmp(node->ip, ip) == 0) {
			set_str(&node->hostname, label);
			updated++;
			continue;
		}

		struct tree_node *holder = ip_holder(config, ip);

		if(holder && holder != node) {
			if(holder->is_static) {
				syslog(LOG_WARNING, "static list: %s and %s both claim %s — "
									"keeping %s",
					   holder->key, mac, ip, holder->key);
				continue;
			}

			syslog(LOG_WARNING, "static list: %s takes %s from dynamic lease of %s",
				   mac, ip, holder->key);
			lease_drop_ip(config, holder);
		}

		bool was_static = node->is_static;
		if(node->ip) {
			node->is_static = false; // let lease_drop_ip release it
			lease_drop_ip(config, node);
		}
		node->is_static = true;
		node->rec_op = 0; // statics are config, not journal state
		lease_bind_ip(config, node, ip);
		node->expires = 0;
		set_str(&node->hostname, label);
		if(was_static)
			updated++;
		else
			added++;
		syslog(LOG_INFO, "Static assignment: %s (%s) -> %s", mac, label, ip);
	}

	free(buffer);
	syslog(LOG_INFO, "Static list: %d added, %d refreshed", added, updated);

	return added + updated;
}

int load_static_assignments(dhcp_config_t *config) {
	return reload_static_assignments(config) > 0 ? 0 : -1;
}

// Blacklist

int load_blacklist(dhcp_config_t *config) {
	if(!config || !config->blacklist || !config->blacklist_path)
		return -1;

	int fd = open(config->blacklist_path, O_RDONLY);
	if(fd < 0)
		return -1;

	struct stat st;
	if(fstat(fd, &st) < 0 || st.st_size == 0) {
		close(fd);

		return -1;
	}
	size_t buf_size = (size_t)st.st_size + 1;

	char *buffer = malloc(buf_size);
	if(!buffer) {
		close(fd);

		return -1;
	}

	ssize_t n = read(fd, buffer, buf_size - 1);
	close(fd);
	if(n <= 0) {
		free(buffer);

		return -1;
	}
	buffer[n] = '\0';

	char *save_ptr;
	char *line = strtok_r(buffer, "\n", &save_ptr);
	int loaded = 0;

	while(line) {
		if(line[0] == '#' || line[0] == '\0') {
			line = strtok_r(NULL, "\n", &save_ptr);
			continue;
		}
		char *mac = strtok(line, " \t\r\n");
		if(mac && strlen(mac) > 0) {
			add_tree_node(config->blacklist, mac, NULL, 0);
			loaded++;
			syslog(LOG_DEBUG, "Added to blacklist: %s", mac);
		}
		line = strtok_r(NULL, "\n", &save_ptr);
	}

	free(buffer);
	syslog(LOG_INFO, "Loaded %d entries from blacklist", loaded);

	return 0;
}

bool is_blacklisted(dhcp_config_t *config, const char *mac) {
	if(!mac || !config || !config->blacklist)
		return false;

	return find_node(config->blacklist, mac) != NULL;
}

// Re-read blacklist.txt and add any new MACs.
int reload_blacklist(dhcp_config_t *config) {
	if(!config || !config->blacklist || !config->blacklist_path)
		return -1;

	int fd = open(config->blacklist_path, O_RDONLY);
	if(fd < 0)
		return -1;

	struct stat st;
	if(fstat(fd, &st) < 0 || st.st_size == 0) {
		close(fd);

		return 0;
	}
	size_t buf_size = (size_t)st.st_size + 1;

	char *buffer = malloc(buf_size);
	if(!buffer) {
		close(fd);

		return -1;
	}

	ssize_t n = read(fd, buffer, buf_size - 1);
	close(fd);
	if(n <= 0) {
		free(buffer);

		return 0;
	}
	buffer[n] = '\0';

	int added = 0;
	char *save_ptr;
	char *line = strtok_r(buffer, "\n", &save_ptr);

	while(line) {
		if(line[0] == '#' || line[0] == '\0') {
			line = strtok_r(NULL, "\n", &save_ptr);
			continue;
		}
		char *mac = strtok(line, " \t\r\n");
		if(mac && strlen(mac) > 0 && !find_node(config->blacklist, mac)) {
			add_tree_node(config->blacklist, mac, NULL, 0);
			added++;
			syslog(LOG_INFO, "SIGHUP: blacklisted %s", mac);
		}
		line = strtok_r(NULL, "\n", &save_ptr);
	}

	free(buffer);
	syslog(LOG_INFO, "SIGHUP blacklist reload: %d new entries", added);

	return 0;
}

// Write a human-readable lease-table snapshot.
static int dump_visitor(struct tree_node *node, void *ctx_ptr) {
	strbuf_t *sb = ctx_ptr;
	time_t now = time(NULL);

	const char *state;

	if(node->is_decline)
		state = "declined";
	else if(node->is_static)
		state = node->bound ? "static" : "static-idle";
	else if(!node->ip)
		state = "free";
	else if(node->bound)
		state = "leased";
	else
		state = "offered";

	char expires_str[32];

	if(node->is_static || (node->expires == 0 && node->ip)) {
		snprintf(expires_str, sizeof(expires_str), "permanent");
	} else if(!node->ip || node->expires <= now) {
		snprintf(expires_str, sizeof(expires_str), "-");
	} else {
		struct tm tm_buf;
		struct tm *tm = localtime_r(&node->expires, &tm_buf);
		if(tm)
			strftime(expires_str, sizeof(expires_str), "%Y-%m-%d %H:%M:%S", tm);
		else
			snprintf(expires_str, sizeof(expires_str), "?");
	}

	sb_printf(sb, "%-40s %-15s %-24s %-20s %-11s %s\n",
			  node->key ? node->key : "-",
			  node->ip ? node->ip : "-",
			  node->hostname ? node->hostname : "-",
			  expires_str, state,
			  node->origin[0] ? node->origin : "-");

	return 0;
}

int dump_lease_table(dhcp_config_t *config) {
	if(!config || !config->mac_table || !config->dump_path)
		return -1;

	strbuf_t sb = {0};
	sb_printf(&sb, "%-40s %-15s %-24s %-20s %-11s %s\n",
			  "Device ID / Client ID", "IP", "Hostname", "Expires", "State", "Node");
	sb_printf(&sb, "%s\n",
			  "---------------------------------------------------------------"
			  "-----------------------------------------------------");
	traverse_tree(config->mac_table, dump_visitor, &sb);
	if(sb.failed) {
		sb_free(&sb);

		return -1;
	}

	pthread_mutex_lock(&g_file_mutex);
	int rc = write_file_atomic(config->dump_path, sb.buf, sb.len);
	pthread_mutex_unlock(&g_file_mutex);
	sb_free(&sb);

	if(rc == 0)
		syslog(LOG_INFO, "Lease table dumped to %s", config->dump_path);

	return rc;
}
