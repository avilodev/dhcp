#ifndef JOURNAL_H
#define JOURNAL_H

#include "node.h"
#include "types.h"

// The lease journal misc/leases.journal

#define JOP_LEASE 1
#define JOP_RELEASE 2
#define JOP_DECLINE 3

#define JOURNAL_LINE_MAX 1024
#define DECLINE_PREFIX "!decline/"

typedef struct {
	char origin[NODE_ID_LEN];
	uint64_t seq;
	time_t time;
	int op;
	char device_id[256];
	char mac[MAC_STR_LEN]; // "-" if unknown
	char ip[IP_STR_LEN];   // "-" if none
	time_t expires;
	char hostname[64]; // sanitised token, "-" if none
} lease_record_t;

// Returned by a local write; pass to journal_sync() before ACKing the client
typedef struct {
	uint32_t gen;
	off_t end;
} journal_ticket_t;

// Open the journal and rebuild the lease tree.
int journal_init(dhcp_config_t *config);
void journal_close(void);

// The id this server stamps on the records it writes
const char *journal_self(void);

int journal_format(const lease_record_t *r, char *buf, size_t buflen);
int journal_parse(const char *line, lease_record_t *r);
const char *journal_op_name(int op);

// Writers hold g_server_mutex to keep tree and journal consistent.
int journal_write_local(lease_record_t *r, journal_ticket_t *ticket); // assigns origin+seq
// Append a record received from a peer (raises that origin's high-water mark)
int journal_write_remote(const lease_record_t *r);
void journal_sync(const journal_ticket_t *ticket);

// Rewrite the journal as just the live records.  Caller holds g_server_mutex.
int journal_compact(dhcp_config_t *config);

// High-water marks: the highest seq seen from each origin
uint64_t journal_hw(const char *origin);
void journal_note_hw(const char *origin, uint64_t hw);
// "A:12,B:7" (or "-" when empty)
void journal_hw_string(char *buf, size_t buflen);

// Fill r from a node's latest record.  Returns false if the node has none.
bool journal_record_from_node(const struct tree_node *n, lease_record_t *r);
// Would compaction keep this node's record? (live lease, recent release, …)
bool journal_record_is_live(const struct tree_node *n, time_t now,
							uint32_t lease_time);

#endif /* JOURNAL_H */
