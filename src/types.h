#ifndef TYPES_H
#define TYPES_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define MAXLINE 4096

// DHCP Protocol Constants
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_MAGIC_COOKIE 0x63825363

// DHCP Message Types (RFC 2132)
#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPDECLINE 4
#define DHCPACK 5
#define DHCPNAK 6
#define DHCPRELEASE 7
#define DHCPINFORM 8

// DHCP Packet Structure Sizes
#define DHCP_CHADDR_LEN 16
#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128
#define DHCP_OPTIONS_LEN 312

// Configuration Constants
#define LEASE_TIME 86400
#define MAX_RETRIES 3
#define BUFFER_SIZE 4096
#define MAC_STR_LEN 18
#define IP_STR_LEN 16

// File Paths
#define SERVER_PATH "/home/avilo/dhcp"
#define LEASE_DB_FILE "/misc/members.txt"
#define STATIC_FILE "/misc/static_list.txt"
#define BLACKLIST_FILE "/misc/blacklist.txt"
#define PID_FILE "/misc/server.pid"
#define SERVER_LOG_FILE "/misc/server.log"
#define DUMP_FILE "/misc/leases_current.txt"
#define JOURNAL_FILE "/misc/leases.journal"

// Cluster defaults
#ifndef NODE_ID_LEN
#define NODE_ID_LEN 16 // max id length incl. NUL: [A-Za-z0-9_-]{1,15}
#endif
#define MAX_MEMBERS 16 // nodes + controllers in one cluster
#define DEFAULT_PEER_PORT 647 // the port ISC's failover protocol used
#define DEFAULT_MCLT 3600 // lease cap while a peer is unreachable
#define DEFAULT_PEER_TIMEOUT 10 // seconds without a heartbeat → peer down
#define DEFAULT_PROBE_MS 500 // how long to wait for a conflict-check answer

#define ROLE_NODE 0 // answers DHCP
#define ROLE_CONTROLLER 1 // owns shared config; never answers DHCP

// Thread pool defaults
#define DEFAULT_WORKERS 4
#define MAX_WORKERS 64

// DHCP Packet Structure (RFC 2131)
struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[DHCP_CHADDR_LEN];
	char sname[DHCP_SNAME_LEN];
	char file[DHCP_FILE_LEN];
	uint32_t magic_cookie;
	uint8_t options[DHCP_OPTIONS_LEN];
} __attribute__((packed));

// DHCP Options Structure
typedef struct {
	uint8_t message_type;
	uint32_t requested_ip;
	uint32_t server_identifier;
	uint32_t lease_time;
	uint8_t parameter_list[256];
	uint8_t parameter_list_len;
	char hostname[256];
	uint8_t client_id[256];
	uint8_t client_id_len;
	bool found_message_type;
	bool found_requested_ip;
	bool found_server_id;
	bool found_lease_time;
	bool found_hostname;
	bool found_client_id;
} dhcp_options_t;

// Server Configuration
typedef struct {
	char *start_ip;
	char *end_ip;
	char *server_ip;
	char *subnet_mask;
	char *gateway;
	char *dns_servers[4];
	int dns_count;
	char *ntp_servers[4]; // option 42 — only sent when a client requests it
	int ntp_count;
	uint32_t lease_time;
	char *domain_name; // option 15 — sent to clients as search domain
	// Runtime file paths — populated from dhcp.conf or compile-time defaults
	char *lease_db_path;
	char *static_path;
	char *blacklist_path;
	char *log_path;
	char *pid_path;
	struct trie_t *ip_table;
	struct tree *mac_table;
	struct tree *blacklist;
	int num_workers;   // thread pool size (default DEFAULT_WORKERS)
	char *dump_path;   // path for SIGUSR1 lease dump output
	char *run_as_user; // drop to this user after bind; NULL = stay as-is

	// Lease journal (source of truth; members.txt is derived from it)
	char *journal_path;
	struct tree *ip_owner; // ip string → key of the lease-tree node holding it

	// Cluster mode — enabled when node_id is set.  Unset = single server.
	char *node_id;
	int role;			 // ROLE_NODE / ROLE_CONTROLLER
	char *cluster_dir;	 // cluster.conf + shared static/blacklist
	char *controller_ip; // where to pull shared config from (optional)
	int controller_port;
	char *peer_key_path;
	int peer_port;
	uint32_t mclt;
	uint32_t peer_timeout;
	uint32_t auto_partner_down; // 0 = never declare a peer down on our own
	char *conf_path;			// the dhcp.conf we were started with
	int probe_timeout_ms;		// conflict check before a fresh offer; 0 = off
} dhcp_config_t;

// One line of cluster.conf:  node|controller  <id>  <ip>  [port]
typedef struct {
	char id[NODE_ID_LEN];
	char ip[IP_STR_LEN];
	int port;
	int role;
} cluster_member_t;

// Lease Information
typedef struct {
	char mac[MAC_STR_LEN];
	char ip[IP_STR_LEN];
	char hostname[256];
	time_t expires;
	bool is_static;
} lease_entry_t;

void cleanup_config(void);

#endif /* TYPES_H */
