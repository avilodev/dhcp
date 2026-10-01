#ifndef NODE_H
#define NODE_H

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MAXLINE 4096

#ifndef NODE_ID_LEN
#define NODE_ID_LEN 16 // cluster node id, incl. NUL
#endif

struct tree_node {
	uint32_t value; // DJB2 hash — BST ordering key
	char *key;		// full key string — resolves hash collisions
	char *ip;
	char *hostname; // last-seen DHCP hostname / static device label
	time_t expires; // 0 = no expiry; otherwise Unix timestamp
	char *mac;		// hardware address last seen for this device

	// Live state
	bool bound;		 // ACKed lease (false = tentative OFFER / none)
	bool is_static;	 // from static_list.txt — never expires/journaled
	bool is_decline; // "!decline/<ip>" placeholder holding a declined IP
	bool unverified; // fresh offer: not yet checked for a conflict

	// The latest journal record for this key
	char origin[NODE_ID_LEN];
	uint64_t seq;
	time_t rec_time;
	uint8_t rec_op;
	char rec_ip[16];
	time_t rec_expires;

	struct tree_node *chain; // singly-linked list of nodes sharing this hash
	struct tree_node *left;
	struct tree_node *right;
	struct tree_node *parent;

	int color; // 0 = black, 1 = red
};

struct tree {
	struct tree_node *head;
};

struct tree *create_tree(void);
void destroy_tree(struct tree *);

uint32_t hash_string(const char *str);

// key is strdup'd internally; ip ownership passes to the node
struct tree_node *add_tree_node(struct tree *, const char *key, char *ip, time_t expires);
int insert_node(struct tree *, struct tree_node *);

// Update or set the hostname of an existing node (hostname is strdup'd)
void update_node_hostname(struct tree *tree, const char *key, const char *hostname);

void rotate_left(struct tree *, struct tree_node *);
void rotate_right(struct tree *, struct tree_node *);
void insert_fixup(struct tree *, struct tree_node *);

struct tree_node *find_node(struct tree *, const char *key);

// Visitor callback for traverse_tree.  Return non-zero to stop early.
typedef int (*tree_visitor_fn)(struct tree_node *node, void *ctx);

// In-order traversal; calls fn(node, ctx) for every node in the tree.
void traverse_tree(struct tree *tree, tree_visitor_fn fn, void *ctx);

void delete_tree(struct tree_node *);

#endif /* NODE_H */
