#ifndef NODE_H
#define NODE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#define MAXLINE 4096

struct Tree_Node
{
    uint32_t value;           /* DJB2 hash — BST ordering key */
    char    *key;             /* full key string — resolves hash collisions */
    char    *ip;
    char    *hostname;        /* last-seen DHCP hostname / static device label */
    time_t   expires;         /* 0 = no expiry; otherwise Unix timestamp */

    struct Tree_Node *chain;  /* singly-linked list of nodes sharing this hash */
    struct Tree_Node *left;
    struct Tree_Node *right;
    struct Tree_Node *parent;

    int color;                /* 0 = black, 1 = red */
};

struct Tree
{
    struct Tree_Node *head;
};

struct Tree *create_tree(void);
void destroy_tree(struct Tree *);

uint32_t hash_string(const char *str);

/* key is strdup'd internally; ip ownership passes to the node */
struct Tree_Node *add_tree_node(struct Tree *, const char *key, char *ip, time_t expires);
int insert_node(struct Tree *, struct Tree_Node *);

/* Update or set the hostname of an existing node (hostname is strdup'd) */
void update_node_hostname(struct Tree *tree, const char *key, const char *hostname);

void rotate_left(struct Tree *, struct Tree_Node *);
void rotate_right(struct Tree *, struct Tree_Node *);
void insert_fixup(struct Tree *, struct Tree_Node *);

struct Tree_Node *find_node(struct Tree *, const char *key);

/* Visitor callback for traverse_tree.  Return non-zero to stop early. */
typedef int (*tree_visitor_fn)(struct Tree_Node *node, void *ctx);

/* In-order traversal; calls fn(node, ctx) for every node in the tree.
 * Stops early if fn returns non-zero. */
void traverse_tree(struct Tree *tree, tree_visitor_fn fn, void *ctx);

void treeprint(struct Tree_Node *, int);
void deleteTree(struct Tree_Node *);

#endif /* NODE_H */
