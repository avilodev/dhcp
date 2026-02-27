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
    uint32_t value;     /* hash key - was int (truncated 64-bit hash) */
    char *ip;
    time_t expires;     /* 0 = no expiry; otherwise Unix timestamp */

    struct Tree_Node *left;
    struct Tree_Node *right;
    struct Tree_Node *parent;

    int color;          /* 0 = black, 1 = red */
};

struct Tree
{
    struct Tree_Node *head;
};

struct Tree *create_tree(void);
void destroy_tree(struct Tree *);

uint32_t hash_string(const char *str);

struct Tree_Node *add_tree_node(struct Tree *, uint32_t, char *, time_t);
int insert_node(struct Tree *, struct Tree_Node *);

void rotate_left(struct Tree *, struct Tree_Node *);
void rotate_right(struct Tree *, struct Tree_Node *);
void insert_fixup(struct Tree *, struct Tree_Node *);

struct Tree_Node *find_node(struct Tree *, uint32_t);

void treeprint(struct Tree_Node *, int);
void deleteTree(struct Tree_Node *);

#endif /* NODE_H */
