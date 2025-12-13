#ifndef NODE_H
#define NODE_H

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
 
#include <sys/types.h>
#include <sys/stat.h>

#include <time.h>

#define MAXLINE 4096

struct Tree_Node
{
    int value;
    char* ip;

    struct Tree_Node* left;
    struct Tree_Node* right; 

    struct Tree_Node* parent;

    int color;            //0 for black, 1 for red
};

struct Tree
{
    struct Tree_Node* head;
};

// Tree management functions
struct Tree* create_tree();
void destroy_tree(struct Tree*);

// Node operations now take a Tree* parameter
int hash_string(char*);
struct Tree_Node* add_tree_node(struct Tree*, int, char*);
int insert_node(struct Tree*, struct Tree_Node*);

void rotate_left(struct Tree*, struct Tree_Node*);
void rotate_right(struct Tree*, struct Tree_Node*);
void insert_fixup(struct Tree*, struct Tree_Node*);

struct Tree_Node* find_node(struct Tree*, int);

void treeprint(struct Tree_Node*, int);
void deleteTree(struct Tree_Node*); 

#endif