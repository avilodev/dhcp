#ifndef TRIE_H
#define TRIE_H

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
 
#include <time.h>

struct Trie  
{
    struct Trie_Node* head;
};

struct Trie_Node
{
    struct Trie_Node* structure[256];
    int end;
};

struct Trie* create_trie();
struct Trie_Node* add_node();

void add_word(struct Trie*, char*);
void remove_word(struct Trie*, char*);

void lookup_trie(struct Trie*, char*);
int test_ip(struct Trie*, char*);

void print_trie(struct Trie*);
void print_trie_helper(struct Trie_Node*, char*, int);

void free_node(struct Trie_Node*);
void free_trie(struct Trie*);

#endif  