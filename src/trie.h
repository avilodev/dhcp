#ifndef TRIE_H
#define TRIE_H

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <time.h>

struct trie_t {
	struct trie_node *head;
};

struct trie_node {
	struct trie_node *structure[256];
	int end;
};

struct trie_t *create_trie();
struct trie_node *add_node();

void add_word(struct trie_t *, char *);
void remove_word(struct trie_t *, char *);

int test_ip(struct trie_t *, char *);

void free_node(struct trie_node *);
void free_trie(struct trie_t *);

#endif /* TRIE_H */
