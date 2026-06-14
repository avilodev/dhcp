#include "trie.h"

#define MAXLINE 4096

struct Trie* create_trie()
{
    struct Trie* trie = malloc(sizeof(struct Trie));
    if(!trie)
        return NULL;

    trie->head = add_node();
    if(!trie->head)
    {
        free(trie);
        return NULL; 
    }

    return trie; 
}

struct Trie_Node* add_node()
{
    struct Trie_Node* node = malloc(sizeof(struct Trie_Node));

    if(!node)
        return NULL;

    for(int i = 0; i < 256; i++)
    {
        node->structure[i] = NULL;
    }
    node->end = 0;

    return node;
}

void add_word(struct Trie* trie, char* word)
{
    if(!trie || !trie->head)
        return;

    struct Trie_Node* current = trie->head;

    char word_copy[MAXLINE];
    strncpy(word_copy, word, MAXLINE - 1);
    word_copy[MAXLINE - 1] = '\0';

    char *octet1 = word_copy;
    char *octet2 = strchr(octet1, '.');
    if(!octet2) return; 
    *octet2++ = '\0';
    char *octet3 = strchr(octet2, '.');
    if(!octet3) return;
    *octet3++ = '\0';
    char *octet4 = strchr(octet3, '.');
    if(!octet4) return;
    *octet4++ = '\0';

    int octet[4];
    octet[0] = atoi(octet1);
    octet[1] = atoi(octet2);
    octet[2] = atoi(octet3);
    octet[3] = atoi(octet4);

    for(size_t i = 0; i < 4; i++)
    {
        int index = octet[i];
        if(index < 0 || index > 255)
            return;

        if(!current->structure[index])
        {
            current->structure[index] = add_node();
            if(!current->structure[index])
                return;
        }

        current = current->structure[index];
    }
    current->end = 1;
}

void remove_word(struct Trie *trie, char *word) {
    if (!trie || !trie->head || !word) return;

    struct Trie_Node *current = trie->head;

    char word_copy[MAXLINE];
    strncpy(word_copy, word, MAXLINE - 1);
    word_copy[MAXLINE - 1] = '\0';

    char *octet1 = word_copy;
    char *octet2 = strchr(octet1, '.'); if (!octet2) return; *octet2++ = '\0';
    char *octet3 = strchr(octet2, '.'); if (!octet3) return; *octet3++ = '\0';
    char *octet4 = strchr(octet3, '.'); if (!octet4) return; *octet4++ = '\0';

    int octet[4];
    octet[0] = atoi(octet1); octet[1] = atoi(octet2);
    octet[2] = atoi(octet3); octet[3] = atoi(octet4);

    for (int i = 0; i < 4; i++) {
        int index = octet[i];
        if (index < 0 || index > 255) return;
        if (!current->structure[index]) return; /* never inserted */
        current = current->structure[index];
    }
    current->end = 0;
}

int test_ip(struct Trie* trie, char* word)
{
    if(!trie || !trie->head || !word)
        return 0;

    struct Trie_Node* current = trie->head;

    char word_copy[MAXLINE];
    strncpy(word_copy, word, MAXLINE - 1);
    word_copy[MAXLINE - 1] = '\0';

    char *octet1 = word_copy;
    char *octet2 = strchr(octet1, '.');
    if(!octet2) return 0; 
    *octet2++ = '\0';
    char *octet3 = strchr(octet2, '.');
    if(!octet3) return 0;
    *octet3++ = '\0';
    char *octet4 = strchr(octet3, '.');
    if(!octet4) return 0;
    *octet4++ = '\0';

    int octet[4];
    octet[0] = atoi(octet1);
    octet[1] = atoi(octet2);
    octet[2] = atoi(octet3);
    octet[3] = atoi(octet4);

    for(size_t i = 0; i < 4; i++)
    {
        int index = octet[i];
        if(index < 0 || index > 255)
            return 0;

        if(!current->structure[index])
        {
            return 0;
        }
        current = current->structure[index];
    }
    return current->end;
}

void free_node(struct Trie_Node* node)
{
    if(!node)
        return;
    
    for(int i = 0; i < 256; i++) 
    {
        if(node->structure[i])
            free_node(node->structure[i]);
    }
    
    free(node);
}

void free_trie(struct Trie* trie)
{
    if(!trie)
        return;
    
    free_node(trie->head);
    free(trie);
}