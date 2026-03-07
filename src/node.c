#include "node.h"

struct Tree *create_tree(void) {
    struct Tree *tree = malloc(sizeof(struct Tree));
    if (tree)
        tree->head = NULL;
    return tree;
}

void destroy_tree(struct Tree *tree) {
    if (tree) {
        deleteTree(tree->head);
        free(tree);
    }
}

uint32_t hash_string(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++))
        hash = ((hash << 5) + hash) + (uint32_t)c;
    return hash;
}

struct Tree_Node *add_tree_node(struct Tree *tree, const char *key,
                                char *ip, time_t expires) {
    if (!tree || !key) return NULL;

    struct Tree_Node *node = malloc(sizeof(struct Tree_Node));
    if (!node) return NULL;

    node->key      = strdup(key);
    if (!node->key) { free(node); return NULL; }
    node->value    = hash_string(key);
    node->ip       = ip;
    node->hostname = NULL;
    node->expires  = expires;
    node->chain    = NULL;
    node->left     = NULL;
    node->right    = NULL;
    node->parent   = NULL;
    node->color    = 1;

    if (insert_node(tree, node) != 1) {
        /* Already have this key — free what we allocated and bail */
        free(node->key);
        free(node->ip);
        free(node);
        return NULL;
    }

    return node;
}

int insert_node(struct Tree *tree, struct Tree_Node *_node) {
    if (!tree->head) {
        tree->head = _node;
        tree->head->color = 0;
        return 1;
    }

    struct Tree_Node *node   = tree->head;
    struct Tree_Node *parent = NULL;

    while (node) {
        parent = node;
        if (node->value == _node->value) {
            /* Same hash value — walk the chain to see if it's the same key or just a collision */
            struct Tree_Node *chain = node;
            while (chain) {
                if (strcmp(chain->key, _node->key) == 0)
                    return -1;  /* Exact same key — reject */
                if (!chain->chain) break;
                chain = chain->chain;
            }
            /* Different key but same hash — hang it off the collision chain */
            chain->chain   = _node;
            _node->parent  = NULL;
            _node->left    = NULL;
            _node->right   = NULL;
            return 1;
        } else if (node->value > _node->value) {
            node = node->left;
        } else {
            node = node->right;
        }
    }

    _node->parent = parent;
    _node->color  = 1;

    if (parent->value > _node->value)
        parent->left = _node;
    else
        parent->right = _node;

    insert_fixup(tree, _node);
    return 1;
}

void insert_fixup(struct Tree *tree, struct Tree_Node *node) {
    while (node != tree->head && node->parent && node->parent->color == 1) {
        if (!node->parent->parent) break;
        if (node->parent == node->parent->parent->left) {
            struct Tree_Node *uncle = node->parent->parent->right;
            if (uncle && uncle->color == 1) {
                node->parent->color         = 0;
                uncle->color                = 0;
                node->parent->parent->color = 1;
                node = node->parent->parent;
            } else {
                if (node == node->parent->right) {
                    node = node->parent;
                    rotate_left(tree, node);
                }
                node->parent->color         = 0;
                node->parent->parent->color = 1;
                rotate_right(tree, node->parent->parent);
            }
        } else {
            struct Tree_Node *uncle = node->parent->parent->left;
            if (uncle && uncle->color == 1) {
                node->parent->color         = 0;
                uncle->color                = 0;
                node->parent->parent->color = 1;
                node = node->parent->parent;
            } else {
                if (node == node->parent->left) {
                    node = node->parent;
                    rotate_right(tree, node);
                }
                node->parent->color         = 0;
                node->parent->parent->color = 1;
                rotate_left(tree, node->parent->parent);
            }
        }
    }
    tree->head->color = 0;
}

void rotate_left(struct Tree *tree, struct Tree_Node *node) {
    struct Tree_Node *right_child = node->right;
    node->right = right_child->left;

    if (right_child->left)
        right_child->left->parent = node;

    right_child->parent = node->parent;

    if (!node->parent)
        tree->head = right_child;
    else if (node == node->parent->left)
        node->parent->left = right_child;
    else
        node->parent->right = right_child;

    right_child->left = node;
    node->parent      = right_child;
}

void rotate_right(struct Tree *tree, struct Tree_Node *node) {
    struct Tree_Node *left_child = node->left;
    node->left = left_child->right;

    if (left_child->right)
        left_child->right->parent = node;

    left_child->parent = node->parent;

    if (!node->parent)
        tree->head = left_child;
    else if (node == node->parent->right)
        node->parent->right = left_child;
    else
        node->parent->left = left_child;

    left_child->right = node;
    node->parent      = left_child;
}

/* Look up a key by hash, then confirm with strcmp to handle hash collisions. */
struct Tree_Node *find_node(struct Tree *tree, const char *key) {
    if (!tree || !key) return NULL;
    uint32_t hash = hash_string(key);
    struct Tree_Node *node = tree->head;

    while (node) {
        if (node->value == hash) {
            /* Hash matched — now confirm the key matches exactly */
            struct Tree_Node *chain = node;
            while (chain) {
                if (strcmp(chain->key, key) == 0)
                    return chain;
                chain = chain->chain;
            }
            return NULL;
        } else if (node->value > hash) {
            node = node->left;
        } else {
            node = node->right;
        }
    }
    return NULL;
}

void treeprint(struct Tree_Node *_head, int level) {
    if (!_head) return;
    for (int i = 0; i < level; i++)
        printf(i == level - 1 ? "|-" : "  ");
    printf("%u (%d) key=%s\n", _head->value, _head->color,
           _head->key ? _head->key : "(null)");
    treeprint(_head->left,  level + 1);
    treeprint(_head->right, level + 1);
}

void deleteTree(struct Tree_Node *node) {
    if (!node) return;
    deleteTree(node->left);
    deleteTree(node->right);

    /* Free any nodes chained off this one due to hash collisions */
    struct Tree_Node *chain = node->chain;
    while (chain) {
        struct Tree_Node *next = chain->chain;
        free(chain->key);
        free(chain->ip);
        free(chain->hostname);
        free(chain);
        chain = next;
    }

    free(node->key);
    free(node->ip);
    free(node->hostname);
    free(node);
}

/* In-order traversal visits every BST node and every node in its collision chain. */
static void traverse_inorder(struct Tree_Node *node, tree_visitor_fn fn, void *ctx, int *stop) {
    if (!node || *stop) return;
    traverse_inorder(node->left, fn, ctx, stop);
    if (*stop) return;
    /* Visit the primary node, then walk any chained entries at the same hash */
    struct Tree_Node *cur = node;
    while (cur && !*stop) {
        if (fn(cur, ctx)) *stop = 1;
        cur = cur->chain;
    }
    traverse_inorder(node->right, fn, ctx, stop);
}

void traverse_tree(struct Tree *tree, tree_visitor_fn fn, void *ctx) {
    if (!tree || !fn) return;
    int stop = 0;
    traverse_inorder(tree->head, fn, ctx, &stop);
}

void update_node_hostname(struct Tree *tree, const char *key, const char *hostname) {
    if (!tree || !key) return;
    struct Tree_Node *node = find_node(tree, key);
    if (!node) return;
    free(node->hostname);
    node->hostname = hostname ? strdup(hostname) : NULL;
}
