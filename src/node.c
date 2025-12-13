#include "node.h"

struct Tree* create_tree() {
    struct Tree* tree = malloc(sizeof(struct Tree));
    if (tree) 
    {
        tree->head = NULL;
    }
    return tree; 
}

void destroy_tree(struct Tree* tree)  
{
    if (tree) 
    {
        deleteTree(tree->head);
        free(tree);
    }
}

int hash_string(char* mac) 
{
    unsigned long hash = 5381;
    int c;
    while ((c = *mac++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

struct Tree_Node* add_tree_node(struct Tree* tree, int _value, char* _ip) 
{
    struct Tree_Node* node = malloc(sizeof(struct Tree_Node));
    node->value = _value;
    node->ip = _ip;
    node->left = NULL;
    node->right = NULL;
    node->parent = NULL;
    
    int ret = insert_node(tree, node);
    if(ret != 1)
        return NULL;
    
    return node;
}

int insert_node(struct Tree* tree, struct Tree_Node* _node) 
{
    if(!tree->head) {
        tree->head = _node;
        tree->head->color = 0;
        //printf("Inserting Node: %d\n", _node->value);
        return 1;
    }
    
    struct Tree_Node* node = tree->head;
    struct Tree_Node* parent = NULL;
    
    while(node) {
        parent = node;
        if(node->value == _node->value) {
            //printf("Duplicate Node Detected: %d\n", _node->value);
            free(_node);
            return -1;
        }
        else if(node->value > _node->value) {
            node = node->left;
        }
        else {
            node = node->right;
        }
    }
    
    _node->parent = parent;
    _node->color = 1;
    
    if(parent->value > _node->value) {
        parent->left = _node;
        //printf("Inserting Left: %d\n", _node->value);
    }
    else {
        parent->right = _node;
        //printf("Inserting Right: %d\n", _node->value);
    }
    
    insert_fixup(tree, _node);
    return 1;
}

void insert_fixup(struct Tree* tree, struct Tree_Node* node) 
{
    while(node != tree->head && node->parent && node->parent->color == 1) {
        if(node->parent == node->parent->parent->left) {
            struct Tree_Node* uncle = node->parent->parent->right;
            if(uncle && uncle->color == 1) {
                //printf("Case 1 Left: Recoloring around %d\n", node->value);
                node->parent->color = 0;
                uncle->color = 0;
                node->parent->parent->color = 1;
                node = node->parent->parent;
            }
            else {
                if(node == node->parent->right) {
                    //printf("Case 2 Left: Left rotate around %d\n", node->parent->value);
                    node = node->parent;
                    rotate_left(tree, node);
                }
                //printf("Case 3 Left: Right rotate around %d\n", node->parent->parent->value);
                node->parent->color = 0;
                node->parent->parent->color = 1;
                rotate_right(tree, node->parent->parent);
            }
        }
        else {
            // Same fix needed for the right side...
            struct Tree_Node* uncle = node->parent->parent->left;
            if(uncle && uncle->color == 1) {
                //printf("Case 1 Right: Recoloring around %d\n", node->value);
                node->parent->color = 0;
                uncle->color = 0;
                node->parent->parent->color = 1;
                node = node->parent->parent;
            }
            else {
                if(node == node->parent->left) {
                    //printf("Case 2 Right: Right rotate around %d\n", node->parent->value);
                    node = node->parent;
                    rotate_right(tree, node);
                }
                //printf("Case 3 Right: Left rotate around %d\n", node->parent->parent->value);
                node->parent->color = 0;
                node->parent->parent->color = 1;
                rotate_left(tree, node->parent->parent);
            }
        }
    }
    tree->head->color = 0;
}

void rotate_left(struct Tree* tree, struct Tree_Node* node) 
{
    struct Tree_Node* right_child = node->right;
    node->right = right_child->left;
    
    if(right_child->left)
        right_child->left->parent = node;
    
    right_child->parent = node->parent;
    
    if(!node->parent)
        tree->head = right_child;
    else if(node == node->parent->left)
        node->parent->left = right_child;
    else
        node->parent->right = right_child;
    
    right_child->left = node;
    node->parent = right_child;
}

void rotate_right(struct Tree* tree, struct Tree_Node* node) 
{
    struct Tree_Node* left_child = node->left;
    node->left = left_child->right;
    
    if(left_child->right)
        left_child->right->parent = node;
    
    left_child->parent = node->parent;
    
    if(!node->parent)
        tree->head = left_child;
    else if(node == node->parent->right)
        node->parent->right = left_child;
    else
        node->parent->left = left_child;
    
    left_child->right = node;
    node->parent = left_child;
}

struct Tree_Node* find_node(struct Tree* tree, int _value) 
{
    struct Tree_Node* node = tree->head;
    
    while(node) {
        if(node->value == _value)
            return node;
        else if(node->value > _value)
            node = node->left;
        else if(node->value < _value)
            node = node->right;
    }
    
    return NULL;
}

void treeprint(struct Tree_Node* _head, int level) 
{
    struct Tree_Node* root = _head;
    if (root == NULL)
        return;
    
    for (int i = 0; i < level; i++)
        printf(i == level - 1 ? "|-" : "  ");
    
    printf("%d (%d)\n", root->value, root->color);
    treeprint(root->left, level + 1);
    treeprint(root->right, level + 1);
}

void deleteTree(struct Tree_Node* node) 
{
    if (node == NULL)
        return;
    
    deleteTree(node->left);
    deleteTree(node->right);
    //printf("Deleting node: %d\n", node->value);
    free(node->ip);
    free(node);
}
