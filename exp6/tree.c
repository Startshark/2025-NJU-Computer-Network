#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define INVALID_PORT ((uint32_t)-1)
#if !defined(LIKELY)
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

struct TrieNode {
    struct TrieNode* children[2];
    uint32_t port;
    int is_end;
};

struct AdvancedNode {
    struct AdvancedNode* children[16]; // 改成16叉树(4 bit)
    uint32_t port;
    uint32_t best_port;               // 记录到此节点为止的最长前缀端口
    int is_end;
};

static struct TrieNode* g_basic_root = NULL;
static struct AdvancedNode* g_adv_root = NULL;

static struct TrieNode* alloc_node(void){
    struct TrieNode* node = (struct TrieNode*)malloc(sizeof(struct TrieNode));
    if(!node){
        perror("malloc TrieNode failed");
        exit(EXIT_FAILURE);
    }
    node->children[0] = node->children[1] = NULL;
    node->port = INVALID_PORT;
    node->is_end = 0;
    return node;
}

static void free_trie(struct TrieNode* root){
    if(!root) return;
    free_trie(root->children[0]);
    free_trie(root->children[1]);
    free(root);
}

static int parse_ipv4(const char* ip_str, uint32_t* out_ip){
    unsigned int a,b,c,d;
    if(sscanf(ip_str, "%u.%u.%u.%u", &a,&b,&c,&d) != 4) return 0;
    if(a>255 || b>255 || c>255 || d>255) return 0;
    *out_ip = (a<<24) | (b<<16) | (c<<8) | d;
    return 1;
}

static struct AdvancedNode* alloc_adv_node(void){
    struct AdvancedNode* node = (struct AdvancedNode*)malloc(sizeof(struct AdvancedNode));
    if(!node){
        perror("malloc AdvancedNode failed");
        exit(EXIT_FAILURE);
    }
    for(int i = 0; i < 16; ++i){
        node->children[i] = NULL;
    }
    node->port = INVALID_PORT;
    node->best_port = INVALID_PORT;
    node->is_end = 0;
    return node;
}

static void free_adv_trie(struct AdvancedNode* root){
    if(!root) return;
    for(int i = 0; i < 16; ++i){
        free_adv_trie(root->children[i]);
    }
    free(root);
}

static void propagate_best_port(struct AdvancedNode* node, uint32_t inherited){
    if(!node) return;
    uint32_t current = inherited;
    if(node->is_end) current = node->port;
    node->best_port = current;
    for(int i = 0; i < 16; ++i){
        propagate_best_port(node->children[i], current);
    }
}
static void insert_prefix(struct TrieNode** root, uint32_t ip, int mask_len, uint32_t port){
    if(mask_len < 0 || mask_len > 32) return;
    if(!*root) *root = alloc_node();
    struct TrieNode* cur = *root;
    for(int i = 0; i < mask_len; ++i){
        int bit = (ip >> (31 - i)) & 1;
        if(!cur->children[bit]) cur->children[bit] = alloc_node();
        cur = cur->children[bit];
    }
    cur->is_end = 1;
    cur->port = port;
}

static void insert_prefix_adv(uint32_t ip, int mask_len, uint32_t port){
    if(mask_len < 0 || mask_len > 32) return;
    if(!g_adv_root) g_adv_root = alloc_adv_node();
    struct AdvancedNode* cur = g_adv_root;

    int full_steps = mask_len / 4;
    int remainder = mask_len % 4;

    for(int i = 0; i < full_steps; ++i){
        int nibble = (ip >> (28 - i * 4)) & 0xF;
        if(!cur->children[nibble]) cur->children[nibble] = alloc_adv_node();
        cur = cur->children[nibble];
    }

    if(remainder == 0){
        cur->is_end = 1;
        cur->port = port;
        return;
    }

    int shift = 4 - remainder;
    int nibble = (ip >> (28 - full_steps * 4)) & 0xF;
    int prefix = nibble >> shift;
    int start = prefix << shift;
    int end = start + ((1 << shift) - 1);

    for(int val = start; val <= end; ++val){
        if(!cur->children[val]) cur->children[val] = alloc_adv_node();
        cur->children[val]->is_end = 1;
        cur->children[val]->port = port;
    }
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    FILE* fp = fopen(lookup_file, "r");
    if(!fp){
        fprintf(stderr, "Error opening file %s\n", lookup_file);
        exit(EXIT_FAILURE);
    }
    uint32_t* ip_vec = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(!ip_vec){
        perror("malloc ip_vec failed");
        fclose(fp);
        exit(EXIT_FAILURE);
    }
    char ip_str[64];
    for(int i = 0; i < TEST_SIZE; ++i){
        if(fscanf(fp, "%63s", ip_str) != 1){
            fprintf(stderr, "lookup file format error at line %d\n", i + 1);
            ip_vec[i] = INVALID_PORT;
            continue;
        }
        if(!parse_ipv4(ip_str, &ip_vec[i])){
            fprintf(stderr, "invalid ip string %s at line %d\n", ip_str, i + 1);
            ip_vec[i] = 0;
        }
    }
    fclose(fp);
    return ip_vec;
}

// Constructing a basic trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
    if(g_basic_root){
        free_trie(g_basic_root);
        g_basic_root = NULL;
    }
    FILE* fp = fopen(forward_file, "r");
    if(!fp){
        fprintf(stderr, "Open forwarding table failed: %s\n", forward_file);
        exit(EXIT_FAILURE);
    }
    char ip_str[64];
    int mask_len;
    unsigned int port;
    while(fscanf(fp, "%63s %d %u", ip_str, &mask_len, &port) == 3){
        uint32_t ip_val;
        if(!parse_ipv4(ip_str, &ip_val)) continue;
        insert_prefix(&g_basic_root, ip_val, mask_len, port);
    }
    fclose(fp);
}

// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    if(!ip_vec){
        fprintf(stderr, "lookup_tree received NULL ip_vec\n");
        return NULL;
    }
    uint32_t* result = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(!result){
        perror("malloc lookup result failed");
        exit(EXIT_FAILURE);
    }
    for(int i = 0; i < TEST_SIZE; ++i){
        uint32_t ip = ip_vec[i];
        uint32_t matched_port = INVALID_PORT;
        struct TrieNode* cur = g_basic_root;
        if(cur && cur->is_end) matched_port = cur->port;
        for(int bit_idx = 0; bit_idx < 32 && cur; ++bit_idx){
            int bit = (ip >> (31 - bit_idx)) & 1;
            cur = cur->children[bit];
            if(!cur) break;
            if(cur->is_end) matched_port = cur->port;
        }
        result[i] = matched_port;
    }
    return result;
}

// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file){
    if(g_adv_root){
        free_adv_trie(g_adv_root);
        g_adv_root = NULL;
    }

    FILE* fp = fopen(forward_file, "r");
    if(!fp){
        fprintf(stderr, "Open forwarding table failed: %s\n", forward_file);
        exit(EXIT_FAILURE);
    }

    char ip_str[64];
    int mask_len;
    unsigned int port;

    while(fscanf(fp, "%63s %d %u", ip_str, &mask_len, &port) == 3){
        uint32_t ip_val;
        if(!parse_ipv4(ip_str, &ip_val)) continue;
        insert_prefix_adv(ip_val, mask_len, port);
    }

    fclose(fp);

    propagate_best_port(g_adv_root, INVALID_PORT);
}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    if(!ip_vec){
        fprintf(stderr, "lookup_tree_advance received NULL ip_vec\n");
        return NULL;
    }

    uint32_t* result = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
    if(!result){
        perror("malloc advanced lookup result failed");
        exit(EXIT_FAILURE);
    }

    for(int i = 0; i < TEST_SIZE; ++i){
        register uint32_t shift_ip = ip_vec[i];
        register struct AdvancedNode* cur = g_adv_root;
        register uint32_t matched_port = INVALID_PORT;

        if(LIKELY(cur)) matched_port = cur->best_port;

#define ADV_STEP do { \
    if (UNLIKELY(!cur)) break; \
    int nibble = (int)((shift_ip >> 28) & 0xF); \
    shift_ip <<= 4; \
    cur = cur->children[nibble]; \
    if (UNLIKELY(!cur)) break; \
    matched_port = cur->best_port; \
} while(0)

        // Unroll 8 steps (32 bits / 4)
        ADV_STEP; ADV_STEP; ADV_STEP; ADV_STEP;
        ADV_STEP; ADV_STEP; ADV_STEP; ADV_STEP;

#undef ADV_STEP

        result[i] = matched_port;
    }

    return result;
}