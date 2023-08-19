# include <bpf/bpf_helpers.h>
// # include "vmlinux.h" // TODO how to use core import vmlinux? why this fails?

// Everything is host order
// For now only support TCP

// struct bpf_map_def dport_forward_map SEC("maps") = {
//     .type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(__u16),
//     .value_size = sizeof(__u16),
//     .max_entries = 1024,
// };


typedef struct dnat_key_t
{
    unsigned int saddr;
    unsigned short sport;
    // unsigned char proto;
} dnat_key_t;

typedef struct dnat_value_t
{
    unsigned int daddr;
    unsigned short dport;
} dnat_value_t;

struct bpf_map_def dnat_map SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(dnat_key_t),
    .value_size = sizeof(dnat_value_t),
    .max_entries = 1024,
};

typedef struct conntrack_key_t
{
    unsigned int saddr;
    unsigned short sport;
    unsigned char proto;
} conntrack_key_t;

typedef struct conntrack_value_t
{
    unsigned int daddr;
    unsigned int updated_daddr;
    unsigned short dport;
    unsigned short updated_dport;
} conntrack_value_t;

struct bpf_map_def ct_map SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(conntrack_key_t),
    .value_size = sizeof(conntrack_value_t),
    .max_entries = 1024,
};