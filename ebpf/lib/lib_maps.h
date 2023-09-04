# include <bpf/bpf_helpers.h>
# include "vmlinux.h" // TODO how to use core import vmlinux? why this fails?

// Everything is host order
// For now only support TCP

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
    // LB interface addr?
    unsigned int saddr;
    unsigned short sport;
    // TODO support tcp, udp, icmp
    unsigned char proto;
} conntrack_key_t;

typedef struct conntrack_value_t
{
    // unsigned int original_saddr;
    unsigned int daddr;
    // TODO remove, should be in separate map?
    unsigned int updated_daddr;
    unsigned short dport;
    // TODO remove, should be in separate map?
    unsigned short updated_dport;
    // TODO gc half open connections?
    int tcp_state;
    // Get by bpf_ktime_get_ns(), used for gc
    // TODO more cautious on tcp conn gc? tcp keepalive
    u64 timestamp;
} conntrack_value_t;

// e.g. 192.168.31.6 -> 192.168.31.11
struct bpf_map_def ct_map_internal SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(conntrack_key_t),
    .value_size = sizeof(conntrack_value_t),
    .max_entries = 1024,
};

// e.g. 192.168.31.11 -> 192.168.31.6
struct bpf_map_def ct_map_external SEC("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(conntrack_key_t),
    .value_size = sizeof(conntrack_value_t),
    .max_entries = 1024,
};