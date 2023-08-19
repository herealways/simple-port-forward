#include <string.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
// #include <linux/icmp.h>
// #include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <arpa/inet.h>
#include "lib/lib_maps.h"
// #include "lib/vmlinux.h"


char __license[] SEC("license") = "Dual MIT/GPL";

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline __u16 csum_fold_helper2(__u32 csum)
{
    return ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
                      __u32 *csum)
{
    *csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    *csum = csum_fold_helper2(*csum);
}



SEC("xdp")
int simple_lb(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int iphsize;
    unsigned short dport;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    iphsize = ip->ihl * 4;


    struct tcphdr *tcp = data + sizeof(*eth) + iphsize;
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    // simple port forward
    // unsigned short *forward_port;
    // dport = bpf_ntohs(tcp->dest);
    // forward_port = bpf_map_lookup_elem(&dport_forward_map, &dport);

    dnat_key_t dnat_key = {0};
    dnat_key.saddr = bpf_ntohl(ip->daddr);
    dnat_key.sport = bpf_ntohs(tcp->dest);
    dnat_value_t *dnat_value = bpf_map_lookup_elem(&dnat_map, &dnat_key);

    if (dnat_value) {
        // update dport
        struct tcphdr tcp_old;
        __u16 old_csum = tcp->check;
        tcp->check = 0;
        tcp_old = *tcp;
        __u16 old_dport = tcp->dest;

        tcp->dest = bpf_htons(dnat_value->dport);

        __u32 csum, size = sizeof(struct tcphdr);
        csum = bpf_csum_diff((__be32 *) &tcp_old, size, (__be32 *)tcp, size, ~old_csum);
        csum = csum_fold_helper(csum);

        tcp->check = csum;

        bpf_printk("tcp checksum after change dport: %d\n", tcp->check);

        // update daddr
        // TODO why ip checksum correct, but tcp incorrect? When not updating ip header, tcp checksum is correct
        unsigned int dnat_daddr = bpf_htonl(dnat_value->daddr);
        if (ip->daddr != dnat_daddr) {
            struct iphdr ip_old;
            __u16 old_csum = ip->check;
            ip->check = 0;
            ip_old = *ip;
            __be32 old_daddr = ip->daddr;

            ip->daddr = dnat_daddr;

            __u32 csum, size = sizeof(struct iphdr);
            csum = bpf_csum_diff((__be32 *) &ip_old, size, (__be32 *)ip, size, ~old_csum);
            csum = csum_fold_helper(csum);

            ip->check = csum;
        }

        bpf_printk("tcp checksum after change daddr: %d\n", tcp->check);


        // https://elixir.bootlin.com/linux/v6.0/source/samples/bpf/xdp_adjust_tail_kern.c#L63
        // TODO not calculated correctly
        // unsigned int dnat_daddr = bpf_htonl(dnat_value->daddr);
        // if (ip->daddr != dnat_daddr) {
        //     ip->daddr = dnat_daddr;
        //     ip->check = 0;
        //     __u32 csum = 0;
        //     ipv4_csum(ip, sizeof(struct iphdr), &csum);
        //     ip->check = csum;
        // }


        // update conntrack map

        // need to initialize all fields of struct, before updating it. Otherwise verifier will reject the prog
        // https://stackoverflow.com/questions/71529801/ebpf-bpf-map-update-returns-the-invalid-indirect-read-from-stack-error
        struct conntrack_key_t conn_key = {0};
        struct conntrack_value_t conn_value = {0};
        // or
        // memset(&conn_key, 0, sizeof(conn_key));
        // memset(&conn_value, 0, sizeof(conn_value));
 
        conn_key.proto = ip->protocol;
        conn_key.saddr = bpf_ntohs(ip->saddr);
        conn_key.sport = bpf_ntohs(tcp->source);
        conn_value.daddr = bpf_ntohs(ip->daddr);
        conn_value.dport = bpf_ntohs(old_dport);
        conn_value.updated_dport = dnat_value->dport;

        // TODO check error and log
        bpf_map_update_elem(&ct_map, &conn_key, &conn_value, BPF_ANY);
    }

    return XDP_PASS;
}


// TC eBPF program attached to the same device
// 1. read map
// 2. if match, modify daddr/dport

SEC("lb_egress")
int simple_lb_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;
    
   struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    // TODO other protocols
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    
    int iphsize = ip->ihl * 4;
    struct tcphdr *tcp = data + sizeof(*eth) + iphsize;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;
    
    struct conntrack_key_t conn_key = {0};
    conn_key.proto = ip->protocol;
    // reversed source and dest
    conn_key.saddr = bpf_ntohs(ip->daddr);
    conn_key.sport = bpf_ntohs(tcp->dest);

    struct conntrack_value_t *conn_value = bpf_map_lookup_elem(&ct_map, &conn_key);
    // TODO acutally can use skb to calculate checksum
    // TODO why don't need update checksum here? checksum offload?
    if (conn_value) {
        tcp->source = bpf_htons(conn_value->dport);
    }

    return TC_ACT_OK;
}