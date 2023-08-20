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
#include "lib/parse_helpers.h"
// #include "lib/vmlinux.h"


#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_DEST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define TCP_DPORT_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define IS_PSEUDO 0x10

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



SEC("lb_ingress")
int simple_lb_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    int iphsize;
    unsigned short dport;
    struct iphdr *ip;
    if (__revalidate_data_pull(skb, &data, &data_end, (void *)&ip, sizeof(struct iphdr), sizeof(struct tcphdr), true))
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    iphsize = ip->ihl * 4;


    struct tcphdr *tcp = data + sizeof(*eth) + iphsize;
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    // simple port forward
    // unsigned short *forward_port;
    // dport = bpf_ntohs(tcp->dest);
    // forward_port = bpf_map_lookup_elem(&dport_forward_map, &dport);

    dnat_key_t dnat_key = {0};
    dnat_key.saddr = bpf_ntohl(ip->daddr);
    dnat_key.sport = bpf_ntohs(tcp->dest);
    dnat_value_t *dnat_value = bpf_map_lookup_elem(&dnat_map, &dnat_key);

    if (dnat_value) {
        // update dport new method update csum
        __u16 old_dport = tcp->dest;
        __u16 new_dport = bpf_htons(dnat_value->dport);
        tcp->dest = new_dport;

        // TODO why don't update checksum still work?
        // TODO verifier error
        
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_dport, new_dport, sizeof(new_dport)))
            return TC_ACT_OK;

        if (__revalidate_data_pull(skb, &data, &data_end, (void *)&ip, sizeof(struct iphdr), sizeof(struct tcphdr), false))
            return TC_ACT_OK;

        // if ((data + sizeof(*eth) + iphsize + sizeof(*tcp)) > data_end)
        //     return TC_ACT_OK;


        // update daddr
        unsigned int new_daddr = bpf_htonl(dnat_value->daddr);
        if (ip->daddr != new_daddr) {
            unsigned int old_daddr = ip->daddr;
            ip->saddr = old_daddr;
            ip->daddr = new_daddr;

            // TODO why don't update checksum still work?
            // TODO verifier error
            if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_daddr, new_daddr, IS_PSEUDO | sizeof(new_dport)))
                return TC_ACT_OK;
            if (bpf_l3_csum_replace(skb, IP_DEST_OFF, old_daddr, new_daddr, sizeof(new_daddr)))
                return TC_ACT_OK;
            if (__revalidate_data_pull(skb, &data, &data_end, (void *)&ip, sizeof(struct iphdr), sizeof(struct tcphdr), false))
                return TC_ACT_OK;
        }

        // TODO lookup FIB and change mac addr?

        // update conntrack map


        struct conntrack_key_t conn_key = {0};
        struct conntrack_value_t conn_value = {0};
 
        conn_key.proto = ip->protocol;
        conn_key.saddr = bpf_ntohs(ip->saddr);
        conn_key.sport = bpf_ntohs(tcp->source);
        conn_value.daddr = bpf_ntohs(ip->daddr);
        conn_value.dport = bpf_ntohs(old_dport);
        conn_value.updated_dport = dnat_value->dport;

        // TODO check error and log
        bpf_map_update_elem(&ct_map, &conn_key, &conn_value, BPF_ANY);
    }

    return TC_ACT_OK;
}


// TC eBPF program attached to the same device
// 1. read map
// 2. if match, modify daddr/dport

SEC("lb_egress")
int simple_lb_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *ip;
    if (__revalidate_data_pull(skb, &data, &data_end, (void *)&ip, sizeof(struct iphdr), sizeof(struct tcphdr), true))
        return TC_ACT_OK;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

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
        ip->saddr = bpf_htonl(conn_value->daddr);
    }

    return TC_ACT_OK;
}