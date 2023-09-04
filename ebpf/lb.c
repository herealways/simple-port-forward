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
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
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

// Since the bpf program only track send packet, so this may not correct.
// However for now we just need to track connection changes to TIME_WAIT/CLOSE to gc conntrack map.
static __always_inline void update_conntrack_tcp_state(struct conntrack_value_t *conn_value, struct tcphdr *tcph) {
    if (conn_value->tcp_state == 0)
        conn_value->tcp_state = TCP_CLOSE;

    if (tcph->rst) {
        conn_value->tcp_state = TCP_CLOSE;
        return;
    }

    switch (conn_value->tcp_state) {
        case TCP_CLOSE:
            if (tcph->syn && tcph->ack)
                conn_value->tcp_state = TCP_SYN_RECV;
            else if (tcph->syn)
                conn_value->tcp_state = TCP_SYN_SENT;
            break;
        case TCP_SYN_SENT:
            if (tcph->ack)
                conn_value->tcp_state = TCP_ESTABLISHED;
            break;
        // not correct
        case TCP_SYN_RECV:
            if (tcph->ack)
                conn_value->tcp_state = TCP_ESTABLISHED;
            break;
        case TCP_ESTABLISHED:
            break;
        
    }
}

// change conntrack tcp state. Delete entry if state is closed
static __always_inline void update_conntrack_state(bool is_internal, struct conntrack_key_t *conn_key, struct conntrack_value_t *conn_value, struct iphdr *iph, struct tcphdr *tcph) {
    // if in map, check tcp flag, update tcp status
    if (tcph) {
        int previous_state = conn_value->tcp_state;
        


        // TODO looks like incorrect
        if (tcph->syn) {
            conn_value->tcp_state = TCP_SYN_SENT;
        } else if (tcph->syn && tcph->ack) {
            conn_value->tcp_state = TCP_SYN_RECV;
        } else if (tcph->ack || tcph->psh) {
            conn_value->tcp_state = TCP_ESTABLISHED;
        } else if (tcph->fin) {
            conn_value->tcp_state = TCP_FIN_WAIT1;
            // TODO repeat
        } else if (tcph->fin && tcph->ack) {
            conn_value->tcp_state = TCP_FIN_WAIT2;
        } else if (tcph->fin && tcph->ack) {
            conn_value->tcp_state = TCP_TIME_WAIT;
        } else if (tcph->rst) {
            conn_value->tcp_state = TCP_CLOSE;
        }
    }

    conn_value->timestamp = bpf_ktime_get_ns();

    if (is_internal)
        if (bpf_map_update_elem(&ct_map_internal, conn_key, conn_value, BPF_ANY))
            bpf_printk("update internal conntrack map error\n");
    else
        if (bpf_map_update_elem(&ct_map_external, conn_key, conn_value, BPF_ANY))
            bpf_printk("update external conntrack map error\n");
}


// Check if conn is tracked (both ingress and egress map), and if tracked update conntrack map
static __always_inline bool check_conntrack(struct conntrack_key_t *conn_key, struct conntrack_value_t *conn_value, struct iphdr *iph, struct tcphdr *tcph) {
    conn_value = bpf_map_lookup_elem(&ct_map_internal, conn_key);
    if (conn_value) {
        update_conntrack_state(true, conn_key, conn_value, iph, tcph);
        return true;
    }

    conn_value = bpf_map_lookup_elem(&ct_map_external, conn_key);
    if (conn_value) {
        update_conntrack_state(false, conn_key, conn_value, iph, tcph);
        return true;
    }

    return false;
}

static __always_inline int new_conntrack_entry(struct conntrack_key_t *conn_key, struct conntrack_value_t *conn_value, struct dnat_value_t *dnat_value, struct iphdr *iph, struct tcphdr *tcph, bool is_internal) {
    conn_key->proto = iph->protocol;
    conn_key->saddr = bpf_ntohl(iph->saddr);
    conn_key->sport = bpf_ntohs(tcph->source);

    conn_value->daddr = bpf_ntohl(iph->daddr);
    conn_value->dport = bpf_ntohs(tcph->dest);
    conn_value->updated_daddr = dnat_value->daddr;
    conn_value->updated_dport = dnat_value->dport;

    if (bpf_map_update_elem(&ct_map_internal, conn_key, conn_value, BPF_ANY)) {
        bpf_printk("update internal conntrack map error\n");
        return 1;
    }
    update_conntrack_state(true, conn_key, conn_value, iph, tcph);

    // Also create external conntrack entry
    struct conntrack_key_t external_conn_key = {0};
    struct conntrack_value_t external_conn_value = {0};
    external_conn_key.proto = iph->protocol;
    external_conn_key.saddr = dnat_value->daddr;
    external_conn_key.sport = dnat_value->dport;
    external_conn_value.daddr = bpf_ntohl(iph->daddr);
    external_conn_value.dport = bpf_ntohs(tcph->dest);
    external_conn_value.updated_daddr = bpf_ntohl(iph->saddr);
    external_conn_value.updated_dport = bpf_ntohs(tcph->source);

    if (bpf_map_update_elem(&ct_map_external, conn_key, conn_value, BPF_ANY)) {
        bpf_printk("update external conntrack map error\n");
        return 1;
    }

    return 0;
}

// TODO somewhere store the original sip and sport?
// TODO if new map, also need gc this
static __always_inline int do_dnat(struct __sk_buff *skb, void *data, void *data_end, struct dnat_key_t *dnat_key, struct dnat_value_t *dnat_value, struct iphdr *iph, struct tcphdr *tcph, bool *redirect_mode) {
    unsigned short old_dport;
    unsigned short new_dport;

    old_dport = tcph->dest;
    new_dport = bpf_htons(dnat_value->dport);
    tcph->dest = new_dport;

    if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_dport, new_dport, sizeof(new_dport)))
        return 1;

    if (__revalidate_data_pull(skb, &data, &data_end, (void *)&iph, sizeof(struct iphdr), sizeof(struct tcphdr), false))
        return 1;

    // TODO also need to change sport to a random one and make sure it's not used?
    // TODO e.g. If 2 clients with same sport connect, then will mess up

    // update daddr
    unsigned int new_daddr = bpf_htonl(dnat_value->daddr);
    if (iph->daddr != new_daddr) {
        unsigned int old_daddr = iph->daddr;
        unsigned int old_saddr = iph->saddr;

        *redirect_mode = true;
        ip_decrease_ttl(iph);

        iph->saddr = dnat_key->saddr;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_saddr, old_daddr, IS_PSEUDO | sizeof(old_daddr)))
            return 1;
        if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_saddr, old_daddr, sizeof(old_daddr)))
            return 1;

        if (__revalidate_data_l4(skb, &data, &data_end, (void *)&iph, (void *)&tcph, sizeof(struct iphdr), sizeof(struct tcphdr), false))
            return 1;

        iph->daddr = new_daddr;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_daddr, new_daddr, IS_PSEUDO | sizeof(new_daddr)))
            return 1;

        if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_daddr, new_daddr, sizeof(new_daddr)))
            return 1;
    }

    return 0;
}

static __always_inline void gc_conntrack_map(struct conntrack_key_t *conn_key, struct conntrack_value_t *conn_value, struct iphdr *iph, struct tcphdr *tcph, bool is_internal) {
    // TODO make sure tcp state machine can delete for time wait (last ack!)
    if (conn_value->tcp_state == TCP_CLOSE || conn_value->tcp_state == TCP_TIME_WAIT) {
        if (is_internal) {
            bpf_map_delete_elem(&ct_map_internal, conn_key);
            // Also delete external map entry
            struct conntrack_key_t external_conn_key = {0};
            external_conn_key.saddr = conn_value->updated_daddr;
            external_conn_key.sport = conn_value->updated_dport;
            external_conn_key.proto = iph->protocol;
            bpf_map_delete_elem(&ct_map_external, &external_conn_key);
        } else {
            bpf_map_delete_elem(&ct_map_external, conn_key);
            // Also delete internal map entry
            struct conntrack_key_t internal_conn_key = {0};
            internal_conn_key.saddr = conn_value->updated_daddr;
            internal_conn_key.sport = conn_value->updated_dport;
            internal_conn_key.proto = iph->protocol;
            bpf_map_delete_elem(&ct_map_internal, &internal_conn_key);
        }
    }
}

SEC("lb_ingress")
int simple_lb_ingress(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    unsigned short dport;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int old_saddr = 0;
    unsigned int old_daddr;
    __u16 old_dport;
    __u16 new_dport;
    bool redirect_mode = false;
    struct conntrack_key_t conn_key = {0};
    struct conntrack_value_t conn_value = {0};


    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (__revalidate_data_pull(skb, &data, &data_end, (void *)&iph, sizeof(struct iphdr), sizeof(struct tcphdr), true))
        return TC_ACT_OK;

    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;
    
    // TODO support udp, icmp
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcph = data + sizeof(*eth) + sizeof(*iph);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    conn_key.proto = iph->protocol;
    conn_key.saddr = bpf_ntohl(iph->saddr);
    conn_key.sport = bpf_ntohs(tcph->source);

    // TODO if is tracked, directly DNAT? no need to check dnat map
    bool is_tracked = check_conntrack(&conn_key, &conn_value, iph, tcph);


    dnat_key_t dnat_key = {0};
    dnat_key.saddr = bpf_ntohl(iph->daddr);
    dnat_key.sport = bpf_ntohs(tcph->dest);
    dnat_value_t *dnat_value = bpf_map_lookup_elem(&dnat_map, &dnat_key);

    // receive from client (internal)
    if (dnat_value) {
        if (!is_tracked)
            new_conntrack_entry(&conn_key, &conn_value, &dnat_key, iph, tcph, true);

        if (do_dnat(skb, data, data_end, &dnat_key, dnat_value, iph, tcph, &redirect_mode))
            return TC_ACT_OK;

        // TODO check conn_value before return. If is TCP and TCP state is TIME_WAIT / CLOSE, delete the entry (both?)
        gc_conntrack_map(&conn_key, &conn_value, iph, tcph, true);

        if (redirect_mode)
            // TODO read from host info bpf map
            return bpf_redirect_neigh(2, 0, 0, 0);
        else
            return TC_ACT_OK;
    }

    // receive resp from backend (external)


    // receive from backend? forward to client
    struct conntrack_key_t conn_key = {0};
    struct conntrack_value_t *conn_value;
    conn_key.proto = iph->protocol;
    conn_key.saddr = bpf_ntohl(iph->daddr);
    conn_key.sport = bpf_ntohs(tcph->dest);
    conn_value = bpf_map_lookup_elem(&ct_map_internal, &conn_key);

    if (conn_value) {
        ip_decrease_ttl(iph);
        unsigned int old_daddr = iph->daddr;
        unsigned int new_daddr = bpf_htonl(conn_value->original_saddr);
        iph->daddr = new_daddr;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_daddr, new_daddr, IS_PSEUDO | sizeof(new_daddr)))
            return TC_ACT_OK;
        if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_daddr, new_daddr, sizeof(new_daddr)))
            return TC_ACT_OK;

        if (__revalidate_data_l4(skb, &data, &data_end, (void *)&iph, (void *)&tcph, sizeof(struct iphdr), sizeof(struct tcphdr), false))
            return TC_ACT_OK;

        unsigned old_saddr = iph->saddr;
        // should change to local IP
        unsigned new_saddr = old_daddr;
        iph->saddr = new_saddr;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_saddr, new_saddr, IS_PSEUDO | sizeof(new_saddr)))
            return TC_ACT_OK;
        if (bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_saddr, new_saddr, sizeof(new_saddr)))
            return TC_ACT_OK;
        
        if (__revalidate_data_l4(skb, &data, &data_end, (void *)&iph, (void *)&tcph, sizeof(struct iphdr), sizeof(struct tcphdr), false))
            return TC_ACT_OK;
        
        unsigned short old_sport = tcph->source;
        unsigned short new_sport = bpf_htons(conn_value->dport);
        tcph->source = new_sport;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_sport, new_sport, sizeof(new_sport)))
            return TC_ACT_OK;

        return bpf_redirect_neigh(2, 0, 0, 0);
    }


    return TC_ACT_OK;
}


// TC eBPF program attached to the same device
// 1. read map
// 2. if match, modify daddr/dport

// TODO this prog only used for port forward on same host?
SEC("lb_egress")
int simple_lb_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph;
    struct ethhdr *eth = data;
    struct tcphdr *tcph;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    if (__revalidate_data_pull(skb, &data, &data_end, (void *)&iph, sizeof(struct iphdr), sizeof(struct tcphdr), true))
        return TC_ACT_OK;

    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    // TODO other protocols
    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    tcph = data + sizeof(*eth) + sizeof(*iph);
    if ((void *)(tcph + 1) > data_end)
        return TC_ACT_OK;

    struct conntrack_key_t conn_key = {0};
    conn_key.proto = iph->protocol;
    // reversed source and dest
    conn_key.saddr = bpf_ntohl(iph->daddr);
    conn_key.sport = bpf_ntohs(tcph->dest);

    struct conntrack_value_t *conn_value = bpf_map_lookup_elem(&ct_map_internal, &conn_key);
    // TODO bpf_redirect, mac
    // TODO TTL--?
    if (conn_value) {
        unsigned short old_port = tcph->source;
        unsigned short new_port = bpf_htons(conn_value->dport);
        unsigned int old_addr = iph->saddr;
        unsigned int new_addr = bpf_htonl(conn_value->daddr);   

        tcph->source = new_port;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_port, new_port, sizeof(new_port)))
            return TC_ACT_OK;

        if (__revalidate_data_l4(skb, &data, &data_end, (void *)&iph, (void *)&tcph, sizeof(struct iphdr), sizeof(struct tcphdr), false))
            return TC_ACT_OK;

        iph->saddr = new_addr;
        if (bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_addr, new_addr, IS_PSEUDO | sizeof(new_addr)))
            return TC_ACT_OK;
        if (bpf_l3_csum_replace(skb, IP_SRC_OFF, old_addr, new_addr, sizeof(new_addr)))
            return TC_ACT_OK;
    }

    return TC_ACT_OK;
}