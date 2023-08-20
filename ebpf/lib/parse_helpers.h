#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

// TODO vmlinux.h
typedef _Bool bool;

enum {
	false = 0,
	true = 1,
};

static __inline int
__revalidate_data_pull(struct __sk_buff *skb, void **data_, void **data_end_,
                       void **l3, const __u32 l3_len, __u32 l4_len, const bool pull)
{
	const __u64 tot_len = ETH_HLEN + l3_len + l4_len;
	void *data_end;
	void *data;

	/* Verifier workaround, do this unconditionally: invalid size of register spill. */
	if (pull)
		bpf_skb_pull_data(skb, tot_len);
	data_end = (void*)((long)skb->data_end);
	data = (void*)((long)skb->data);
	if (data + tot_len > data_end)
		return 1;

	/* Verifier workaround: pointer arithmetic on pkt_end prohibited. */
	*data_ = data;
	*data_end_ = data_end;

	*l3 = data + ETH_HLEN;
	return 0;
}