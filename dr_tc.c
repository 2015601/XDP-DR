#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/ip.h>
#include <sys/socket.h>
#include "bpf_helper.h"
#include "bpf_ip.h"

/*
 * tc classfiy action
 * load:
 * 	tc qdisc add dev enp0s8 clsact
 * 	tc filter add dev enp0s8 ingress bpf direct-action object-file dr_tc.o section clsact
 * unload:
 * 	tc filter delete dev enp0s8 ingress
 */

#if __LITTLE_ENDIAN__
#define TC_L2_MARK 0xFEFFU
#else
#define TC_L2_MARK 0xFFFEU
#endif

#define IPVERSION_DR 11

struct dr_l2_meta_data {
	__u16 mark;
} __attribute__((aligned(2)));

static __always_inline int ip_mark_check(struct __sk_buff *skb)
{
	void *data = (void*)(long)skb->data;
	void *data_end = (void*)(long)skb->data_end;

	if (__be16_to_cpu(skb->protocol) != ETH_P_IP) {
		// bpf_printk("not ip");
		return -1;
	}

	struct bpf_iphdr *iph = (struct bpf_iphdr *)(data+ETH_HLEN);
	if (iph+1 > data_end) {
		// bpf_printk("err len");
		return -2;
	}

	if (iph->version == IPVERSION_DR) {
		// bpf_printk("hit a");
		iph->version = IPVERSION;
		return 0;
	}

	return 1;
}

SEC("clsact")
int tc_dr_input_hook(struct __sk_buff *skb)
{
	struct bpf_redir_neigh nh_param ={};
	void *data = (void*)(long)skb->data;
	struct dr_l2_meta_data *meta = (void*)(long)skb->data_meta;

	if (meta + 1 > data) {
		if (ip_mark_check(skb)) {
			return TC_ACT_UNSPEC;
		}
	} else if (meta->mark != TC_L2_MARK) {
		return TC_ACT_UNSPEC;
	}

	// bpf_printk("Hit tc l2 mark, ingres %d, protocol %x", skb->ingress_ifindex, skb->protocol);

	nh_param.nh_family = AF_INET;
	nh_param.ipv4_nh = 211357868;// 172.16.153.12
	return bpf_redirect_neigh(skb->ingress_ifindex, &nh_param, sizeof(nh_param), 0);
}

char _license[] SEC("license") = "GPL";
