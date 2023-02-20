#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <sys/socket.h>
#include "xlb_helper.h"
#include "xlb_ether.h"
#include "xlb_ip.h"
#include "xlb_tcp.h"
#include "xlb.h"

/*
 * load object:
 * ip link set enp0s8 xdp object xlb_xdp_kernel.o section xdp
 * unload:
 * ip link set enp0s8 xdp off
 */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct xlb_service));
	__uint(value_size, sizeof(struct xlb_service_data));
	__uint(max_entries, XLB_MAX_SERVICES);
} vs_map SEC(".maps");

static __always_inline void encap_l2_pkt(struct ethhdr *eh, __u8 *dst)
{
	memcpy(eh->h_source, eh->h_dest, 6);
	memcpy(eh->h_dest, dst, 6);
}

SEC("xdp")
int xdp_dr_input_hook(struct xdp_md *ctx)
{
	struct ethhdr *eh;
	struct bpf_iphdr *iph;
	struct bpf_tcphdr *th;
	struct bpf_fib_lookup fib = {};
	void *data, *data_end;
	struct xlb_service hit_srv = {};
	struct xlb_rs *rs;
	struct xlb_service_data *srv_data;
	int ret;
	int ifindex;

	data = (void*)(long)ctx->data;
	data_end = (void*)(long)ctx->data_end;

	eh = (struct ethhdr*)data;
	if (eh + 1 > data_end || __be16_to_cpu(eh->h_proto) != ETH_P_IP) {
		return XDP_PASS;
	}

	iph = (struct bpf_iphdr*)(eh + 1);
	if (iph + 1 > data_end || iph->protocol != IPPROTO_TCP) {
		return XDP_PASS;
	}
	hit_srv.ip = iph->daddr;

	th = (struct bpf_tcphdr*)((char*)iph + (iph->ihl << 2));
	if (th + 1 > data_end) {
		return XDP_PASS;
	}
	hit_srv.protocol = iph->protocol;
	hit_srv.port = th->dest;

	// service hit
	srv_data = bpf_map_lookup_elem(&vs_map, &hit_srv);
	if (!srv_data) {
		return XDP_PASS;
	}

	if (srv_data->rs_cnt == 0) {
		return XDP_DROP;
	}

	bpf_printk("client hit");

	__u32 index = xlb_hash_32(iph->saddr, XLB_RS_HASH_TAB_BIT) & (srv_data->rs_cnt-1);
	if (index >= XLB_RS_HASH_TAB_BIT) {
		return XDP_DROP;
	}
	rs = srv_data->rs + index;

	if (rs->flags & XLB_RS_F_IF) {
		ifindex = rs->ifindex;
	} else {
		ifindex = ctx->ingress_ifindex;
	}

	if (rs->flags & XLB_RS_F_MAC) {
		encap_l2_pkt(eh, rs->mac);
		// bpf_printk("redirect");
		return bpf_redirect(ifindex, 0);
	}

	fib.ipv4_dst = rs->ip;
	fib.ipv4_src = iph->saddr;
	fib.tos = iph->tos;
	fib.l4_protocol = iph->protocol;
	fib.tot_len	= __be16_to_cpu(iph->tot_len);
	fib.family = AF_INET;
	fib.ifindex = ctx->ingress_ifindex;

	// bpf_printk("look fib");
	ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);
	switch(ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			break;
		case BPF_FIB_LKUP_RET_NO_NEIGH:
		case BPF_FIB_LKUP_RET_UNREACHABLE:
			iph->version = IPPROTO_XLB;
			return XDP_PASS;
		default:
			return XDP_DROP;
	}

	encap_l2_pkt(eh, fib.dmac);

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
