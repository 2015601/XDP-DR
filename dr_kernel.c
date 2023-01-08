#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <inttypes.h>
#include <sys/socket.h>
#include "bpf_helper.h"
#include "bpf_ether.h"
#include "bpf_ip.h"
#include "bpf_tcp.h"

struct dr_service {
	__u32 ip;
	__u16 port;
	__u8 protocol;
};

struct bpf_elf_map SEC("maps") vs_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.size_key = sizeof(struct dr_service),
	.size_value = sizeof(__u32),
	.max_elem = 100,
	.pinning = 2 // global pin
};

/*
 * load object:
 * ip link set enp0s8 xdp object dr_kernel.o section xdp
 * unload:
 * ip link set enp0s8 xdp off
 */

#if __LITTLE_ENDIAN__
#define TC_L2_MARK 0xFEFFU
#else
#define TC_L2_MARK 0xFFFEU
#endif

#define IPVERSION_DR 11

struct dr_l2_meta_data {
	uint16_t mark;
} __attribute__((aligned(2)));

SEC("xdp")
int xdp_dr_input_hook(struct xdp_md *ctx)
{
	// struct dr_l2_meta_data *meta;
	struct ethhdr *eh;
	struct bpf_iphdr *iph;
	struct bpf_tcphdr *th;
	struct bpf_fib_lookup fib = {};
	void *data, *data_end;
	__u32 *rserver;
	struct dr_service hit_srv = {};
	int ret;

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
	hit_srv.protocol = IPPROTO_TCP;
	hit_srv.port = th->dest;

	// service hit
	rserver = bpf_map_lookup_elem(&vs_map, &hit_srv);
	if (!rserver) {
		return XDP_PASS;
	}

	fib.ipv4_dst = *rserver;
	fib.ipv4_src = iph->saddr;
	fib.tos = iph->tos;
	fib.l4_protocol = IPPROTO_TCP;
	fib.tot_len	= __be16_to_cpu(iph->tot_len);
	fib.family = AF_INET;
	fib.ifindex = ctx->ingress_ifindex;
	ret = bpf_fib_lookup(ctx, &fib, sizeof(fib), BPF_FIB_LOOKUP_DIRECT);

	switch(ret) {
		case BPF_FIB_LKUP_RET_SUCCESS:
			break;
		case BPF_FIB_LKUP_RET_NO_NEIGH:
		case BPF_FIB_LKUP_RET_UNREACHABLE:
			// ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct dr_l2_meta_data));
			// data = (void*)(long)ctx->data;
			// data_end = (void*)(long)ctx->data_end;
			// if (bpf_xdp_adjust_meta(ctx, -(int)sizeof(struct dr_l2_meta_data))) {
			// 	bpf_printk("err adjust");
			iph->version = IPVERSION_DR;
			// } else {
			// 	meta = (void*)(long)ctx->data_meta;
			// 	if (meta + 1 > data) {
			// 		bpf_printk("err len");
			// 		return XDP_ABORTED;
			// 	}
			// 	meta->mark = TC_L2_MARK;
			// }
			return XDP_PASS;
		default:
			return XDP_DROP;
	}

	// bpf_printk("mac %x:%x:%x", fib.dmac[0], fib.dmac[1], fib.dmac[2]);
	// bpf_printk(":%x:%x:%x\n", fib.dmac[3], fib.dmac[4], fib.dmac[5]);
	// bpf_printk("index: %u", fib.ifindex);
	__builtin_memcpy(eh->h_dest, fib.dmac, sizeof(fib.dmac));

	return XDP_TX;
}

char _license[] SEC("license") = "GPL";
