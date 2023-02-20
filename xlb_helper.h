#ifndef __BPF_HELPER_H
#define __BPF_HELPER_H

#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include <asm/byteorder.h>
#include "libbpf/src/bpf_helpers.h"

#define ATTR(X) __attribute__((X))

#define memcpy(X, Y, Z) __builtin_memcpy(X, Y, Z)
#define memcmp(X, Y, Z) __builtin_memcmp(X, Y, Z)
#define htons(X) __cpu_to_be16(X)
#define ntohs(X) __be_to_cpu16(X)
#define htonl(X) __cpu_to_be32(X)
#define ntohl(X) __be_to_cpu32(X)

#define BPFAPI static ATTR(unused)
#define BPFFILED(X) ((void*)BPF_FUNC_ ## X)

// BPFAPI long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = BPFFILED(trace_printk);
// BPFAPI long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = BPFFILED(fib_lookup);
// BPFAPI long (*bpf_snprintf)(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len) = BPFFILED(snprintf);
// BPFAPI long (*bpf_redirect)(__u32 ifindex, __u64 flags) = BPFFILED(redirect);
// BPFAPI long (*bpf_xdp_adjust_meta)(struct xdp_md *xdp_md, int delta) = BPFFILED(xdp_adjust_meta);
// BPFAPI void* (*bpf_map_lookup_elem)(void *map, const void *key) = BPFFILED(map_lookup_elem);

// #define bpf_printk(fmt, ...)				\
// ({							\
// 	char ____fmt[] = fmt;				\
// 	bpf_trace_printk(____fmt, sizeof(____fmt),	\
// 			 ##__VA_ARGS__);		\
// })


static inline unsigned xlb_hash_32(__u32 src, unsigned bit) {
	/* High bits are more random, so use them. */
	return (src * 0x61C88647UL) >> (32 - bit);
}

#endif
