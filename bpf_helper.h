#ifndef __BPF_HELPER_H
#define __BPF_HELPER_H

#include <linux/bpf.h>
#include <linux/if_xdp.h>
#include "bpf_utils.h"

#define BPFAPI static ATTR(unused)
#define BPFFILED(X) ((void*)BPF_FUNC_ ## X)

BPFAPI long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = BPFFILED(trace_printk);

BPFAPI long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = BPFFILED(fib_lookup);

BPFAPI long (*bpf_snprintf)(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len) = BPFFILED(snprintf);

BPFAPI long (*bpf_redirect)(__u32 ifindex, __u64 flags) = BPFFILED(redirect);

BPFAPI long (*bpf_redirect_neigh)(__u32 ifindex, struct bpf_redir_neigh *params, int plen, __u64 flags) = BPFFILED(redirect_neigh);

BPFAPI long (*bpf_xdp_adjust_meta)(struct xdp_md *xdp_md, int delta) = BPFFILED(xdp_adjust_meta);

BPFAPI void* (*bpf_map_lookup_elem)(void *map, const void *key) = BPFFILED(map_lookup_elem);

#define SEC(NAME) __attribute__((section(NAME), used))

#define bpf_printk(fmt, ...)				\
({							\
	char ____fmt[] = fmt;				\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

#endif
