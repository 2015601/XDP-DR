#ifndef __BPF_IP_H
#define __BPF_IP_H

// copy from kernel linux/ip.h

#include <linux/types.h>
#include <endian.h>
#include "bpf_utils.h"

struct bpf_iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
	__u8	ihl:4,
		version:4;
#else
	__u8	version:4,
  		ihl:4;
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	/*The options start here. */
} ATTR(packed);

#endif
