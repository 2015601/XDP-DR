
#define IPPROTO_XLB 11

#define XLB_MAX_SERVICES UINT8_MAX

#define XLB_RS_HASH_TAB_BIT 8
#define XLB_RS_HASH_TAB_SIZE (1<<XLB_RS_HASH_TAB_BIT)
#define XLB_RS_HASH_TAB_MASK (XLB_RS_HASH_TAB_SIZE-1)

#define XLB_RS_F_MAC 0x1
#define XLB_RS_F_IF  0x2


struct xlb_service {
	__u32 ip;
	__u16 port;
	__u8 protocol;
};

struct xlb_rs {
	__u32 ip;
	__u32 flags;
	__u8 mac[6];
	__u8 ifindex;
};

struct xlb_service_data {
	__u16 rs_cnt;
	__u32 flags;
	struct xlb_rs rs[XLB_RS_HASH_TAB_SIZE];
};


struct dr_l2_meta_data {
	uint16_t mark;
} __attribute__((aligned(2)));

#define DEFAULT_VS_MAPPIN "/sys/fs/bpf/xdp/globals/vs_map"
#define DEFAULT_RS_MAPPIN "/sys/fs/bpf/xdp/globals/rs_map"

#define XLB_ERR(format, ...) do { \
	fprintf(stderr, "%s:", __FUNCTION__); \
	fprintf(stderr, format, ## __VA_ARGS__); \
	fprintf(stderr, "\n"); \
	exit(-1); \
} while (0)
