#include <libbpf.h>
#include <bpf.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <error.h>
#include <errno.h>
#include <string.h>

// 192.168.153.200:80 -> 172.16.153.12:80

static const char *map_name = "/sys/fs/bpf/xdp/globals/vs_map";

static struct dr_service {
	__u32 ip;
	__u16 port;
	__u8 protocol;
} dd;


#define __round_mask(x, y) ((__typeof__(x))((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)


int main(int arc, char **argv)
{
	int map_fd;
	char rsrv[round_up(sizeof(__u32), 8) * get_nprocs()];

	map_fd = bpf_obj_get(map_name);
	if (map_fd < 0) {
		fprintf(stderr, "bpf_obj_get err :%s\n", strerror(errno));
		return -1;
	}
	dd.protocol = IPPROTO_TCP;
	dd.ip = inet_addr("192.168.153.200");
	dd.port = htons(80);
	bpf_map_delete_elem(map_fd, &dd);
	*(__u32*)rsrv = inet_addr("172.16.153.12");
	*(__u32*)(rsrv+round_up(sizeof(__u32), 8)) = inet_addr("172.16.153.12");
	bpf_map_update_elem(map_fd, &dd, rsrv, 0);
	// bpf_map_delete_elem(map_fd, &dd);

	return 0;
}
