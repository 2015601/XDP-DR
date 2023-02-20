#include <bpf.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h> 
#include <unistd.h>
#include <error.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <argp.h>
#include <libbpf.h>
#include "xlb.h"

#define XLB_CALL(func, ...) do { \
	if (func(__VA_ARGS__)) { \
		XLB_ERR(#func"err:%s", strerror(errno)); \
		return -1; \
	} \
} while(0)

static struct xlb_param {
	const char *object_file;
	const char *vs_map_path;
	const char *vs_map_meta_path;
	int action;
	int ifindex;
#define XLB_LOAD 1
#define XLB_UNLOAD 2
} params;

enum {
	XLB_KEY_LOAD = 'l',
	XLB_KEY_UNLOAD = 'u',
	XLB_KEY_IFNAME = 'i'
};

static struct argp_option options[] = {
	{"load", XLB_KEY_LOAD, "object", 0, "load eBPF object", 0},
	{"unload", XLB_KEY_UNLOAD, 0, 0, "unload eBPF object", 0},
	{"interface", XLB_KEY_IFNAME, "ifname", 0, "xdp load ifname, default eth0"},
	{0}
};

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	switch(key) {
		case XLB_KEY_LOAD:
			params.action = XLB_LOAD;
			params.object_file = strdup(arg);
			break;
		case XLB_KEY_UNLOAD:
			params.action = XLB_UNLOAD;
			break;
		case XLB_KEY_IFNAME:
			params.ifindex = if_nametoindex(arg);
			break;
	}
	return 0;
}

static int check_params(void) {
	if (params.action != XLB_LOAD && params.action != XLB_UNLOAD) {
		return 1;
	}
	if (params.action == XLB_LOAD && !params.object_file) {
		return 1;
	}

	return 0;
}


static int xlb_load_object(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	int xdp_flags = 0;
	int map_fd = 0;

	obj = bpf_object__open_file(params.object_file, NULL);
	if (libbpf_get_error(obj)) {
		XLB_ERR("bpf_object__open_file err");
		return -1;
	}

	bpf_object__for_each_map(map, obj) {
		if (strcmp(bpf_map__name(map), "vs_map") == 0) {
			unlink(DEFAULT_VS_MAPPIN);
			// map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(__u32), sizeof(struct xlb_rs), XLB_RS_HASH_TAB_SIZE, 0);
			// if (map_fd < 0) {
			// 	XLB_ERR("bpf_create_map err, %s", strerror(errno));
			// 	return -1;
			// }
			// // if (bpf_map__set_inner_map_fd(map, map_fd)) {
			// // 	XLB_ERR("bpf_map__set_inner_map_fd err, %s", strerror(errno));
			// // 	close(map_fd);
			// // 	return -1;
			// // }
			bpf_map__set_pin_path(map, DEFAULT_VS_MAPPIN);
		}
		// else if (strcmp(bpf_map__name(map), "vs_meta") == 0) {
		// 	bpf_map__set_pin_path(map, DEFAULT_VS_META_MAPPIN);
		// }
	}
	prog = bpf_object__find_program_by_name(obj, "xdp_dr_input_hook");
	if (!prog) {
		XLB_ERR("bpf_object__find_program_by_name err: %s", strerror(errno));
		return -1;
	}
	// bpf_program__set_ifindex(prog, params.ifindex);
	// bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
	// bpf_program__set_xdp()

	XLB_CALL(bpf_object__load, obj);

	if (map_fd) {
		close(map_fd);
	}

	bpf_xdp_attach(params.ifindex, bpf_program__fd(prog), xdp_flags, NULL);

	bpf_object__close(obj);

	return 0;
}

static int xlb_unload_object(void)
{
	return bpf_xdp_detach(params.ifindex, 0, NULL);
	// return bpf_set_link_xdp_fd(params.ifindex, -1, 0);
}


int main(int argc, char **argv)
{
	struct argp argp = {options, parse_opt};

	if (argp_parse(&argp, argc, argv, 0, 0, 0) || check_params()) {
		argp_help(&argp, stderr, 0, "XLB LOAD");
		return -1;
	}

	if (params.action == XLB_LOAD) {
		xlb_load_object();
	} else {
		xlb_unload_object();
	}

	return 0;
}
