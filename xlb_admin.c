#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h> 
#include <unistd.h>
#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <argp.h>
#include <libbpf.h>
#include <bpf.h>
#include "xlb.h"

static uint64_t xlb_opt_bit;

#define set_opt(opt) xlb_opt_bit |= (1<<(opt))
#define test_opt(opt) (xlb_opt_bit & (1<<(opt)))

enum {
	XLB_KEY_ADD_SRV = 'A',
	XLB_KEY_ADD_RS = 'a',
	XLB_KEY_RS = 'r',
	XLB_KEY_MAC = 'm',
	XLB_KEY_IF = 'i',
	XLB_KEY_DEL_VS = 'D',
	XLB_KEY_DEL_RS = 'd',
};

enum {
	XLB_OPT_MAC,
	XLB_OPT_IF,
	XLB_OPT_RS,
};

static struct argp_option options[] = {
	{"add-vs", XLB_KEY_ADD_SRV, "ip:port", 0, "add vs", 0},
	{"del-vs", XLB_KEY_DEL_VS, "ip:port", 0, "del vs", 0},
	{"add-rs", XLB_KEY_ADD_RS, "ip:port", 0, "add rs", 0},
	{"del-rs", XLB_KEY_DEL_RS, "ip:port", 0, "del rs", 0},
	{"interface", XLB_KEY_IF, "ifname", 0, "rs router ifname", 0},
	{"mac", XLB_KEY_MAC, "rs-mac-addr", 0, "rs mac address", 0},
	{"realserver", XLB_KEY_RS, "rs-addr", 0, "rs address", 0},
	{0}
};

enum {
	XLB_CTL_ADD_VS = 1,
	XLB_CTL_DEL_VS,
	XLB_CTL_ADD_RS,
	XLB_CTL_DEL_RS,
};

static struct xlbctl {
	int action;
	struct xlb_service srv;
	struct xlb_rs rs;
} ctl;

static void parse_ipv4_port (const char *str, __u32 *ip, __u16 *port)
{
	char *sport;

	str = strdup(str);

	sport = strstr(str, ":");
	if (!sport) {
		XLB_ERR("parse ip port err");
	}
	sport[0] = '\0';
	sport +=1;

	if (sscanf(sport, "%hu", port) == EOF) {
		XLB_ERR("parse port err");
	}

	*port = htons(*port);

	*ip = inet_addr(str);
	if (*ip == 0) {
		XLB_ERR("parse ip err");
	}
}

static void parse_mac(const char *str, __u8 *mac)
{
	if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", mac, mac+1, mac+2,
		mac+3, mac+4, mac+5) == EOF) {
		XLB_ERR("parse mac err");
	}
}

static int parse_opt(int key, char *arg, struct argp_state *state)
{
	switch(key) {
		case XLB_KEY_ADD_SRV:
			ctl.action = XLB_CTL_ADD_VS;
			parse_ipv4_port(arg, &ctl.srv.ip, &ctl.srv.port);
			ctl.srv.protocol = IPPROTO_TCP;
			break;
		case XLB_KEY_ADD_RS:
			ctl.action = XLB_CTL_ADD_RS;
			ctl.srv.protocol = IPPROTO_TCP;
			parse_ipv4_port(arg, &ctl.srv.ip, &ctl.srv.port);
			break;
		case XLB_KEY_DEL_VS:
			ctl.action = XLB_CTL_DEL_VS;
			parse_ipv4_port(arg, &ctl.srv.ip, &ctl.srv.port);
			ctl.srv.protocol = IPPROTO_TCP;
			break;
		case XLB_KEY_DEL_RS:
			ctl.action = XLB_CTL_DEL_RS;
			ctl.srv.protocol = IPPROTO_TCP;
			parse_ipv4_port(arg, &ctl.srv.ip, &ctl.srv.port);
			break;
		case XLB_KEY_RS:
			set_opt(XLB_OPT_RS);
			ctl.rs.ip = inet_addr(arg);
			if (ctl.rs.ip == 0) {
				XLB_ERR("parse ip err");
			}
			break;
		case XLB_KEY_MAC:
			set_opt(XLB_OPT_MAC);
			parse_mac(arg, ctl.rs.mac);
			ctl.rs.flags |= XLB_RS_F_MAC;
			break;
		case XLB_KEY_IF:
			set_opt(XLB_OPT_IF);
			ctl.rs.ifindex = if_nametoindex(arg);
			ctl.rs.flags |= XLB_RS_F_IF;
			break;
	}
	return 0;
}

static void xlb_add_vs(void)
{
	struct xlb_service_data data;
	int vs_map;

	memset(&data, 0, sizeof(data));

	vs_map = bpf_obj_get(DEFAULT_VS_MAPPIN);
	if (vs_map < 0) {
		XLB_ERR("%s", strerror(errno));
	}

	if (bpf_map_update_elem(vs_map, &ctl.srv, &data, BPF_ANY)) {
		XLB_ERR("%s", strerror(errno));
	}
}

static void xlb_add_rs(void)
{
	struct xlb_service_data data;
	int vs_map;

	if (!test_opt(XLB_OPT_RS)) {
		XLB_ERR("need rs");
	}

	vs_map =bpf_obj_get(DEFAULT_VS_MAPPIN);
	if (vs_map < 0) {
		XLB_ERR("%s", strerror(errno));
	}

	if (bpf_map_lookup_elem(vs_map, &ctl.srv, &data)) {
		XLB_ERR("vs not exist");
	}

	if (data.rs_cnt == XLB_RS_HASH_TAB_SIZE) {
		XLB_ERR("rs full");
	}

	for (int i = 0; i < XLB_RS_HASH_TAB_SIZE; ++i) {
		if (data.rs[i].ip == ctl.rs.ip) {
			XLB_ERR("rs aleady exist");
		}
	}

	data.rs[data.rs_cnt] = ctl.rs;
	data.rs_cnt++;

	if (bpf_map_update_elem(vs_map, &ctl.srv, &data, BPF_ANY)) {
		XLB_ERR("rs add err");
	}
}

static void xlb_del_rs(void)
{
	struct xlb_service_data data;
	int vs_map;

	if (!test_opt(XLB_OPT_RS)) {
		XLB_ERR("need rs");
	}

	vs_map =bpf_obj_get(DEFAULT_VS_MAPPIN);
	if (vs_map < 0) {
		XLB_ERR("%s", strerror(errno));
	}

	if (bpf_map_lookup_elem(vs_map, &ctl.srv, &data)) {
		XLB_ERR("vs not exist");
	}

	for (int i = 0; i < XLB_RS_HASH_TAB_SIZE; ++i) {
		if (ctl.rs.ip == data.rs[i].ip) {
			if (i == data.rs_cnt) {
				data.rs_cnt--;
				break;
			}
			memmove(data.rs+i, data.rs+i+1, sizeof(struct xlb_rs) * data.rs_cnt - i);
			data.rs_cnt--;
			break;
		}
	}
	if (bpf_map_update_elem(vs_map, &ctl.srv, &data, BPF_ANY)) {
		XLB_ERR("rs del err");
	}
}

static void xlb_del_vs(void)
{
	int vs_map;

	vs_map = bpf_obj_get(DEFAULT_VS_MAPPIN);
	if (vs_map < 0) {
		XLB_ERR("%s", strerror(errno));
	}
	if(bpf_map_delete_elem(vs_map, &ctl.srv)) {
		XLB_ERR("%s", strerror(errno));
	}
}

int main(int argc, char **argv)
{
	struct argp argp = {options, parse_opt};

	if (argp_parse(&argp, argc, argv, 0, 0, 0)) {
		argp_help(&argp, stderr, 0, "XLB LOAD");
		return -1;
	}

	switch(ctl.action) {
		case XLB_CTL_ADD_VS:
			xlb_add_vs();
			break;
		case XLB_CTL_ADD_RS:
			xlb_add_rs();
			break;
		case XLB_CTL_DEL_RS:
			xlb_del_rs();
			break;
		case XLB_CTL_DEL_VS:
			xlb_del_vs();
			break;
		default:
			argp_help(&argp, stderr, 0, "xlb admin");
	}

	return 0;
}
