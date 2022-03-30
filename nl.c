// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#include "bridger.h"

static struct nl_sock *event_sock;
static struct uloop_fd event_fd;
static struct uloop_timeout refresh_linkinfo;

static void
handle_newlink_brvlan(struct device *dev, struct nlattr *info)
{
	struct nlattr *tb[__IFLA_BRIDGE_VLAN_TUNNEL_MAX];
	struct nlattr *cur;
	int start = 0, end = 0;
	int rem;
	int i;

	for (i = 0; i < dev->n_vlans; i++)
		dev->vlan[i].tunnel = 0;

	nla_for_each_nested(cur, info, rem) {
		uint16_t flags;
		int cur_id;

		if (nla_type(cur) != IFLA_BRIDGE_VLAN_TUNNEL_INFO)
			continue;

		nla_parse_nested(tb, IFLA_BRIDGE_VLAN_TUNNEL_MAX, cur, NULL);
		if (!tb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS] ||
		    !tb[IFLA_BRIDGE_VLAN_TUNNEL_VID])
			continue;

		flags = nla_get_u16(tb[IFLA_BRIDGE_VLAN_TUNNEL_FLAGS]);
		cur_id = nla_get_u16(tb[IFLA_BRIDGE_VLAN_TUNNEL_VID]);

		switch (flags) {
		case BRIDGE_VLAN_INFO_RANGE_BEGIN:
			start = cur_id;
			continue;
		case 0:
			start = cur_id;
			fallthrough;
		case BRIDGE_VLAN_INFO_RANGE_END:
			end = cur_id;
			break;
		default:
			continue;
		}

		for (i = 0; i < dev->n_vlans; i++)
			if (dev->vlan[i].id >= start &&
			    dev->vlan[i].id <= end)
				dev->vlan[i].tunnel = 1;
	}
}

static void
handle_newlink(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct nlattr *tb[__IFLA_MAX];
	struct nlattr *tbi[__IFLA_INFO_MAX] = {};
	struct nlattr *tbd[__IFLA_BR_MAX];
	struct nlattr *cur;
	enum device_type type = DEVICE_TYPE_ETHERNET;
	struct device *dev;

	if (ifi->ifi_family != PF_BRIDGE &&
	    ifi->ifi_family != AF_UNSPEC)
		return;

	nlmsg_parse(nh, sizeof(struct ifinfomsg), tb, __IFLA_MAX - 1, NULL);
	if (!tb[IFLA_IFNAME])
		return;

	if (tb[IFLA_LINKINFO])
		nla_parse_nested(tbi, IFLA_INFO_MAX, tb[IFLA_LINKINFO], NULL);

	if (tbi[IFLA_INFO_KIND])
		type = device_lookup_type(nla_data(tbi[IFLA_INFO_KIND]));

	dev = device_create(ifi->ifi_index, type, nla_data(tb[IFLA_IFNAME]));

	if ((cur = tb[IFLA_ADDRESS]) != NULL &&
	    nla_len(cur) == ETH_ALEN)
		memcpy(dev->addr, nla_data(cur), ETH_ALEN);

	if (ifi->ifi_family == PF_BRIDGE) {
		if (tb[IFLA_MASTER])
			dev->master_ifindex = nla_get_u32(tb[IFLA_MASTER]);
		else
			dev->master_ifindex = 0;

		if (tb[IFLA_AF_SPEC])
			handle_newlink_brvlan(dev, tb[IFLA_AF_SPEC]);
	} else {
		if ((cur = tb[IFLA_PHYS_SWITCH_ID]) != NULL &&
			nla_len(cur) <= sizeof(dev->phys_switch_id)) {
			memcpy(dev->phys_switch_id, nla_data(cur), nla_len(cur));
			dev->phys_switch_id_len = nla_len(cur);
		} else {
			dev->phys_switch_id_len = 0;
		}
	}

	if (tbi[IFLA_INFO_DATA] && type == DEVICE_TYPE_BRIDGE) {
		struct nlattr *cur;

		nla_parse_nested(tbd, IFLA_BR_MAX, tbi[IFLA_INFO_DATA], NULL);

		if ((cur = tbd[IFLA_BR_VLAN_FILTERING]) != NULL)
			dev->br->vlan_enabled = nla_get_u8(cur);
		if ((cur = tbd[IFLA_BR_VLAN_PROTOCOL]) != NULL)
			dev->br->vlan_proto = ntohs(nla_get_u16(cur));
	}

	device_update(dev);
}

static void
handle_dellink(struct nlmsghdr *nh)
{
	struct ifinfomsg *ifi = NLMSG_DATA(nh);
	struct device *dev;

	dev = device_get(ifi->ifi_index);
	if (!dev)
		return;

	switch (ifi->ifi_family) {
	case AF_UNSPEC:
		device_free(dev);
		break;
	case PF_BRIDGE:
		dev->master_ifindex = 0;
		device_update(dev);
		break;
	}
}


static void
handle_neigh(struct nlmsghdr *nh, bool add)
{
	struct ndmsg *r = NLMSG_DATA(nh);
	struct nlattr *tb[__NDA_MAX];
	struct fdb_key key = {};
	struct fdb_entry *f;
	struct device *dev;
	struct bridge *br;
	const uint8_t *addr;

	if (r->ndm_family != AF_BRIDGE ||
	    r->ndm_state == NUD_STALE)
		return;

	nlmsg_parse(nh, sizeof(struct ndmsg), tb, NDA_MAX, NULL);
	if (!tb[NDA_LLADDR] || !tb[NDA_MASTER])
		return;

	addr = nla_data(tb[NDA_LLADDR]);
	if (addr[0] & 1) /* skip multicast */
		return;

	dev = device_get(nla_get_u32(tb[NDA_MASTER]));
	if (!dev)
		return;

	br = dev->br;
	if (!br)
		return;

	memcpy(key.addr, addr, sizeof(key.addr));
	if (tb[NDA_VLAN])
		key.vlan = nla_get_u16(tb[NDA_VLAN]);

	if (!add) {
		f = fdb_get(br, &key);
		if (f)
			fdb_delete(br, f);
		return;
	}

	dev = device_get(r->ndm_ifindex);
	f = fdb_create(br, &key, dev);
	f->ndm_state = r->ndm_state;
}

static void
handle_vlan(struct nlmsghdr *nh, bool add)
{
	struct br_vlan_msg *bvm = NLMSG_DATA(nh);
	struct nlattr *tb[__BRIDGE_VLANDB_MAX];
	struct nlattr *tbe[__BRIDGE_VLANDB_ENTRY_MAX];
	struct bridge_vlan_info *vinfo;
	struct vlan vlan = {};
	struct device *dev;

	if (bvm->family != AF_BRIDGE)
		return;

	dev = device_get(bvm->ifindex);
	if (!dev)
		return;

	nlmsg_parse(nh, sizeof(struct br_vlan_msg), tb, BRIDGE_VLANDB_MAX, NULL);
	if (!tb[BRIDGE_VLANDB_ENTRY])
		return;

	nla_parse_nested(tbe, BRIDGE_VLANDB_ENTRY_MAX, tb[BRIDGE_VLANDB_ENTRY], NULL);
	if (!tbe[BRIDGE_VLANDB_ENTRY_INFO])
		return;

	vinfo = nla_data(tbe[BRIDGE_VLANDB_ENTRY_INFO]);
	vlan.id = vinfo->vid;
	vlan.untagged = !!(vinfo->flags & BRIDGE_VLAN_INFO_UNTAGGED);
	vlan.pvid = !!(vinfo->flags & BRIDGE_VLAN_INFO_PVID);
	device_vlan_add(dev, &vlan);
	uloop_timeout_set(&refresh_linkinfo, 10);
}

static int
bridger_nl_event_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);

	switch (nh->nlmsg_type) {
	case RTM_NEWLINK:
		handle_newlink(nh);
		break;
	case RTM_DELLINK:
		handle_dellink(nh);
		break;
	case RTM_NEWNEIGH:
		handle_neigh(nh, true);
		break;
	case RTM_DELNEIGH:
		handle_neigh(nh, false);
		break;
	case RTM_NEWVLAN:
		handle_vlan(nh, true);
		break;
	case RTM_DELVLAN:
		handle_vlan(nh, false);
		break;
	default:
		break;
	}

	return NL_SKIP;
}

static void
bridger_nl_sock_cb(struct uloop_fd *fd, unsigned int events)
{
	nl_recvmsgs_default(event_sock);
}

static void bridger_refresh_linkinfo_cb(struct uloop_timeout *timeout)
{
	static struct rtgenmsg llmsg = { .rtgen_family = PF_BRIDGE };
	struct nl_msg *msg;

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	nlmsg_append(msg, &llmsg, sizeof(llmsg), NLMSG_ALIGNTO);
	nla_put_u32(msg, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN_COMPRESSED);
	nl_send_auto_complete(event_sock, msg);
}

static int bridger_nl_set_bpf_prog(int ifindex, int fd)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .attach_point = BPF_TC_INGRESS,
			    .ifindex = ifindex);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_ingress,
			    .flags = BPF_TC_F_REPLACE,
			    .handle = 1,
			    .priority = 0xc001);

	bpf_tc_hook_create(&hook);
	if (fd < 0) {
		bpf_tc_detach(&hook, &attach_ingress);
		return 0;
	}

	attach_ingress.prog_fd = fd;
	return bpf_tc_attach(&hook, &attach_ingress);
}

int bridger_nl_device_attach(struct device *dev)
{
	return bridger_nl_set_bpf_prog(device_ifindex(dev), bridger_bpf_prog_fd);
}

void bridger_nl_device_detach(struct device *dev)
{
	bridger_nl_set_bpf_prog(device_ifindex(dev), -1);
}

int bridger_nl_fdb_refresh(struct fdb_entry *f)
{
	struct ndmsg ndmsg = {
		.ndm_family = PF_BRIDGE,
		.ndm_flags = NTF_USE | NTF_MASTER,
		.ndm_state = f->ndm_state,
	};
	struct nl_msg *msg;
	int ret;

	if (!f->dev || f->updated)
		return 0;

	ndmsg.ndm_ifindex = device_ifindex(f->dev);
	msg = nlmsg_alloc_simple(RTM_NEWNEIGH, NLM_F_REQUEST);
	nlmsg_append(msg, &ndmsg, sizeof(ndmsg), NLMSG_ALIGNTO);
	nla_put_u16(msg, NDA_VLAN, f->key.vlan);
	nla_put(msg, NDA_LLADDR, ETH_ALEN, f->key.addr);
	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);

	f->updated = true;

	ret = nl_wait_for_ack(event_sock);
	if (ret)
		D("Failed to refresh fdb entry %s vid=%d @%s ret=%d\n",
		  format_macaddr(f->key.addr), f->key.vlan, f->dev->ifname, ret);

	return ret;
}

int bridger_nl_init(void)
{
	static struct rtgenmsg llmsg = { .rtgen_family = AF_UNSPEC };
	static struct ndmsg ndmsg = { .ndm_family = PF_BRIDGE };
	static struct br_vlan_msg bvmsg = { .family = PF_BRIDGE };
	struct nl_msg *msg;

	refresh_linkinfo.cb = bridger_refresh_linkinfo_cb;

	event_sock = nl_socket_alloc();
	if (!event_sock)
		return -1;

	if (nl_connect(event_sock, NETLINK_ROUTE))
		return -1;

	nl_socket_disable_seq_check(event_sock);
	nl_socket_set_buffer_size(event_sock, 65536, 0);
	nl_socket_modify_cb(event_sock, NL_CB_VALID, NL_CB_CUSTOM,
			    bridger_nl_event_cb, NULL);
	nl_socket_add_membership(event_sock, RTNLGRP_LINK);
	nl_socket_add_membership(event_sock, RTNLGRP_NEIGH);
	nl_socket_add_membership(event_sock, RTNLGRP_BRVLAN);

	event_fd.fd = nl_socket_get_fd(event_sock);
	event_fd.cb = bridger_nl_sock_cb;
	uloop_fd_add(&event_fd, ULOOP_READ);

	nl_send_simple(event_sock, RTM_GETLINK, NLM_F_DUMP | NLM_F_REQUEST, &llmsg, sizeof(llmsg));
	nl_wait_for_ack(event_sock);

	msg = nlmsg_alloc_simple(RTM_GETVLAN, NLM_F_REQUEST | NLM_F_DUMP);
	nlmsg_append(msg, &bvmsg, sizeof(bvmsg), NLMSG_ALIGNTO);
	nla_put_u32(msg, BRIDGE_VLANDB_DUMP_FLAGS, 0);
	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);
	nl_wait_for_ack(event_sock);

	nl_send_simple(event_sock, RTM_GETNEIGH, NLM_F_DUMP | NLM_F_REQUEST, &ndmsg, sizeof(ndmsg));
	nl_wait_for_ack(event_sock);

	return 0;
}
