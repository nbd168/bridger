// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>
#include <linux/pkt_cls.h>
#include <linux/tc_act/tc_vlan.h>
#include <linux/tc_act/tc_mirred.h>
#include "bridger.h"

static struct nl_sock *event_sock;
static struct uloop_fd event_fd;
static struct uloop_timeout refresh_linkinfo;
static bool ignore_errors;

static int offload_handle_cmp(const void *k1, const void *k2, void *ptr)
{
	uint32_t v1 = (uint32_t)(uintptr_t)k1;
	uint32_t v2 = (uint32_t)(uintptr_t)k2;

	return memcmp(&v1, &v2, sizeof(v1));
}

static AVL_TREE(offload_flows, offload_handle_cmp, false, NULL);

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
	struct nlattr *tbp[__IFLA_BRPORT_MAX] = {};
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

	if (tb[IFLA_PROTINFO])
		nla_parse_nested(tbp, IFLA_BRPORT_MAX, tb[IFLA_PROTINFO], NULL);

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

	if (tbp[IFLA_BRPORT_MODE])
		dev->hairpin_mode = nla_get_u8(tb[IFLA_BRPORT_MODE]);

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

static void
handle_filter(struct nlmsghdr *nh)
{
	struct tcmsg *t = NLMSG_DATA(nh);
	struct nlattr *tb[__TCA_MAX];
	struct nlattr *tbf[__TCA_FLOWER_MAX];
	struct nlattr *tba[__TCA_ACT_MAX];
	struct nlattr *tbm[__TCA_MIRRED_MAX];
	struct nlattr *cur;
	struct bridger_flow *flow;
	const struct tcf_t *tm;
	const void *key;
	int prio = t->tcm_info >> 16;
	int hz = sysconf(_SC_CLK_TCK);
	int idle;
	int rem;

	if (t->tcm_parent != TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS) ||
	    prio < BRIDGER_PRIO_OFFLOAD_START ||
	    prio > BRIDGER_PRIO_OFFLOAD_END || !t->tcm_handle)
		return;

	nlmsg_parse(nh, sizeof(struct tcmsg), tb, TCA_MAX, NULL);
	if (!tb[TCA_KIND] || !tb[TCA_OPTIONS])
		return;

	if (strcmp(nla_data(tb[TCA_KIND]), "flower") != 0)
		return;

	key = (const void *)(uintptr_t)t->tcm_handle;
	flow = avl_find_element(&offload_flows, key, flow, offload_node);
	if (!flow)
		return;

	nla_parse_nested(tbf, TCA_FLOWER_MAX, tb[TCA_OPTIONS], NULL);
	if (!tbf[TCA_FLOWER_ACT])
		return;

	nla_for_each_nested(cur, tbf[TCA_FLOWER_ACT], rem) {
		nla_parse_nested(tba, TCA_ACT_MAX, cur, NULL);
		if (!tba[TCA_ACT_KIND] || !tba[TCA_ACT_STATS] ||
		    !tba[TCA_ACT_OPTIONS])
			continue;

		if (strcmp(nla_data(tba[TCA_ACT_KIND]), "mirred") != 0)
			continue;

		goto check_action;
	}
	return;

check_action:
	nla_parse_nested(tbm, TCA_MIRRED_MAX, tba[TCA_ACT_OPTIONS], NULL);
	if (!tbm[TCA_MIRRED_TM])
		return;

	tm = (const struct tcf_t *)nla_data(tbm[TCA_MIRRED_TM]);
	idle = tm->lastuse / hz;
	if (idle < flow->idle)
		flow->idle = idle;
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
	case RTM_NEWTFILTER:
		handle_filter(nh);
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
			    .priority = BRIDGER_PRIO_BPF);

	bpf_tc_hook_create(&hook);
	attach_ingress.prog_fd = fd;

	return bpf_tc_attach(&hook, &attach_ingress);
}

static void
bridger_nl_del_filter(struct device *dev, unsigned int prio)
{
	struct tcmsg tcmsg = {
		.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = device_ifindex(dev),
		.tcm_info = TC_H_MAKE(prio << 16, 0),
	};
	struct nl_msg *msg;

	msg = nlmsg_alloc_simple(RTM_DELTFILTER, NLM_F_REQUEST);
	nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);
	ignore_errors = true;
	nl_wait_for_ack(event_sock);
	ignore_errors = false;
}

static void
bridger_nl_device_clear_offload(struct device *dev)
{
	int i;

	for (i = BRIDGER_PRIO_OFFLOAD_START; i <= BRIDGER_PRIO_OFFLOAD_END; i++)
		bridger_nl_del_filter(dev, i);
}

static void
bridger_nl_device_cleanup(struct device *dev)
{
	while ((dev = dev->offload_dev) != NULL) {
		if (!dev->cleanup)
			continue;

		bridger_nl_device_clear_offload(dev);
		dev->cleanup = false;
	}
}

static void
bridger_nl_device_prepare(struct device *dev)
{
	struct tcmsg tcmsg = {
		.tcm_parent = TC_H_CLSACT,
		.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0),
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = device_ifindex(dev),
	};
	struct nl_msg *msg;

	if (dev->has_clsact)
		return;

	dev->has_clsact = true;
	msg = nlmsg_alloc_simple(RTM_NEWQDISC, NLM_F_CREATE | NLM_F_EXCL);
	nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
	nla_put_string(msg, TCA_KIND, "clsact");
	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);
	ignore_errors = true;
	nl_wait_for_ack(event_sock);
	ignore_errors = false;
}

static uint16_t
bridger_nl_offload_prio(uint16_t vlan)
{
	switch (vlan & BRIDGER_VLAN_FLAGS) {
	case BRIDGER_VLAN_PRESENT | BRIDGER_VLAN_TYPE_AD:
		return BRIDGER_PRIO_OFFLOAD_8021AD;
	case BRIDGER_VLAN_PRESENT:
		return BRIDGER_PRIO_OFFLOAD_8021Q;
	default:
		return BRIDGER_PRIO_OFFLOAD_UNTAG;
	}
}

static uint16_t
bridger_vlan_proto(uint16_t vlan)
{
	switch (vlan & BRIDGER_VLAN_FLAGS) {
	case BRIDGER_VLAN_PRESENT | BRIDGER_VLAN_TYPE_AD:
		return cpu_to_be16(ETH_P_8021AD);
	case BRIDGER_VLAN_PRESENT:
		return cpu_to_be16(ETH_P_8021Q);
	default:
		return cpu_to_be16(ETH_P_ALL);
	}
}

static uint32_t bridger_nl_flow_handle(struct bridger_flow *flow)
{
	return (uint32_t)((uintptr_t)flow >> 3);
}

static struct nl_msg *
bridger_nl_flow_offload_msg(struct bridger_flow *flow, int ifindex, int cmd)
{
	struct tcmsg tcmsg = {
		.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = ifindex,
		.tcm_handle = bridger_nl_flow_handle(flow),
	};
	unsigned int flags = NLM_F_REQUEST;
	unsigned int prio, proto;
	struct nl_msg *msg;

	prio = bridger_nl_offload_prio(flow->key.vlan);
	proto = bridger_vlan_proto(flow->key.vlan);
	tcmsg.tcm_info = TC_H_MAKE(prio << 16, proto);

	if (cmd == RTM_NEWTFILTER)
		flags |= NLM_F_CREATE | NLM_F_EXCL;

	msg = nlmsg_alloc_simple(cmd, flags);
	nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
	nla_put_string(msg, TCA_KIND, "flower");

	return msg;
}

static int
__bridger_nl_flow_offload_add(struct bridger_flow *flow, struct device *dev)
{
	uint8_t mask[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	static const struct nla_bitfield32 hw_stats = {
		.value = TCA_ACT_HW_STATS_IMMEDIATE,
		.selector = TCA_ACT_HW_STATS_IMMEDIATE,
	};
	struct tc_mirred m = {
		.ifindex = device_ifindex(flow->fdb_out->dev),
		.eaction = TCA_EGRESS_REDIR,
	};
	struct nlattr *opts, *acts, *act, *aopt;
	struct nl_msg *msg;
	int act_index = 0;
	int ifindex;
	int proto;

	bridger_nl_device_prepare(dev);

	ifindex = device_ifindex(dev);
	proto = bridger_vlan_proto(flow->key.vlan);
	msg = bridger_nl_flow_offload_msg(flow, ifindex, RTM_NEWTFILTER);

	opts = nla_nest_start(msg, TCA_OPTIONS);

	nla_put_u32(msg, TCA_FLOWER_FLAGS, TCA_CLS_FLAGS_SKIP_SW);
	nla_put_string(msg, TCA_FLOWER_INDEV, dev->ifname);
	if (flow->key.vlan & BRIDGER_VLAN_PRESENT)
		nla_put_u16(msg, TCA_FLOWER_KEY_VLAN_ID, flow->key.vlan & BRIDGER_VLAN_ID);
	nla_put(msg, TCA_FLOWER_KEY_ETH_SRC, ETH_ALEN, flow->key.src);
	nla_put(msg, TCA_FLOWER_KEY_ETH_SRC_MASK, ETH_ALEN, mask);
	nla_put(msg, TCA_FLOWER_KEY_ETH_DST, ETH_ALEN, flow->key.dest);
	nla_put(msg, TCA_FLOWER_KEY_ETH_DST_MASK, ETH_ALEN, mask);
	if (flow->key.vlan & BRIDGER_VLAN_PRESENT)
		nla_put_u16(msg, TCA_FLOWER_KEY_ETH_TYPE, proto);

	acts = nla_nest_start(msg, TCA_FLOWER_ACT);

	if (flow->key.vlan != flow->offload.vlan) {
		if (flow->key.vlan & BRIDGER_VLAN_PRESENT) {
			static const struct tc_vlan tcv = {
				.action = TC_ACT_PIPE,
				.v_action = TCA_VLAN_ACT_POP,
			};
			act = nla_nest_start(msg, ++act_index);
			nla_put_string(msg, TCA_ACT_KIND, "vlan");

			aopt = nla_nest_start(msg, TCA_ACT_OPTIONS);
			nla_put(msg, TCA_VLAN_PARMS, sizeof(tcv), &tcv);
			nla_nest_end(msg, aopt);
			nla_nest_end(msg, act);
		}

		if (flow->offload.vlan & BRIDGER_VLAN_PRESENT) {
			static const struct tc_vlan tcv = {
				.action = TC_ACT_PIPE,
				.v_action = TCA_VLAN_ACT_PUSH,
			};
			act = nla_nest_start(msg, ++act_index);
			nla_put_string(msg, TCA_ACT_KIND, "vlan");

			aopt = nla_nest_start(msg, TCA_ACT_OPTIONS);
			nla_put(msg, TCA_VLAN_PARMS, sizeof(tcv), &tcv);

			nla_put_u16(msg, TCA_VLAN_PUSH_VLAN_ID,
				   flow->offload.vlan & BRIDGER_VLAN_ID);
			nla_put_u16(msg, TCA_VLAN_PUSH_VLAN_PROTOCOL,
				    bridger_vlan_proto(flow->offload.vlan));

			nla_nest_end(msg, aopt);
			nla_nest_end(msg, act);
		}
	}

	act = nla_nest_start(msg, ++act_index);
	nla_put_string(msg, TCA_ACT_KIND, "mirred");

	nla_put(msg, TCA_ACT_HW_STATS, sizeof(hw_stats), &hw_stats);
	aopt = nla_nest_start(msg, TCA_ACT_OPTIONS);
	nla_put(msg, TCA_MIRRED_PARMS, sizeof(m), &m);
	nla_nest_end(msg, aopt);
	nla_nest_end(msg, act);

	nla_nest_end(msg, acts);

	nla_nest_end(msg, opts);

	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);

	return nl_wait_for_ack(event_sock);
}

int bridger_nl_flow_offload_add(struct bridger_flow *flow)
{
	struct device *dev;
	int ifindex;
	int ret = -1;

	if (flow->offload_ifindex)
		bridger_nl_flow_offload_del(flow);

	for (dev = flow->fdb_in->dev; dev; dev = dev->offload_dev) {
		ifindex = device_ifindex(dev);
		ret = __bridger_nl_flow_offload_add(flow, dev);
		D("Add flow on %s: %s\n", dev->ifname, ret ? strerror(-ret) : "Success");
		if (!ret)
			break;
	}

	if (ret)
		return ret;

	flow->offload_ifindex = ifindex;
	flow->offload_node.key = (void *)(uintptr_t)bridger_nl_flow_handle(flow);
	avl_insert(&offload_flows, &flow->offload_node);

	return 0;
}

void bridger_nl_flow_offload_update(struct bridger_flow *flow)
{
	struct tcmsg tcmsg = {
		.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = flow->offload_ifindex,
	};
	struct nl_msg *msg;
	struct device *dev;

	if (!flow->offload_ifindex)
		return;

	dev = device_get(flow->offload_ifindex);
	if (!dev)
		return;

	if (!dev->offload_update)
		return;

	dev->offload_update = false;
	msg = nlmsg_alloc_simple(RTM_GETTFILTER, NLM_F_REQUEST | NLM_F_DUMP);
	nlmsg_append(msg, &tcmsg, sizeof(tcmsg), NLMSG_ALIGNTO);
	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);
	nl_wait_for_ack(event_sock);
}

void bridger_nl_flow_offload_del(struct bridger_flow *flow)
{
	struct nl_msg *msg;
	int ifindex;

	ifindex = flow->offload_ifindex;
	if (!ifindex)
		return;

	avl_delete(&offload_flows, &flow->offload_node);
	flow->offload_ifindex = 0;
	msg = bridger_nl_flow_offload_msg(flow, ifindex, RTM_DELTFILTER);
	nl_send_auto_complete(event_sock, msg);
	nlmsg_free(msg);

	ignore_errors = true;
	nl_wait_for_ack(event_sock);
	ignore_errors = false;
}

int bridger_nl_device_attach(struct device *dev)
{
	int ret;

	bridger_nl_device_detach(dev);
	bridger_nl_device_cleanup(dev);

	ret = bridger_nl_set_bpf_prog(device_ifindex(dev), bridger_bpf_prog_fd);
	if (ret)
		return ret;

	return 0;
}

void bridger_nl_device_detach(struct device *dev)
{
	dev->cleanup = false;
	bridger_nl_del_filter(dev, BRIDGER_PRIO_BPF);
	bridger_nl_device_clear_offload(dev);
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

static int
bridge_nl_error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err,
		   void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) err - 1;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	struct nlattr *attrs;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);
	int len = nlh->nlmsg_len;
	const char *errstr = "(unknown)";

	if (ignore_errors)
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	attrs = (void *) ((unsigned char *) nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG])
		errstr = nla_data(tb[NLMSGERR_ATTR_MSG]);

	D("Netlink error(%d): %s\n", err->error, errstr);

	return NL_STOP;
}

int bridger_nl_init(void)
{
	static struct rtgenmsg llmsg = { .rtgen_family = AF_UNSPEC };
	static struct ndmsg ndmsg = { .ndm_family = PF_BRIDGE };
	static struct br_vlan_msg bvmsg = { .family = PF_BRIDGE };
	struct nl_msg *msg;
	int opt;

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
	nl_cb_err(nl_socket_get_cb(event_sock), NL_CB_CUSTOM,
		  bridge_nl_error_cb, NULL);
	nl_socket_add_membership(event_sock, RTNLGRP_LINK);
	nl_socket_add_membership(event_sock, RTNLGRP_NEIGH);
	nl_socket_add_membership(event_sock, RTNLGRP_BRVLAN);

	event_fd.fd = nl_socket_get_fd(event_sock);
	event_fd.cb = bridger_nl_sock_cb;
	uloop_fd_add(&event_fd, ULOOP_READ);

	opt = 1;
	setsockopt(event_fd.fd, SOL_NETLINK,
		   NETLINK_EXT_ACK, &opt, sizeof(opt));

	opt = 1;
	setsockopt(event_fd.fd, SOL_NETLINK,
		   NETLINK_CAP_ACK, &opt, sizeof(opt));

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
