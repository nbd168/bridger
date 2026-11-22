// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#define KBUILD_MODNAME "bridger-mat"
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "bridger-mat-bpf.h"

#define MAT_PULL_LEN		128
#define MAT_EXTHDR_MAX		4

#define IPPROTO_HOPOPTS		0
#define IPPROTO_ROUTING		43
#define IPPROTO_FRAGMENT	44
#define IPPROTO_DSTOPTS		60

#define ICMPV6_MLD_REPORT	131
#define ICMPV6_ND_FIRST		133
#define ICMPV6_ND_LAST		137
#define ICMPV6_IND_SOLICIT	141
#define ICMPV6_IND_ADVERT	142

#define IGMP_V1_REPORT		0x12
#define IGMP_V2_REPORT		0x16

#define PORT_DHCP_SERVER	67
#define PORT_DHCP_CLIENT	68
#define PORT_DHCP6_SERVER	547

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__type(key, __u32);
	__type(value, struct mat_dev);
	__uint(max_entries, MAT_MAX_DEVS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} mat_dev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__type(key, struct mat_bind_key);
	__type(value, struct mat_bind);
	__uint(max_entries, MAT_MAX_BINDINGS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} mat_bind SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(pinning, 1);
	__type(key, struct mat_bind_key);
	__type(value, __u64);
	__uint(max_entries, MAT_EVENT_SLOTS);
} mat_event_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(pinning, 1);
	__uint(max_entries, 64 * 1024);
} mat_events SEC(".maps");

enum mat_class {
	MAT_CLASS_DATA,
	MAT_CLASS_CONTROL,
	MAT_CLASS_PROBE,
	MAT_CLASS_REPORT,
	MAT_CLASS_SERVER,
	MAT_CLASS_OTHER,
	MAT_CLASS_DROP,
};

struct mat_pkt {
	__u8 dst[ETH_ALEN];
	__u8 src[ETH_ALEN];
	__be16 proto;
	__u8 class;
	__u8 dst_group;
	__u8 src_unspec;
	struct mat_bind_key src_key;
	struct mat_bind_key dst_key;
};

#define memcpy __builtin_memcpy
#define memset __builtin_memset

static __always_inline void *
skb_ptr(struct __sk_buff *skb, int offset, int len)
{
	void *ptr = (void *)(long)skb->data + offset;
	void *end = (void *)(long)skb->data_end;

	if (ptr + len > end)
		return NULL;

	return ptr;
}

static __always_inline bool
mac_equal(const __u8 *a, const __u8 *b)
{
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
	       a[3] == b[3] && a[4] == b[4] && a[5] == b[5];
}

static __always_inline void
mat_key_set_ipv4(struct mat_bind_key *key, __be32 addr)
{
	key->addr[10] = 0xff;
	key->addr[11] = 0xff;
	memcpy(&key->addr[12], &addr, sizeof(addr));
}

static __always_inline bool
mat_addr_v4_mapped(const struct in6_addr *addr)
{
	return !addr->s6_addr32[0] && !addr->s6_addr32[1] &&
	       addr->s6_addr32[2] == bpf_htonl(0xffff);
}

static __always_inline void
mat_parse_udp(struct __sk_buff *skb, int offset, struct mat_pkt *p, bool ipv6)
{
	__be16 ports[2];
	__u16 sport, dport;

	if (bpf_skb_load_bytes(skb, offset, ports, sizeof(ports)))
		return;

	sport = bpf_ntohs(ports[0]);
	dport = bpf_ntohs(ports[1]);

	if (ipv6) {
		if (sport == PORT_DHCP6_SERVER)
			p->class = MAT_CLASS_SERVER;
		return;
	}

	if (sport == PORT_DHCP_SERVER && dport == PORT_DHCP_SERVER)
		p->class = MAT_CLASS_SERVER;
	else if ((sport == PORT_DHCP_CLIENT && dport == PORT_DHCP_SERVER) ||
		 (sport == PORT_DHCP_SERVER && dport == PORT_DHCP_CLIENT))
		p->class = MAT_CLASS_CONTROL;
}

static __always_inline int
mat_parse_ipv4(struct __sk_buff *skb, struct mat_pkt *p)
{
	struct iphdr *iph;
	int offset;
	__u8 proto;
	__u8 type;

	iph = skb_ptr(skb, sizeof(struct ethhdr), sizeof(*iph));
	if (!iph || iph->ihl < 5)
		return -1;

	mat_key_set_ipv4(&p->src_key, iph->saddr);
	mat_key_set_ipv4(&p->dst_key, iph->daddr);
	p->src_unspec = !iph->saddr;
	p->dst_group = (iph->daddr & bpf_htonl(0xf0000000)) == bpf_htonl(0xe0000000) ||
		       iph->daddr == bpf_htonl(0xffffffff);

	if (iph->frag_off & bpf_htons(0x3fff))
		return 0;

	proto = iph->protocol;
	offset = sizeof(struct ethhdr) + iph->ihl * 4;

	if (proto == IPPROTO_UDP) {
		mat_parse_udp(skb, offset, p, false);
		return 0;
	}

	if (proto != IPPROTO_IGMP)
		return 0;

	if (bpf_skb_load_bytes(skb, offset, &type, sizeof(type)))
		return 0;

	if (type == IGMP_V1_REPORT || type == IGMP_V2_REPORT)
		p->class = MAT_CLASS_REPORT;

	return 0;
}

static __always_inline int
mat_parse_ipv6(struct __sk_buff *skb, struct mat_pkt *p)
{
	struct ipv6hdr *ip6h;
	int offset = sizeof(struct ethhdr) + sizeof(*ip6h);
	bool fragment = false;
	__u8 nexthdr;
	__u8 type;
	int i;

	ip6h = skb_ptr(skb, sizeof(struct ethhdr), sizeof(*ip6h));
	if (!ip6h)
		return -1;

	/* an IPv4-mapped address has the key of an IPv4 binding */
	if (mat_addr_v4_mapped(&ip6h->saddr) || mat_addr_v4_mapped(&ip6h->daddr))
		return -1;

	memcpy(p->src_key.addr, &ip6h->saddr, sizeof(p->src_key.addr));
	memcpy(p->dst_key.addr, &ip6h->daddr, sizeof(p->dst_key.addr));
	p->dst_group = ip6h->daddr.s6_addr[0] == 0xff;
	p->src_unspec = !(ip6h->saddr.s6_addr32[0] | ip6h->saddr.s6_addr32[1] |
			  ip6h->saddr.s6_addr32[2] | ip6h->saddr.s6_addr32[3]);
	nexthdr = ip6h->nexthdr;

	for (i = 0; i < MAT_EXTHDR_MAX; i++) {
		__u8 hdr[2];

		if (nexthdr != IPPROTO_HOPOPTS && nexthdr != IPPROTO_ROUTING &&
		    nexthdr != IPPROTO_DSTOPTS)
			break;

		if (bpf_skb_load_bytes(skb, offset, hdr, sizeof(hdr)))
			return 0;

		nexthdr = hdr[0];
		offset += (hdr[1] + 1) * 8;
	}

	if (nexthdr == IPPROTO_UDP) {
		mat_parse_udp(skb, offset, p, true);
		return 0;
	}

	if (nexthdr == IPPROTO_FRAGMENT) {
		__u8 frag[4];

		if (bpf_skb_load_bytes(skb, offset, frag, sizeof(frag)))
			return 0;

		/* only the first fragment holds the ICMPv6 type */
		if (frag[0] != IPPROTO_ICMPV6 || frag[2] || (frag[3] & 0xf8))
			return 0;

		fragment = true;
		nexthdr = frag[0];
		offset += 8;
	}

	if (nexthdr != IPPROTO_ICMPV6)
		return 0;

	if (bpf_skb_load_bytes(skb, offset, &type, sizeof(type)))
		return 0;

	if (type == ICMPV6_IND_SOLICIT || type == ICMPV6_IND_ADVERT)
		p->class = MAT_CLASS_DROP;
	else if (type == ICMPV6_MLD_REPORT)
		p->class = MAT_CLASS_REPORT;
	else if (type < ICMPV6_ND_FIRST || type > ICMPV6_ND_LAST)
		return 0;
	else if (fragment)
		/* neighbour discovery must not be fragmented (RFC 6980) */
		p->class = MAT_CLASS_DROP;
	else
		p->class = MAT_CLASS_CONTROL;

	return 0;
}

static __always_inline int
mat_parse(struct __sk_buff *skb, struct mat_dev *dev, struct mat_pkt *p)
{
	struct ethhdr *eth;
	__u32 len = skb->len;

	if (len > MAT_PULL_LEN)
		len = MAT_PULL_LEN;
	bpf_skb_pull_data(skb, len);

	eth = skb_ptr(skb, 0, sizeof(*eth));
	if (!eth)
		return -1;

	memcpy(p->dst, eth->h_dest, ETH_ALEN);
	memcpy(p->src, eth->h_source, ETH_ALEN);
	p->proto = eth->h_proto;
	p->src_key.sta_ifindex = dev->sta_ifindex;
	p->dst_key.sta_ifindex = dev->sta_ifindex;

	switch (bpf_ntohs(p->proto)) {
	case ETH_P_ARP:
		p->class = MAT_CLASS_CONTROL;
		return 0;
	case MAT_ETH_P_PROBE:
		p->class = MAT_CLASS_PROBE;
		return 0;
	case ETH_P_IP:
		return mat_parse_ipv4(skb, p);
	case ETH_P_IPV6:
		return mat_parse_ipv6(skb, p);
	default:
		p->class = MAT_CLASS_OTHER;
		return 0;
	}
}

static __always_inline void
mat_group_mac(struct mat_pkt *p, __u8 *mac)
{
	const __u8 *addr = p->dst_key.addr;

	if (p->proto == bpf_htons(ETH_P_IPV6)) {
		mac[0] = 0x33;
		mac[1] = 0x33;
		memcpy(&mac[2], &addr[12], 4);
		return;
	}

	if (addr[12] == 0xff) {
		memset(mac, 0xff, ETH_ALEN);
		return;
	}

	mac[0] = 0x01;
	mac[1] = 0x00;
	mac[2] = 0x5e;
	mac[3] = addr[13] & 0x7f;
	mac[4] = addr[14];
	mac[5] = addr[15];
}

static __always_inline void
mat_learn(struct mat_pkt *p)
{
	struct mat_event *ev;
	__u64 now = bpf_ktime_get_ns();
	__u64 *last;

	last = bpf_map_lookup_elem(&mat_event_time, &p->src_key);
	if (last && now - *last < MAT_EVENT_INTERVAL_NS)
		return;

	bpf_map_update_elem(&mat_event_time, &p->src_key, &now, BPF_ANY);

	ev = bpf_ringbuf_reserve(&mat_events, sizeof(*ev), 0);
	if (!ev)
		return;

	ev->sta_ifindex = p->src_key.sta_ifindex;
	memcpy(ev->addr, p->src_key.addr, sizeof(ev->addr));
	memcpy(ev->mac, p->src, ETH_ALEN);
	ev->pad[0] = 0;
	ev->pad[1] = 0;
	bpf_ringbuf_submit(ev, 0);
}

static __always_inline int
mat_set_dest(struct __sk_buff *skb, const __u8 *mac)
{
	return bpf_skb_store_bytes(skb, 0, mac, ETH_ALEN, 0);
}

static __always_inline int
mat_set_source(struct __sk_buff *skb, const __u8 *mac)
{
	return bpf_skb_store_bytes(skb, ETH_ALEN, mac, ETH_ALEN, 0);
}

SEC("tc")
int mat_up(struct __sk_buff *skb)
{
	struct mat_pkt p = {};
	struct mat_bind *bind;
	struct mat_dev *dev;
	__u8 sta_mac[ETH_ALEN];
	__u32 ifindex = skb->ifindex;
	__u32 sta_ifindex, port_ifindex;

	dev = bpf_map_lookup_elem(&mat_dev, &ifindex);
	if (!dev)
		return TC_ACT_UNSPEC;

	if (skb->vlan_present) {
		/*
		 * A frame that mat_down sends to user space. A LAN host can
		 * send the same tag, so the frame must come from the station.
		 */
		if (skb->vlan_proto == bpf_htons(ETH_P_8021AD) &&
		    (skb->vlan_tci & 0xfff) == MAT_TAG_TCI &&
		    skb->ingress_ifindex == dev->sta_ifindex)
			return TC_ACT_UNSPEC;

		return TC_ACT_SHOT;
	}

	if (mat_parse(skb, dev, &p))
		return TC_ACT_SHOT;

	memcpy(sta_mac, dev->sta_mac, ETH_ALEN);
	sta_ifindex = dev->sta_ifindex;
	port_ifindex = dev->port_ifindex;

	switch (p.class) {
	case MAT_CLASS_CONTROL:
	case MAT_CLASS_PROBE:
		return TC_ACT_UNSPEC;
	case MAT_CLASS_DATA:
	case MAT_CLASS_REPORT:
		break;
	default:
		return TC_ACT_SHOT;
	}

	if (mac_equal(p.src, sta_mac))
		return TC_ACT_SHOT;

	if (mac_equal(p.dst, sta_mac)) {
		bind = bpf_map_lookup_elem(&mat_bind, &p.dst_key);
		if (!bind)
			return TC_ACT_SHOT;

		/*
		 * The station MAC as source keeps the bridge from learning
		 * the sender's address on the proxy port.
		 */
		if (mat_set_dest(skb, bind->mac) || mat_set_source(skb, sta_mac))
			return TC_ACT_SHOT;

		return bpf_redirect(port_ifindex, BPF_F_INGRESS);
	}

	if (!p.src_unspec && !(p.src[0] & 1)) {
		bind = bpf_map_lookup_elem(&mat_bind, &p.src_key);
		if (bind && mac_equal(bind->mac, p.src))
			bind->last_seen = bpf_ktime_get_ns();
		else
			mat_learn(&p);
	}

	if (mat_set_source(skb, sta_mac))
		return TC_ACT_SHOT;

	return bpf_redirect(sta_ifindex, 0);
}

SEC("tc")
int mat_down(struct __sk_buff *skb)
{
	struct mat_pkt p = {};
	struct mat_bind *bind;
	struct mat_dev *dev;
	__u8 mac[ETH_ALEN];
	__u32 ifindex = skb->ifindex;
	__u32 port_ifindex;
	bool group;

	dev = bpf_map_lookup_elem(&mat_dev, &ifindex);
	if (!dev)
		return TC_ACT_UNSPEC;

	if (mat_parse(skb, dev, &p))
		return TC_ACT_UNSPEC;

	/* the AP sends the station's own group frames back to it */
	if (mac_equal(p.src, dev->sta_mac))
		return TC_ACT_SHOT;

	group = p.dst[0] & 1;
	if (!group && !mac_equal(p.dst, dev->sta_mac))
		return TC_ACT_UNSPEC;

	port_ifindex = dev->port_ifindex;

	switch (p.class) {
	case MAT_CLASS_OTHER:
		return TC_ACT_UNSPEC;
	case MAT_CLASS_DROP:
		return TC_ACT_SHOT;
	case MAT_CLASS_REPORT:
		/*
		 * A report from upstream stops the reports of the LAN hosts
		 * (report suppression), and a snooping AP then drops the
		 * station from the group.
		 */
		return TC_ACT_SHOT;
	case MAT_CLASS_CONTROL:
		goto bounce;
	case MAT_CLASS_PROBE:
		if (!group)
			return TC_ACT_SHOT;
		break;
	default:
		break;
	}

	if (group)
		return bpf_redirect(port_ifindex, BPF_F_INGRESS);

	if (p.dst_group) {
		mat_group_mac(&p, mac);
		if (mat_set_dest(skb, mac))
			return TC_ACT_SHOT;

		return bpf_redirect(port_ifindex, BPF_F_INGRESS);
	}

	bind = bpf_map_lookup_elem(&mat_bind, &p.dst_key);
	if (!bind)
		goto bounce;

	memcpy(mac, bind->mac, ETH_ALEN);
	if (mat_set_dest(skb, mac))
		return TC_ACT_SHOT;

	return bpf_redirect(port_ifindex, BPF_F_INGRESS);

bounce:
	if (bpf_skb_vlan_push(skb, bpf_htons(ETH_P_8021AD), MAT_TAG_TCI))
		return TC_ACT_SHOT;

	return bpf_redirect(port_ifindex, 0);
}

SEC("tc")
int mat_sta_out(struct __sk_buff *skb)
{
	struct mat_dev *dev;
	struct ethhdr *eth;
	__u32 ifindex = skb->ifindex;

	dev = bpf_map_lookup_elem(&mat_dev, &ifindex);
	if (!dev)
		return TC_ACT_UNSPEC;

	bpf_skb_pull_data(skb, sizeof(*eth));
	eth = skb_ptr(skb, 0, sizeof(*eth));
	if (!eth)
		return TC_ACT_SHOT;

	if (!mac_equal(eth->h_source, dev->sta_mac))
		return TC_ACT_SHOT;

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
