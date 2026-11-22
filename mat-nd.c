// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "bridger.h"

#define IP6_HDR_LEN		40
#define IP6_OFS_PAYLOAD_LEN	4
#define IP6_OFS_NEXTHDR		6
#define IP6_OFS_HOPLIMIT	7
#define IP6_OFS_SRC		8
#define IP6_OFS_DST		24

#define IP6_EXTHDR_MAX		4

#define ND_ROUTER_SOLICIT	133
#define ND_ROUTER_ADVERT	134
#define ND_NEIGHBOR_SOLICIT	135
#define ND_NEIGHBOR_ADVERT	136
#define ND_REDIRECT		137

#define ND_OPT_SOURCE_LLADDR	1
#define ND_OPT_TARGET_LLADDR	2
#define ND_OPT_LLADDR_LEN	8

#define ND_HOPLIMIT		255

struct mat_nd_pkt {
	struct ether_header *eth;
	uint8_t *ip6;
	uint8_t *icmp;
	size_t icmp_len;
	uint8_t type;
	uint8_t *target;
	uint8_t *opts;
	size_t opts_len;
};

struct mat_ns_frame {
	struct ether_header eth;
	uint8_t ip6[IP6_HDR_LEN];
	uint8_t type;
	uint8_t code;
	uint16_t check;
	uint32_t reserved;
	uint8_t target[MAT_ADDR_LEN];
	uint8_t opt_type;
	uint8_t opt_len;
	uint8_t opt_mac[ETH_ALEN];
} __attribute__((packed));

static const uint8_t addr_unspec[MAT_ADDR_LEN];

uint8_t *mat_ipv6_payload(uint8_t *frame, size_t len, uint8_t *nexthdr,
			  size_t *payload_len)
{
	uint8_t *ip6 = frame + sizeof(struct ether_header);
	size_t ofs = IP6_HDR_LEN;
	size_t plen;
	uint8_t nh;
	int i;

	if (len < sizeof(struct ether_header) + IP6_HDR_LEN)
		return NULL;

	plen = (ip6[IP6_OFS_PAYLOAD_LEN] << 8) | ip6[IP6_OFS_PAYLOAD_LEN + 1];
	if (len < sizeof(struct ether_header) + IP6_HDR_LEN + plen)
		return NULL;

	plen += IP6_HDR_LEN;
	nh = ip6[IP6_OFS_NEXTHDR];
	for (i = 0; i < IP6_EXTHDR_MAX; i++) {
		if (nh != IPPROTO_HOPOPTS && nh != IPPROTO_ROUTING &&
		    nh != IPPROTO_DSTOPTS)
			break;

		if (ofs + 2 > plen)
			return NULL;

		nh = ip6[ofs];
		ofs += (ip6[ofs + 1] + 1) * 8;
	}

	if (ofs > plen)
		return NULL;

	*nexthdr = nh;
	*payload_len = plen - ofs;

	return ip6 + ofs;
}

static uint16_t mat_icmp6_csum(struct mat_nd_pkt *pkt)
{
	uint32_t sum = IPPROTO_ICMPV6 + pkt->icmp_len;

	sum = mat_csum_add(sum, pkt->ip6 + IP6_OFS_SRC, 2 * MAT_ADDR_LEN);
	sum = mat_csum_add(sum, pkt->icmp, pkt->icmp_len);

	return mat_csum_fold(sum);
}

static void mat_icmp6_csum_update(struct mat_nd_pkt *pkt)
{
	pkt->icmp[2] = 0;
	pkt->icmp[3] = 0;
	memcpy(&pkt->icmp[2], &(uint16_t){ mat_icmp6_csum(pkt) }, 2);
}

static uint8_t *mat_nd_option(struct mat_nd_pkt *pkt, uint8_t type)
{
	size_t ofs = 0;

	while (ofs + 2 <= pkt->opts_len) {
		uint8_t *opt = pkt->opts + ofs;

		if (!opt[1])
			return NULL;

		if (opt[0] == type && opt[1] * 8 == ND_OPT_LLADDR_LEN)
			return opt;

		ofs += opt[1] * 8;
	}

	return NULL;
}

static bool mat_nd_options_valid(struct mat_nd_pkt *pkt)
{
	size_t ofs = 0;

	while (ofs < pkt->opts_len) {
		if (ofs + 2 > pkt->opts_len || !pkt->opts[ofs + 1])
			return false;

		ofs += pkt->opts[ofs + 1] * 8;
	}

	return ofs == pkt->opts_len;
}

static bool mat_nd_parse(uint8_t *frame, size_t len, struct mat_nd_pkt *pkt)
{
	size_t opts_ofs;
	uint8_t nexthdr;

	memset(pkt, 0, sizeof(*pkt));
	pkt->eth = (struct ether_header *)frame;
	pkt->ip6 = frame + sizeof(*pkt->eth);
	pkt->icmp = mat_ipv6_payload(frame, len, &nexthdr, &pkt->icmp_len);
	if (!pkt->icmp || nexthdr != IPPROTO_ICMPV6 || pkt->icmp_len < 8)
		return false;

	pkt->type = pkt->icmp[0];
	switch (pkt->type) {
	case ND_ROUTER_SOLICIT:
		opts_ofs = 8;
		break;
	case ND_ROUTER_ADVERT:
		opts_ofs = 16;
		break;
	case ND_NEIGHBOR_SOLICIT:
	case ND_NEIGHBOR_ADVERT:
		opts_ofs = 24;
		break;
	case ND_REDIRECT:
		opts_ofs = 40;
		break;
	default:
		return false;
	}

	if (pkt->icmp_len < opts_ofs)
		return false;

	if (opts_ofs >= 24)
		pkt->target = pkt->icmp + 8;
	pkt->opts = pkt->icmp + opts_ofs;
	pkt->opts_len = pkt->icmp_len - opts_ofs;

	return true;
}

bool mat_nd_match(uint8_t *frame, size_t len)
{
	struct mat_nd_pkt pkt;

	return mat_nd_parse(frame, len, &pkt);
}

static bool mat_nd_valid(struct mat_nd_pkt *pkt)
{
	return pkt->ip6[IP6_OFS_HOPLIMIT] == ND_HOPLIMIT && !pkt->icmp[1] &&
	       !mat_icmp6_csum(pkt) && mat_nd_options_valid(pkt);
}

static bool mat_nd_set_lladdr(struct mat_nd_pkt *pkt, uint8_t type,
			      const uint8_t *mac)
{
	uint8_t *opt;

	opt = mat_nd_option(pkt, type);
	if (!opt)
		return false;

	memcpy(opt + 2, mac, ETH_ALEN);
	mat_icmp6_csum_update(pkt);

	return true;
}

void mat_nd_up(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	const uint8_t *src, *mac;
	struct mat_nd_pkt pkt;
	bool src_unspec;

	if (!mat_nd_parse(frame, len, &pkt) || !mat_nd_valid(&pkt))
		goto drop;

	mac = pkt.eth->ether_shost;
	src = pkt.ip6 + IP6_OFS_SRC;
	src_unspec = !memcmp(src, addr_unspec, MAT_ADDR_LEN);

	switch (pkt.type) {
	case ND_ROUTER_SOLICIT:
		break;
	case ND_NEIGHBOR_SOLICIT:
		/* duplicate address detection: the address is not confirmed */
		if (src_unspec)
			mat_binding_update_ipv6(inst, pkt.target, mac, MAT_SRC_LEARN, 0);
		break;
	case ND_NEIGHBOR_ADVERT:
		mat_binding_update_ipv6(inst, pkt.target, mac, MAT_SRC_NEIGH, 0);
		break;
	default:
		/* a LAN host must not act as a router for the upstream side */
		goto drop;
	}

	if (!src_unspec)
		mat_binding_update_ipv6(inst, src, mac, MAT_SRC_NEIGH, 0);

	/* an answer to a solicitation of mat_nd_request() */
	if (!memcmp(pkt.eth->ether_dhost, inst->own_mac, ETH_ALEN))
		return;

	mat_nd_set_lladdr(&pkt, pkt.type == ND_NEIGHBOR_ADVERT ?
			  ND_OPT_TARGET_LLADDR : ND_OPT_SOURCE_LLADDR,
			  inst->sta_mac);
	mat_send_up(inst, frame, len);
	return;

drop:
	inst->dropped++;
}

void mat_nd_down(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	struct mat_nd_pkt pkt;
	struct mat_binding *b;
	const uint8_t *src;
	uint8_t *opt;

	if (!mat_nd_parse(frame, len, &pkt) || !mat_nd_valid(&pkt))
		goto drop;

	src = pkt.ip6 + IP6_OFS_SRC;

	switch (pkt.type) {
	case ND_ROUTER_SOLICIT:
		goto drop;
	case ND_NEIGHBOR_ADVERT:
		/*
		 * An AP with proxy ND answers for the hosts behind the
		 * station, also for one whose binding is gone.
		 */
		opt = mat_nd_option(&pkt, ND_OPT_TARGET_LLADDR);
		if (opt && !memcmp(opt + 2, inst->sta_mac, ETH_ALEN))
			goto drop;

		mat_upstream_seen(inst, pkt.target);
		break;
	case ND_REDIRECT:
		/* the router names the station for a target on the LAN */
		b = mat_binding_get(inst, pkt.target);
		if (b)
			mat_nd_set_lladdr(&pkt, ND_OPT_TARGET_LLADDR, b->mac);
		break;
	default:
		break;
	}

	if (memcmp(src, addr_unspec, MAT_ADDR_LEN))
		mat_upstream_seen(inst, src);

	if (pkt.eth->ether_dhost[0] & 1) {
		mat_send_down(inst, frame, len);
		return;
	}

	b = mat_binding_get(inst, pkt.ip6 + IP6_OFS_DST);
	if (!b)
		goto drop;

	memcpy(pkt.eth->ether_dhost, b->mac, ETH_ALEN);
	mat_send_down(inst, frame, len);
	return;

drop:
	inst->dropped++;
}

/*
 * The source is never the unspecified address: the target would take the
 * solicitation for duplicate address detection and defend its address with
 * an advertisement to all nodes, which also goes upstream.
 */
void mat_nd_request(struct mat_instance *inst, const uint8_t *addr,
		    const uint8_t *dest)
{
	struct mat_ns_frame f = {
		.eth.ether_type = htons(ETH_P_IPV6),
		.ip6[0] = 0x60,
		.ip6[IP6_OFS_PAYLOAD_LEN + 1] = sizeof(f) - offsetof(struct mat_ns_frame, type),
		.ip6[IP6_OFS_NEXTHDR] = IPPROTO_ICMPV6,
		.ip6[IP6_OFS_HOPLIMIT] = ND_HOPLIMIT,
		.type = ND_NEIGHBOR_SOLICIT,
		.opt_type = ND_OPT_SOURCE_LLADDR,
		.opt_len = 1,
	};
	struct mat_nd_pkt pkt = {
		.ip6 = f.ip6,
		.icmp = &f.type,
		.icmp_len = sizeof(f) - offsetof(struct mat_ns_frame, type),
	};
	uint8_t *src = f.ip6 + IP6_OFS_SRC;
	uint8_t *dst = f.ip6 + IP6_OFS_DST;

	memcpy(f.eth.ether_shost, inst->own_mac, ETH_ALEN);
	memcpy(f.opt_mac, inst->own_mac, ETH_ALEN);
	memcpy(f.target, addr, MAT_ADDR_LEN);

	src[0] = 0xfe;
	src[1] = 0x80;
	memcpy(&src[8], inst->own_mac, 3);
	src[8] ^= 2;
	src[11] = 0xff;
	src[12] = 0xfe;
	memcpy(&src[13], &inst->own_mac[3], 3);

	if (dest) {
		memcpy(dst, addr, MAT_ADDR_LEN);
		memcpy(f.eth.ether_dhost, dest, ETH_ALEN);
	} else {
		dst[0] = 0xff;
		dst[1] = 0x02;
		dst[11] = 0x01;
		dst[12] = 0xff;
		memcpy(&dst[13], &addr[13], 3);
		f.eth.ether_dhost[0] = 0x33;
		f.eth.ether_dhost[1] = 0x33;
		memcpy(&f.eth.ether_dhost[2], &dst[12], 4);
	}

	mat_icmp6_csum_update(&pkt);
	mat_send_down(inst, (uint8_t *)&f, sizeof(f));
}
