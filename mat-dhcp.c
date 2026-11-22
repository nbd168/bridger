// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "bridger.h"

#define DHCP_SERVER_PORT	67
#define DHCP_CLIENT_PORT	68

#define DHCP_MAGIC		0x63825363
#define DHCP_FLAG_BROADCAST	0x8000

#define BOOTREQUEST		1
#define BOOTREPLY		2

#define DHCPDECLINE		4
#define DHCPACK			5
#define DHCPNAK			6
#define DHCPRELEASE		7

#define DHCP_OPT_PAD		0
#define DHCP_OPT_REQUESTED_IP	50
#define DHCP_OPT_LEASE_TIME	51
#define DHCP_OPT_MSG_TYPE	53
#define DHCP_OPT_CLIENT_ID	61
#define DHCP_OPT_END		255

#define DHCP_CLIENT_ID_LEN	(2 + 1 + ETH_ALEN)

struct mat_ip_hdr {
	uint8_t ver_ihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint8_t saddr[4];
	uint8_t daddr[4];
} __attribute__((packed));

struct mat_udp_hdr {
	uint16_t source;
	uint16_t dest;
	uint16_t len;
	uint16_t check;
} __attribute__((packed));

struct mat_dhcp_hdr {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint8_t ciaddr[4];
	uint8_t yiaddr[4];
	uint8_t siaddr[4];
	uint8_t giaddr[4];
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic;
	uint8_t options[];
} __attribute__((packed));

struct mat_dhcp_pkt {
	struct ether_header *eth;
	struct mat_ip_hdr *ip;
	struct mat_udp_hdr *udp;
	struct mat_dhcp_hdr *dhcp;
	size_t opt_len;
	size_t end_ofs;
	uint8_t msg_type;
	const uint8_t *requested_ip;
	const uint8_t *lease_time;
	const uint8_t *client_id;
};

struct mat_dhcp_xid {
	struct list_head list;
	uint32_t xid;
	uint16_t flags;
	uint8_t mac[ETH_ALEN];
	uint64_t time;
};

static const uint8_t ip_broadcast[4] = { 0xff, 0xff, 0xff, 0xff };
static const uint8_t ip_unspec[4];

static uint32_t csum_add(uint32_t sum, const void *data, size_t len)
{
	const uint8_t *p = data;

	for (; len > 1; len -= 2, p += 2)
		sum += (p[0] << 8) | p[1];

	if (len)
		sum += p[0] << 8;

	return sum;
}

static uint16_t csum_fold(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return htons(~sum);
}

static uint16_t mat_udp_csum(struct mat_ip_hdr *ip, struct mat_udp_hdr *udp)
{
	uint16_t len = ntohs(udp->len);
	uint32_t sum = IPPROTO_UDP + len;
	uint16_t check;

	sum = csum_add(sum, ip->saddr, 8);
	sum = csum_add(sum, udp, len);
	check = csum_fold(sum);

	return check ? check : 0xffff;
}

static bool mat_udp_csum_valid(struct mat_ip_hdr *ip, struct mat_udp_hdr *udp)
{
	uint16_t len = ntohs(udp->len);
	uint32_t sum = IPPROTO_UDP + len;

	if (!udp->check)
		return true;

	sum = csum_add(sum, ip->saddr, 8);
	sum = csum_add(sum, udp, len);

	return !csum_fold(sum);
}

static void mat_dhcp_csum_update(struct mat_dhcp_pkt *pkt)
{
	if (!pkt->udp->check)
		return;

	pkt->udp->check = 0;
	pkt->udp->check = mat_udp_csum(pkt->ip, pkt->udp);
}

static struct mat_udp_hdr *
mat_udp_get(const uint8_t *frame, size_t len, struct mat_ip_hdr **ip_ret)
{
	struct mat_ip_hdr *ip = (struct mat_ip_hdr *)(frame + sizeof(struct ether_header));
	struct mat_udp_hdr *udp;
	size_t ihl;

	if (len < sizeof(struct ether_header) + sizeof(*ip))
		return NULL;

	ihl = (ip->ver_ihl & 0xf) * 4;
	if (ihl < sizeof(*ip) || ip->protocol != IPPROTO_UDP ||
	    (ip->frag_off & htons(0x3fff)))
		return NULL;

	if (len < sizeof(struct ether_header) + ihl + sizeof(*udp))
		return NULL;

	*ip_ret = ip;

	return (struct mat_udp_hdr *)((uint8_t *)ip + ihl);
}

bool mat_dhcp_match(const uint8_t *frame, size_t len)
{
	struct mat_udp_hdr *udp;
	struct mat_ip_hdr *ip;
	uint16_t sport, dport;

	udp = mat_udp_get(frame, len, &ip);
	if (!udp)
		return false;

	sport = ntohs(udp->source);
	dport = ntohs(udp->dest);

	return (sport == DHCP_CLIENT_PORT && dport == DHCP_SERVER_PORT) ||
	       (sport == DHCP_SERVER_PORT && dport == DHCP_CLIENT_PORT);
}

static void mat_dhcp_parse_options(struct mat_dhcp_pkt *pkt)
{
	const uint8_t *opt = pkt->dhcp->options;
	size_t ofs = 0;

	pkt->end_ofs = pkt->opt_len;

	while (ofs < pkt->opt_len) {
		uint8_t code = opt[ofs];
		uint8_t olen;

		if (code == DHCP_OPT_PAD) {
			ofs++;
			continue;
		}

		if (code == DHCP_OPT_END) {
			pkt->end_ofs = ofs;
			return;
		}

		if (ofs + 2 > pkt->opt_len)
			return;

		olen = opt[ofs + 1];
		if (ofs + 2 + olen > pkt->opt_len)
			return;

		if (code == DHCP_OPT_MSG_TYPE && olen == 1)
			pkt->msg_type = opt[ofs + 2];
		else if (code == DHCP_OPT_REQUESTED_IP && olen == 4)
			pkt->requested_ip = &opt[ofs + 2];
		else if (code == DHCP_OPT_LEASE_TIME && olen == 4)
			pkt->lease_time = &opt[ofs + 2];
		else if (code == DHCP_OPT_CLIENT_ID)
			pkt->client_id = &opt[ofs];

		ofs += 2 + olen;
	}
}

static bool mat_dhcp_parse(uint8_t *frame, size_t len, struct mat_dhcp_pkt *pkt)
{
	size_t udp_len;

	memset(pkt, 0, sizeof(*pkt));
	pkt->eth = (struct ether_header *)frame;
	pkt->udp = mat_udp_get(frame, len, &pkt->ip);
	if (!pkt->udp)
		return false;

	udp_len = ntohs(pkt->udp->len);
	if (udp_len < sizeof(*pkt->udp) + sizeof(*pkt->dhcp) ||
	    (uint8_t *)pkt->udp + udp_len > frame + len)
		return false;

	if (ntohs(pkt->ip->tot_len) != (uint8_t *)pkt->udp - (uint8_t *)pkt->ip + udp_len)
		return false;

	pkt->dhcp = (struct mat_dhcp_hdr *)(pkt->udp + 1);
	if (pkt->dhcp->magic != htonl(DHCP_MAGIC) ||
	    pkt->dhcp->htype != 1 || pkt->dhcp->hlen != ETH_ALEN)
		return false;

	if (!mat_udp_csum_valid(pkt->ip, pkt->udp))
		return false;

	pkt->opt_len = udp_len - sizeof(*pkt->udp) - sizeof(*pkt->dhcp);
	mat_dhcp_parse_options(pkt);

	return true;
}

void mat_dhcp_xids_expire(struct mat_instance *inst, bool all)
{
	struct mat_dhcp_xid *x, *tmp;
	uint64_t now = mat_now();

	list_for_each_entry_safe(x, tmp, &inst->dhcp_xids, list) {
		if (!all && now - x->time < MAT_DHCP_XID_TIMEOUT)
			continue;

		list_del(&x->list);
		inst->n_dhcp_xids--;
		free(x);
	}
}

static bool mat_dhcp_xid_add(struct mat_instance *inst, struct mat_dhcp_pkt *pkt,
			     const uint8_t *mac)
{
	struct mat_dhcp_xid *x;

	list_for_each_entry(x, &inst->dhcp_xids, list)
		if (x->xid == pkt->dhcp->xid && !memcmp(x->mac, mac, ETH_ALEN))
			goto out;

	if (inst->n_dhcp_xids >= MAT_DHCP_XID_MAX)
		return false;

	x = calloc(1, sizeof(*x));
	if (!x)
		return false;

	x->xid = pkt->dhcp->xid;
	memcpy(x->mac, mac, ETH_ALEN);
	list_add_tail(&x->list, &inst->dhcp_xids);
	inst->n_dhcp_xids++;

out:
	x->flags = pkt->dhcp->flags;
	x->time = mat_now();

	return true;
}

/*
 * The request of a LAN host that a reply answers. A reply with the station's
 * address as chaddr answers a request of the chaddr mode; a server echoes the
 * client identifier (RFC 6842), which then names the host.
 */
static struct mat_dhcp_xid *
mat_dhcp_xid_get(struct mat_instance *inst, struct mat_dhcp_pkt *pkt)
{
	struct mat_dhcp_xid *x, *match = NULL;
	const uint8_t *mac = pkt->dhcp->chaddr;
	const uint8_t *id = pkt->client_id;
	bool rewritten;

	rewritten = !memcmp(mac, inst->sta_mac, ETH_ALEN);
	if (rewritten)
		mac = id && id[1] == 1 + ETH_ALEN && id[2] == 1 ? &id[3] : NULL;

	list_for_each_entry(x, &inst->dhcp_xids, list) {
		if (x->xid != pkt->dhcp->xid)
			continue;

		if (mac && !memcmp(mac, x->mac, ETH_ALEN))
			return x;

		match = x;
	}

	return rewritten ? match : NULL;
}

/*
 * Without a client identifier, a server takes chaddr as the client's
 * identity (RFC 2131 4.2), and every host would be the same client.
 */
static size_t mat_dhcp_add_client_id(struct mat_dhcp_pkt *pkt, uint8_t *frame,
				     size_t len, const uint8_t *mac)
{
	uint8_t *opt = pkt->dhcp->options + pkt->end_ofs;
	size_t space = pkt->opt_len - pkt->end_ofs;
	size_t grow = 0;
	uint16_t ip_len;

	if (pkt->client_id)
		return len;

	if (space < DHCP_CLIENT_ID_LEN + 1) {
		grow = DHCP_CLIENT_ID_LEN + 1 - space;
		grow += grow & 1;
		if ((size_t)(opt + space + grow - frame) > MAT_FRAME_MAX - 4)
			return 0;

		memset(opt + space, 0, grow);
	}

	opt[0] = DHCP_OPT_CLIENT_ID;
	opt[1] = 1 + ETH_ALEN;
	opt[2] = 1;
	memcpy(&opt[3], mac, ETH_ALEN);
	opt[DHCP_CLIENT_ID_LEN] = DHCP_OPT_END;

	if (!grow)
		return len;

	pkt->udp->len = htons(ntohs(pkt->udp->len) + grow);
	ip_len = ntohs(pkt->ip->tot_len) + grow;
	pkt->ip->tot_len = htons(ip_len);
	pkt->ip->check = 0;
	pkt->ip->check = csum_fold(csum_add(0, pkt->ip, (pkt->ip->ver_ihl & 0xf) * 4));

	return sizeof(struct ether_header) + ip_len;
}

static void mat_dhcp_unbind(struct mat_instance *inst, const uint8_t *ip,
			    const uint8_t *mac)
{
	uint8_t addr[MAT_ADDR_LEN];
	struct mat_binding *b;

	if (!ip || !memcmp(ip, ip_unspec, 4))
		return;

	mat_addr_from_ipv4(addr, ip);
	b = mat_binding_get(inst, addr);
	if (b && !memcmp(b->mac, mac, ETH_ALEN))
		mat_binding_delete(inst, b);
}

void mat_dhcp_up(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	struct mat_dhcp_pkt pkt;
	uint8_t mac[ETH_ALEN];

	if (!mat_dhcp_parse(frame, len, &pkt) || pkt.dhcp->op != BOOTREQUEST ||
	    pkt.udp->source != htons(DHCP_CLIENT_PORT))
		goto drop;

	memcpy(mac, pkt.eth->ether_shost, ETH_ALEN);
	if (!mat_dhcp_xid_add(inst, &pkt, mac))
		goto drop;

	if (pkt.msg_type == DHCPRELEASE)
		mat_dhcp_unbind(inst, pkt.dhcp->ciaddr, mac);
	else if (pkt.msg_type == DHCPDECLINE)
		mat_dhcp_unbind(inst, pkt.requested_ip, mac);

	if (inst->dhcp_mode == MAT_DHCP_CHADDR) {
		memcpy(pkt.dhcp->chaddr, inst->sta_mac, ETH_ALEN);
		len = mat_dhcp_add_client_id(&pkt, frame, len, mac);
		if (!len)
			goto drop;
	} else {
		pkt.dhcp->flags |= htons(DHCP_FLAG_BROADCAST);
	}

	mat_dhcp_csum_update(&pkt);
	mat_send_up(inst, frame, len);
	return;

drop:
	inst->dropped++;
}

static void mat_dhcp_bind(struct mat_instance *inst, struct mat_dhcp_pkt *pkt,
			  const uint8_t *mac)
{
	uint8_t addr[MAT_ADDR_LEN];
	uint32_t lease;

	if (pkt->msg_type == DHCPNAK) {
		mat_binding_delete_dhcp(inst, mac);
		return;
	}

	if (pkt->msg_type != DHCPACK || !pkt->lease_time ||
	    !memcmp(pkt->dhcp->yiaddr, ip_unspec, 4))
		return;

	memcpy(&lease, pkt->lease_time, sizeof(lease));
	mat_addr_from_ipv4(addr, pkt->dhcp->yiaddr);
	mat_binding_update(inst, addr, mac, MAT_SRC_DHCP,
			   (uint64_t)ntohl(lease) * 1000);
}

void mat_dhcp_down(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	struct mat_dhcp_pkt pkt;
	struct mat_dhcp_xid *x;
	const uint8_t *mac;
	bool broadcast;

	if (!mat_dhcp_parse(frame, len, &pkt) || pkt.dhcp->op != BOOTREPLY ||
	    pkt.udp->source != htons(DHCP_SERVER_PORT))
		goto drop;

	mac = pkt.dhcp->chaddr;
	broadcast = !memcmp(pkt.ip->daddr, ip_broadcast, 4);
	x = mat_dhcp_xid_get(inst, &pkt);

	if (!memcmp(mac, inst->sta_mac, ETH_ALEN)) {
		if (!x)
			goto drop;

		mac = x->mac;
		broadcast = broadcast && (x->flags & htons(DHCP_FLAG_BROADCAST));
		memcpy(pkt.dhcp->chaddr, mac, ETH_ALEN);
		mat_dhcp_csum_update(&pkt);
	}

	/* a reply to no request of a LAN host is for a client upstream */
	if (x)
		mat_dhcp_bind(inst, &pkt, mac);

	if (!(pkt.eth->ether_dhost[0] & 1)) {
		if (broadcast)
			memset(pkt.eth->ether_dhost, 0xff, ETH_ALEN);
		else
			memcpy(pkt.eth->ether_dhost, mac, ETH_ALEN);
	}

	mat_send_down(inst, frame, len);
	return;

drop:
	inst->dropped++;
}
