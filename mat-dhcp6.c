// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include "bridger.h"

#define DHCP6_SERVER_PORT	547
#define DHCP6_CLIENT_PORT	546

#define DHCP6_UDP_HDR_LEN	8
#define DHCP6_MSG_HDR_LEN	4
#define DHCP6_OPT_HDR_LEN	4

#define DHCP6_MSG_REPLY		7

#define DHCP6_OPT_IA_NA		3
#define DHCP6_OPT_IA_TA		4
#define DHCP6_OPT_IAADDR	5
#define DHCP6_OPT_IA_PD		25
#define DHCP6_OPT_IAPREFIX	26

#define DHCP6_IA_NA_HDR_LEN	12
#define DHCP6_IA_TA_HDR_LEN	4
#define DHCP6_IAADDR_LEN	24
#define DHCP6_IAPREFIX_LEN	25
#define DHCP6_PREFIX_MIN_LEN	16

#define IP6_OFS_SRC		8
#define IP6_OFS_DST		24

static uint32_t get_be32(const uint8_t *data)
{
	uint32_t val;

	memcpy(&val, data, sizeof(val));

	return ntohl(val);
}

static uint8_t *mat_dhcp6_payload(uint8_t *frame, size_t len, size_t *payload_len)
{
	uint8_t nexthdr;
	uint8_t *udp;
	size_t udp_len;
	uint32_t sum;

	udp = mat_ipv6_payload(frame, len, &nexthdr, &udp_len);
	if (!udp || nexthdr != IPPROTO_UDP ||
	    udp_len < DHCP6_UDP_HDR_LEN + DHCP6_MSG_HDR_LEN)
		return NULL;

	if (((udp[0] << 8) | udp[1]) != DHCP6_SERVER_PORT ||
	    ((udp[2] << 8) | udp[3]) != DHCP6_CLIENT_PORT)
		return NULL;

	sum = mat_csum_add(IPPROTO_UDP + udp_len,
			   frame + sizeof(struct ether_header) + IP6_OFS_SRC,
			   2 * MAT_ADDR_LEN);
	if (mat_csum_fold(mat_csum_add(sum, udp, udp_len)))
		return NULL;

	*payload_len = udp_len - DHCP6_UDP_HDR_LEN;

	return udp + DHCP6_UDP_HDR_LEN;
}

bool mat_dhcp6_match(uint8_t *frame, size_t len)
{
	size_t payload_len;

	return !!mat_dhcp6_payload(frame, len, &payload_len);
}

static void mat_dhcp6_lease(struct mat_instance *inst, const uint8_t *mac,
			    uint16_t code, const uint8_t *data, size_t len)
{
	uint64_t lifetime;

	if (code == DHCP6_OPT_IAADDR && len >= DHCP6_IAADDR_LEN) {
		lifetime = (uint64_t)get_be32(data + 20) * 1000;
		if (lifetime)
			mat_binding_update_ipv6(inst, data, mac, MAT_SRC_DHCP, lifetime);
		return;
	}

	if (code == DHCP6_OPT_IAPREFIX && len >= DHCP6_IAPREFIX_LEN &&
	    data[8] >= DHCP6_PREFIX_MIN_LEN) {
		lifetime = (uint64_t)get_be32(data + 4) * 1000;
		mat_prefix_update(inst, data + 9, data[8], mac, lifetime);
	}
}

static void mat_dhcp6_options(struct mat_instance *inst, const uint8_t *mac,
			      const uint8_t *opts, size_t len, bool nested)
{
	while (len >= DHCP6_OPT_HDR_LEN) {
		uint16_t code = (opts[0] << 8) | opts[1];
		size_t olen = (opts[2] << 8) | opts[3];
		const uint8_t *data = opts + DHCP6_OPT_HDR_LEN;
		size_t hdr_len = 0;

		if (olen > len - DHCP6_OPT_HDR_LEN)
			return;

		if (nested)
			mat_dhcp6_lease(inst, mac, code, data, olen);
		else if (code == DHCP6_OPT_IA_NA || code == DHCP6_OPT_IA_PD)
			hdr_len = DHCP6_IA_NA_HDR_LEN;
		else if (code == DHCP6_OPT_IA_TA)
			hdr_len = DHCP6_IA_TA_HDR_LEN;

		if (hdr_len && olen >= hdr_len)
			mat_dhcp6_options(inst, mac, data + hdr_len,
					  olen - hdr_len, true);

		opts = data + olen;
		len -= DHCP6_OPT_HDR_LEN + olen;
	}
}

void mat_dhcp6_down(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	struct ether_header *eth = (struct ether_header *)frame;
	uint8_t *ip6 = frame + sizeof(*eth);
	struct mat_binding *b;
	size_t payload_len;
	uint8_t *msg;

	if (eth->ether_dhost[0] & 1) {
		mat_send_down(inst, frame, len);
		return;
	}

	/* a client sends from its link-local address, which data frames bind */
	b = mat_binding_get(inst, ip6 + IP6_OFS_DST);
	if (!b) {
		inst->dropped++;
		return;
	}

	msg = mat_dhcp6_payload(frame, len, &payload_len);
	if (msg && msg[0] == DHCP6_MSG_REPLY)
		mat_dhcp6_options(inst, b->mac, msg + DHCP6_MSG_HDR_LEN,
				  payload_len - DHCP6_MSG_HDR_LEN, false);

	memcpy(eth->ether_dhost, b->mac, ETH_ALEN);
	mat_send_down(inst, frame, len);
}
