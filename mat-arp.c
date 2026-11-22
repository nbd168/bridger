// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>

#include "bridger.h"

struct mat_arp_frame {
	struct ether_header eth;
	struct ether_arp arp;
} __attribute__((packed));

struct mat_arp_probe {
	struct list_head list;
	uint8_t addr[MAT_ADDR_LEN];
	uint8_t mac[ETH_ALEN];
	uint64_t time;
};

static const uint8_t ip_unspec[4];

static struct mat_arp_frame *mat_arp_parse(uint8_t *frame, size_t len)
{
	struct mat_arp_frame *f = (struct mat_arp_frame *)frame;
	uint16_t op;

	if (len < sizeof(*f))
		return NULL;

	if (f->arp.arp_hrd != htons(ARPHRD_ETHER) ||
	    f->arp.arp_pro != htons(ETH_P_IP) ||
	    f->arp.arp_hln != ETH_ALEN || f->arp.arp_pln != 4)
		return NULL;

	op = ntohs(f->arp.arp_op);
	if (op != ARPOP_REQUEST && op != ARPOP_REPLY)
		return NULL;

	return f;
}

void mat_arp_probes_expire(struct mat_instance *inst, bool all)
{
	struct mat_arp_probe *p, *tmp;
	uint64_t now = mat_now();

	list_for_each_entry_safe(p, tmp, &inst->arp_probes, list) {
		if (!all && now - p->time < MAT_ARP_PROBE_TIMEOUT)
			continue;

		list_del(&p->list);
		inst->n_arp_probes--;
		free(p);
	}
}

static struct mat_arp_probe *
mat_arp_probe_get(struct mat_instance *inst, const uint8_t *addr)
{
	struct mat_arp_probe *p;

	list_for_each_entry(p, &inst->arp_probes, list)
		if (!memcmp(p->addr, addr, MAT_ADDR_LEN))
			return p;

	return NULL;
}

static void mat_arp_probe_add(struct mat_instance *inst, const uint8_t *addr,
			      const uint8_t *mac)
{
	struct mat_arp_probe *p;

	p = mat_arp_probe_get(inst, addr);
	if (!p) {
		if (inst->n_arp_probes >= MAT_ARP_PROBE_MAX)
			return;

		p = calloc(1, sizeof(*p));
		if (!p)
			return;

		memcpy(p->addr, addr, MAT_ADDR_LEN);
		list_add_tail(&p->list, &inst->arp_probes);
		inst->n_arp_probes++;
	}

	memcpy(p->mac, mac, ETH_ALEN);
	p->time = mat_now();
}

void mat_arp_up(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	struct mat_arp_frame *f;
	uint8_t addr[MAT_ADDR_LEN];
	bool probe;

	f = mat_arp_parse(frame, len);
	if (!f)
		goto drop;

	probe = !memcmp(f->arp.arp_spa, ip_unspec, 4);
	if (!probe) {
		mat_addr_from_ipv4(addr, f->arp.arp_spa);
		mat_binding_update(inst, addr, f->eth.ether_shost, MAT_SRC_NEIGH, 0);
	}

	/* an answer to a request of mat_arp_request() */
	if (!memcmp(f->eth.ether_dhost, inst->own_mac, ETH_ALEN))
		return;

	if (probe && f->arp.arp_op == htons(ARPOP_REQUEST)) {
		mat_addr_from_ipv4(addr, f->arp.arp_tpa);
		mat_arp_probe_add(inst, addr, f->eth.ether_shost);
	}

	memcpy(f->arp.arp_sha, inst->sta_mac, ETH_ALEN);
	mat_send_up(inst, frame, len);
	return;

drop:
	inst->dropped++;
}

void mat_arp_down(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	struct mat_arp_frame *f;
	struct mat_arp_probe *p;
	struct mat_binding *b;
	uint8_t addr[MAT_ADDR_LEN];
	const uint8_t *mac;

	f = mat_arp_parse(frame, len);
	if (!f)
		goto drop;

	mat_addr_from_ipv4(addr, f->arp.arp_spa);

	/*
	 * An AP with proxy ARP answers for the hosts behind the station, also
	 * for one whose binding is gone.
	 */
	if (!memcmp(f->arp.arp_sha, inst->sta_mac, ETH_ALEN))
		goto drop;

	if (memcmp(f->arp.arp_spa, ip_unspec, 4))
		mat_upstream_seen(inst, addr);

	if (f->eth.ether_dhost[0] & 1) {
		mat_send_down(inst, frame, len);
		return;
	}

	/* the answer to an address probe carries no usable target address */
	p = mat_arp_probe_get(inst, addr);
	if (p) {
		mac = p->mac;
	} else {
		mat_addr_from_ipv4(addr, f->arp.arp_tpa);
		b = mat_binding_get(inst, addr);
		if (!b)
			goto drop;

		mac = b->mac;
	}

	if (!memcmp(f->arp.arp_tha, inst->sta_mac, ETH_ALEN))
		memcpy(f->arp.arp_tha, mac, ETH_ALEN);
	memcpy(f->eth.ether_dhost, mac, ETH_ALEN);
	mat_send_down(inst, frame, len);
	return;

drop:
	inst->dropped++;
}

void mat_arp_request(struct mat_instance *inst, const uint8_t *addr,
		     const uint8_t *dest)
{
	struct mat_arp_frame f = {
		.eth.ether_type = htons(ETH_P_ARP),
		.arp.arp_hrd = htons(ARPHRD_ETHER),
		.arp.arp_pro = htons(ETH_P_IP),
		.arp.arp_hln = ETH_ALEN,
		.arp.arp_pln = 4,
		.arp.arp_op = htons(ARPOP_REQUEST),
	};

	if (dest)
		memcpy(f.eth.ether_dhost, dest, ETH_ALEN);
	else
		memset(f.eth.ether_dhost, 0xff, ETH_ALEN);

	memcpy(f.eth.ether_shost, inst->own_mac, ETH_ALEN);
	memcpy(f.arp.arp_sha, inst->own_mac, ETH_ALEN);
	memcpy(f.arp.arp_tpa, addr + 12, 4);
	mat_send_down(inst, (uint8_t *)&f, sizeof(f));
}
