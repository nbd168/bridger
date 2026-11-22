// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BRIDGER_MAT_H
#define __BRIDGER_MAT_H

#include <errno.h>

#include "bridger-mat-bpf.h"

#define MAT_ADDR_LEN		16
#define MAT_INSTANCE_MAX	(MAT_MAX_DEVS / 2)
#define MAT_FRAME_MAX		65536

#define MAT_IDLE_TIMEOUT	(300 * 1000)
#define MAT_PROBE_TIMEOUT	2000
#define MAT_ARP_PROBE_TIMEOUT	5000
#define MAT_QUEUE_TIMEOUT	1000
#define MAT_RETRY_INTERVAL	5000
#define MAT_DHCP_XID_TIMEOUT	(60 * 1000)
#define MAT_ARP_PROBE_MAX	64
#define MAT_DHCP_XID_MAX	256
#define MAT_QUEUE_ADDR_MAX	8
#define MAT_QUEUE_MAX		64
#define MAT_UPSTREAM_MAX	256
#define MAT_BIND_MAX		(MAT_MAX_BINDINGS / MAT_INSTANCE_MAX)
#define MAT_BIND_MAC_MAX	16

enum mat_source {
	MAT_SRC_LEARN,
	MAT_SRC_NEIGH,
	MAT_SRC_DHCP,
};

enum mat_dhcp_mode {
	MAT_DHCP_BROADCAST,
	MAT_DHCP_CHADDR,
};

struct mat_binding {
	struct avl_node node;
	uint8_t addr[MAT_ADDR_LEN];
	uint8_t mac[ETH_ALEN];
	uint8_t claim_mac[ETH_ALEN];
	enum mat_source source;
	enum mat_source claim_source;
	bool probing;
	bool claim;
	uint64_t expire;
	uint64_t last_seen;
	uint64_t probe_time;
};

struct mat_instance {
	struct list_head list;

	char sta_name[IFNAMSIZ];
	char port_name[IFNAMSIZ];
	char bridge_name[IFNAMSIZ];
	enum mat_dhcp_mode dhcp_mode;

	bool active;
	unsigned int sta_ifindex;
	unsigned int port_ifindex;
	uint8_t sta_mac[ETH_ALEN];
	uint8_t own_mac[ETH_ALEN];

	struct uloop_fd tap;
	int sta_sock;
	struct uloop_timeout timer;
	struct uloop_timeout retry;
	bool carrier;
	bool sta_ipv6_disabled;
	unsigned int tick;
	unsigned int n_probing;

	struct avl_tree bindings;
	struct avl_tree upstream;
	struct list_head arp_probes;
	struct list_head queue;
	struct list_head dhcp_xids;
	unsigned int queue_len;
	unsigned int n_arp_probes;
	unsigned int n_dhcp_xids;

	uint64_t rx_up;
	uint64_t rx_down;
	uint64_t tx_up;
	uint64_t tx_down;
	uint64_t missed;
	uint64_t dropped;
};

extern const uint8_t mat_addr_v4_prefix[12];

static inline void mat_addr_from_ipv4(uint8_t *addr, const void *ip)
{
	memcpy(addr, mat_addr_v4_prefix, sizeof(mat_addr_v4_prefix));
	memcpy(addr + 12, ip, 4);
}

static inline bool mat_addr_is_ipv4(const uint8_t *addr)
{
	return !memcmp(addr, mat_addr_v4_prefix, sizeof(mat_addr_v4_prefix));
}

uint64_t mat_now(void);
const char *mat_addr_str(const uint8_t *addr);

struct blob_buf;

#ifdef MAT_SUPPORT
int bridger_mat_set(const char *sta, const char *port, const char *bridge,
		    enum mat_dhcp_mode dhcp_mode);
int bridger_mat_delete(const char *sta);
void bridger_mat_device_update(struct device *dev);
void bridger_mat_device_free(struct device *dev);
bool bridger_mat_dev_is_port(struct device *dev);
void bridger_mat_stop(void);
void bridger_mat_status(struct blob_buf *b);
#else
static inline int bridger_mat_set(const char *sta, const char *port,
				  const char *bridge,
				  enum mat_dhcp_mode dhcp_mode)
{
	return -ENOTSUP;
}
static inline int bridger_mat_delete(const char *sta)
{
	return 0;
}
static inline void bridger_mat_device_update(struct device *dev)
{
}
static inline void bridger_mat_device_free(struct device *dev)
{
}
static inline bool bridger_mat_dev_is_port(struct device *dev)
{
	return false;
}
static inline void bridger_mat_stop(void)
{
}
static inline void bridger_mat_status(struct blob_buf *b)
{
}
#endif

struct mat_binding *mat_binding_get(struct mat_instance *inst, const uint8_t *addr);
void mat_binding_update(struct mat_instance *inst, const uint8_t *addr,
			const uint8_t *mac, enum mat_source source,
			uint64_t lifetime);
void mat_binding_delete(struct mat_instance *inst, struct mat_binding *b);
void mat_binding_delete_dhcp(struct mat_instance *inst, const uint8_t *mac);
void mat_upstream_seen(struct mat_instance *inst, const uint8_t *addr);

void mat_send_up(struct mat_instance *inst, uint8_t *frame, size_t len);
void mat_send_down(struct mat_instance *inst, const uint8_t *frame, size_t len);

void mat_arp_up(struct mat_instance *inst, uint8_t *frame, size_t len);
void mat_arp_down(struct mat_instance *inst, uint8_t *frame, size_t len);
void mat_arp_request(struct mat_instance *inst, const uint8_t *addr,
		     const uint8_t *dest);
void mat_arp_probes_expire(struct mat_instance *inst, bool all);

bool mat_dhcp_match(const uint8_t *frame, size_t len);
void mat_dhcp_up(struct mat_instance *inst, uint8_t *frame, size_t len);
void mat_dhcp_down(struct mat_instance *inst, uint8_t *frame, size_t len);
void mat_dhcp_xids_expire(struct mat_instance *inst, bool all);

int mat_bpf_attach(struct mat_instance *inst);
void mat_bpf_detach(struct mat_instance *inst);
void mat_bpf_bind_set(struct mat_instance *inst, struct mat_binding *b);
void mat_bpf_bind_delete(struct mat_instance *inst, struct mat_binding *b);
uint64_t mat_bpf_bind_last_seen(struct mat_instance *inst, struct mat_binding *b);

void mat_learn_event(unsigned int sta_ifindex, const uint8_t *addr,
		     const uint8_t *mac);

#endif
