// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BRIDGER_MAT_BPF_H
#define __BRIDGER_MAT_BPF_H

#define MAT_TAG_TCI		0x0fff
#define MAT_ETH_P_PROBE		0x88b5

#define MAT_MAX_DEVS		16
#define MAT_MAX_BINDINGS	8192
#define MAT_EVENT_SLOTS		256
#define MAT_EVENT_INTERVAL_NS	1000000000ULL
#define MAT_MAX_PREFIXES	128

#define MAT_DEV_BLOCKED		(1 << 0)

struct mat_dev {
	uint32_t sta_ifindex;
	uint32_t port_ifindex;
	uint8_t sta_mac[6];
	uint8_t flags;
	uint8_t pad;
};

struct mat_prefix_key {
	uint32_t prefixlen;
	uint32_t sta_ifindex;
	uint8_t addr[16];
};

struct mat_bind_key {
	uint32_t sta_ifindex;
	uint8_t addr[16];
};

struct mat_bind {
	uint8_t mac[6];
	uint16_t flags;
	uint64_t last_seen;
};

struct mat_event {
	uint32_t sta_ifindex;
	uint8_t addr[16];
	uint8_t mac[6];
	uint8_t pad[2];
};

#endif
