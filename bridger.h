// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BRIDGER_H
#define __BRIDGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <libubox/uloop.h>
#include <libubox/list.h>
#include <libubox/avl.h>
#include <libubox/utils.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bridger-bpf.h"
#include "device.h"
#include "flow.h"
#include "fdb.h"
#include "bpf.h"

#define D(format, ...) \
	do { \
		if (debug_level) \
			fprintf(stderr, "%s(%d) " format, __func__, __LINE__, ##__VA_ARGS__); \
	} while(0)

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

#define BRIDGER_PROG_PATH	"/lib/bpf/bridger-bpf.o"
#define BRIDGER_PIN_PATH	"/sys/fs/bpf/bridger"
#define BRIDGER_DATA_PATH	"/sys/fs/bpf/bridger_data"

#define BRIDGER_EWMA_SHIFT	8

extern int debug_level;

static inline void bridger_ewma(uint64_t *avg, uint32_t val)
{
	if (*avg)
		*avg = (*avg * 3) / 4 + ((uint64_t)val << BRIDGER_EWMA_SHIFT) / 4;
	else
		*avg = (uint64_t)val << BRIDGER_EWMA_SHIFT;
}

int bridger_nl_init(void);
const char *format_macaddr(const uint8_t *mac);

int bridger_nl_set_bpf_prog(int ifindex, int fd);

#endif
