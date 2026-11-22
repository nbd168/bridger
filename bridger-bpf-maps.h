// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BRIDGER_BPF_MAPS_H
#define __BRIDGER_BPF_MAPS_H

#include "bridger-bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(pinning, 1);
	__type(key, struct bridger_flow_key);
	__type(value, struct bridger_offload_flow);
	__uint(max_entries, BRIDGER_OFFLOAD_FLOWS);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} offload_flows SEC(".maps");

#endif
