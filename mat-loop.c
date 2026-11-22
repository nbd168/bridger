// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/random.h>
#include <arpa/inet.h>
#include <string.h>

#include "bridger.h"

/*
 * Two client bridges between one LAN and one upstream network forward each
 * other's group frames in a loop. Each instance sends a probe with its id to
 * the upstream side. A probe that returns on the LAN side shows the loop, and
 * the instance with the higher id stops.
 */

#define MAT_LOOP_INTERVAL	5
#define MAT_LOOP_TIMEOUT	(3 * MAT_LOOP_INTERVAL * 1000)

struct mat_loop_frame {
	struct ether_header eth;
	uint8_t magic[4];
	uint64_t id;
	uint8_t pad[34];
} __attribute__((packed));

static const uint8_t loop_magic[4] = { 'b', 'm', 'a', 't' };

static void mat_loop_set_blocked(struct mat_instance *inst, bool blocked)
{
	if (inst->blocked == blocked)
		return;

	D("%s: %s\n", inst->sta_name,
	  blocked ? "loop to the upstream network, stop" : "loop is gone, resume");
	inst->blocked = blocked;
	mat_bpf_dev_set(inst);
}

void mat_loop_init(struct mat_instance *inst)
{
	inst->loop_time = 0;
	inst->loop_foreign_time = 0;
	if (getrandom(&inst->loop_id, sizeof(inst->loop_id), 0) != sizeof(inst->loop_id))
		inst->loop_id = mat_now() ^ ((uint64_t)inst->sta_ifindex << 32);
}

void mat_loop_probe(struct mat_instance *inst)
{
	struct mat_loop_frame f = {
		.eth.ether_type = htons(MAT_ETH_P_PROBE),
		.id = inst->loop_id,
	};

	memset(f.eth.ether_dhost, 0xff, ETH_ALEN);
	memcpy(f.magic, loop_magic, sizeof(f.magic));
	mat_tx_up(inst, (uint8_t *)&f, sizeof(f));
}

void mat_loop_tick(struct mat_instance *inst)
{
	if (inst->blocked && mat_now() - inst->loop_time >= MAT_LOOP_TIMEOUT)
		mat_loop_set_blocked(inst, false);

	if (inst->tick % MAT_LOOP_INTERVAL == 0)
		mat_loop_probe(inst);
}

void mat_loop_frame(struct mat_instance *inst, uint8_t *frame, size_t len,
		    bool down)
{
	struct mat_loop_frame *f = (struct mat_loop_frame *)frame;
	uint64_t now = mat_now();

	if (len < offsetof(struct mat_loop_frame, pad) ||
	    memcmp(f->magic, loop_magic, sizeof(f->magic)))
		return;

	if (down) {
		inst->loop_foreign_id = f->id;
		inst->loop_foreign_time = now;

		/*
		 * Only a running instance closes the loop. If a stopped one
		 * passed the probe on as well, the other instance would see
		 * its own id and stop too.
		 */
		if (!inst->blocked)
			mat_tx_down(inst, frame, len);
		return;
	}

	if (f->id != inst->loop_id)
		return;

	inst->loop_time = now;
	if (inst->loop_foreign_time &&
	    now - inst->loop_foreign_time < MAT_LOOP_TIMEOUT &&
	    inst->loop_foreign_id > inst->loop_id)
		return;

	mat_loop_set_blocked(inst, true);
}
