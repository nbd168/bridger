// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "bridger.h"

static struct bpf_object *obj;
static struct ring_buffer *events;
static struct uloop_fd events_fd;
static int map_dev = -1;
static int map_bind = -1;
static int map_prefix = -1;
static int prog_up_fd = -1;
static int prog_down_fd = -1;
static int prog_sta_out_fd = -1;

static int mat_bpf_event_cb(void *ctx, void *data, size_t size)
{
	struct mat_event *ev = data;

	if (size < sizeof(*ev))
		return 0;

	mat_learn_event(ev->sta_ifindex, ev->addr, ev->mac);

	return 0;
}

static void mat_bpf_events_cb(struct uloop_fd *fd, unsigned int flags)
{
	ring_buffer__consume(events);
}

static int mat_bpf_prog_fd(const char *name)
{
	struct bpf_program *prog;

	prog = bpf_object__find_program_by_name(obj, name);
	if (!prog) {
		D("Can't find program %s\n", name);
		return -1;
	}

	return bpf_program__fd(prog);
}

static int mat_bpf_load(void)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.pin_root_path = BRIDGER_DATA_PATH,
	);
	struct bpf_program *prog;
	int map_events;

	if (obj)
		return 0;

	obj = bpf_object__open_file(BRIDGER_MAT_PROG_PATH, &opts);
	if (libbpf_get_error(obj)) {
		D("Failed to open %s\n", BRIDGER_MAT_PROG_PATH);
		obj = NULL;
		return -1;
	}

	bpf_object__for_each_program(prog, obj)
		bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

	if (bpf_object__load(obj)) {
		D("Failed to load %s\n", BRIDGER_MAT_PROG_PATH);
		goto error;
	}

	map_dev = bpf_object__find_map_fd_by_name(obj, "mat_dev");
	map_bind = bpf_object__find_map_fd_by_name(obj, "mat_bind");
	map_prefix = bpf_object__find_map_fd_by_name(obj, "mat_prefix");
	map_events = bpf_object__find_map_fd_by_name(obj, "mat_events");
	prog_up_fd = mat_bpf_prog_fd("mat_up");
	prog_down_fd = mat_bpf_prog_fd("mat_down");
	prog_sta_out_fd = mat_bpf_prog_fd("mat_sta_out");
	if (map_dev < 0 || map_bind < 0 || map_prefix < 0 || map_events < 0 ||
	    prog_up_fd < 0 || prog_down_fd < 0 || prog_sta_out_fd < 0)
		goto error;

	events = ring_buffer__new(map_events, mat_bpf_event_cb, NULL, NULL);
	if (!events)
		goto error;

	events_fd.fd = ring_buffer__epoll_fd(events);
	events_fd.cb = mat_bpf_events_cb;
	uloop_fd_add(&events_fd, ULOOP_READ);

	return 0;

error:
	bpf_object__close(obj);
	obj = NULL;
	return -1;
}

static void mat_bpf_key(struct mat_instance *inst, struct mat_binding *b,
			struct mat_bind_key *key)
{
	memset(key, 0, sizeof(*key));
	key->sta_ifindex = inst->sta_ifindex;
	memcpy(key->addr, b->addr, sizeof(key->addr));
}

void mat_bpf_bind_set(struct mat_instance *inst, struct mat_binding *b)
{
	struct mat_bind_key key;
	struct mat_bind val = {};

	mat_bpf_key(inst, b, &key);
	bpf_map_lookup_elem(map_bind, &key, &val);
	memcpy(val.mac, b->mac, ETH_ALEN);
	bpf_map_update_elem(map_bind, &key, &val, BPF_ANY);
}

void mat_bpf_bind_delete(struct mat_instance *inst, struct mat_binding *b)
{
	struct mat_bind_key key;

	mat_bpf_key(inst, b, &key);
	bpf_map_delete_elem(map_bind, &key);
}

uint64_t mat_bpf_bind_last_seen(struct mat_instance *inst, struct mat_binding *b)
{
	struct mat_bind_key key;
	struct mat_bind val;

	mat_bpf_key(inst, b, &key);
	if (bpf_map_lookup_elem(map_bind, &key, &val))
		return 0;

	return val.last_seen / 1000000;
}

static void mat_bpf_detach_filters(struct mat_instance *inst)
{
	bridger_nl_bpf_detach(inst->sta_ifindex, BRIDGER_PRIO_MAT, true);
	bridger_nl_bpf_detach(inst->sta_ifindex, BRIDGER_PRIO_MAT, false);
	bridger_nl_bpf_detach(inst->port_ifindex, BRIDGER_PRIO_MAT, false);
}

static void mat_bpf_prefix_key(struct mat_instance *inst, struct mat_prefix *p,
			       struct mat_prefix_key *key)
{
	memset(key, 0, sizeof(*key));
	key->prefixlen = 8 * sizeof(key->sta_ifindex) + p->len;
	key->sta_ifindex = inst->sta_ifindex;
	memcpy(key->addr, p->addr, sizeof(key->addr));
}

void mat_bpf_prefix_set(struct mat_instance *inst, struct mat_prefix *p)
{
	struct mat_prefix_key key;
	struct mat_bind val = {};

	mat_bpf_prefix_key(inst, p, &key);
	memcpy(val.mac, p->mac, ETH_ALEN);
	bpf_map_update_elem(map_prefix, &key, &val, BPF_ANY);
}

void mat_bpf_prefix_delete(struct mat_instance *inst, struct mat_prefix *p)
{
	struct mat_prefix_key key;

	mat_bpf_prefix_key(inst, p, &key);
	bpf_map_delete_elem(map_prefix, &key);
}

int mat_bpf_dev_set(struct mat_instance *inst)
{
	struct mat_dev dev = {
		.sta_ifindex = inst->sta_ifindex,
		.port_ifindex = inst->port_ifindex,
		.flags = inst->blocked ? MAT_DEV_BLOCKED : 0,
	};

	memcpy(dev.sta_mac, inst->sta_mac, ETH_ALEN);
	if (bpf_map_update_elem(map_dev, &inst->sta_ifindex, &dev, BPF_ANY) ||
	    bpf_map_update_elem(map_dev, &inst->port_ifindex, &dev, BPF_ANY))
		return -1;

	return 0;
}

int mat_bpf_attach(struct mat_instance *inst)
{
	if (mat_bpf_load())
		return -1;

	if (mat_bpf_dev_set(inst))
		goto error;

	if (bridger_nl_bpf_attach(inst->sta_ifindex, prog_down_fd, BRIDGER_PRIO_MAT, true) ||
	    bridger_nl_bpf_attach(inst->sta_ifindex, prog_sta_out_fd, BRIDGER_PRIO_MAT, false) ||
	    bridger_nl_bpf_attach(inst->port_ifindex, prog_up_fd, BRIDGER_PRIO_MAT, false))
		goto error;

	return 0;

error:
	D("Failed to attach client bridge %s: %s\n", inst->sta_name, strerror(errno));
	mat_bpf_detach(inst);
	return -1;
}

void mat_bpf_detach(struct mat_instance *inst)
{
	if (!obj)
		return;

	mat_bpf_detach_filters(inst);
	bpf_map_delete_elem(map_dev, &inst->sta_ifindex);
	bpf_map_delete_elem(map_dev, &inst->port_ifindex);
}
