// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <glob.h>
#include <libubox/utils.h>
#include "bridger.h"

static int device_avl_cmp(const void *k1, const void *k2, void *ptr)
{
	return (uintptr_t)k1 - (uintptr_t)k2;
}

static AVL_TREE(devices, device_avl_cmp, false, NULL);
static bool init_done = false;

static const char * const device_types[__DEVICE_TYPE_MAX] = {
	[DEVICE_TYPE_ETHERNET] = "ethernet",
	[DEVICE_TYPE_VLAN] = "vlan",
	[DEVICE_TYPE_BRIDGE] = "bridge",
};

enum device_type device_lookup_type(const char *type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(device_types); i++)
		if (!strcmp(type, device_types[i]))
			return i;

	return DEVICE_TYPE_ETHERNET;
}

struct device *device_get(int ifindex)
{
	struct device *dev;

	if (!ifindex)
		return NULL;

	return avl_find_element(&devices, (void *)(uintptr_t)ifindex, dev, node);
}

int device_vlan_get_input(struct device *dev, uint16_t bpf_vlan)
{
	struct device *master = dev->master;
	int i;

	if (!master || !master->br || !master->br->vlan_enabled)
		return 0;

	if (!(bpf_vlan & BRIDGER_VLAN_PRESENT) ||
	    !!(bpf_vlan & BRIDGER_VLAN_TYPE_AD) !=
	    (master->br->vlan_proto == ETH_P_8021AD))
		return dev->pvid;

	bpf_vlan &= BRIDGER_VLAN_ID;
	for (i = 0; i < dev->n_vlans; i++)
		if (bpf_vlan == dev->vlan[i].id)
			return bpf_vlan;

	return dev->pvid;
}

uint16_t device_vlan_get_output(struct device *dev, int vid)
{
	struct device *master = dev->master;
	uint16_t flags = 0;
	int i;

	if (!master || !master->br)
		return 0;

	for (i = 0; i < dev->n_vlans; i++) {
		if (vid != dev->vlan[i].id)
			continue;

		if (dev->vlan[i].untagged)
			return 0;

		flags = BRIDGER_VLAN_PRESENT;
		if (master->br->vlan_proto == ETH_P_8021AD)
			flags |= BRIDGER_VLAN_TYPE_AD;

		return vid | flags;
	}

	return 0;
}

struct device *device_create(int ifindex, enum device_type type, const char *name)
{
	struct device *dev;

	dev = device_get(ifindex);
	if (dev) {
		if (dev->type == type)
			goto out;

		device_free(dev);
	}


	D("Create %s device %s, ifindex=%d\n", device_types[type], name, ifindex);
	dev = calloc(1, sizeof(*dev));
	dev->type = type;
	dev->node.key = (void *)(uintptr_t)ifindex;
	avl_insert(&devices, &dev->node);
	INIT_LIST_HEAD(&dev->fdb_entries);
	INIT_LIST_HEAD(&dev->member_list);

	if (type == DEVICE_TYPE_BRIDGE) {
		struct bridge *br = calloc(1, sizeof(*br));

		INIT_LIST_HEAD(&br->members);
		fdb_init(br);
		dev->br = br;
		br->dev = dev;
	}

out:
	snprintf(dev->ifname, sizeof(dev->ifname), "%s", name);
	return dev;
}

static void device_clear_flows(struct device *dev)
{
	struct fdb_entry *f;

	list_for_each_entry(f, &dev->fdb_entries, dev_list)
		fdb_clear_flows(f);
}

void device_free(struct device *dev)
{
	D("Free device %s\n", dev->ifname);

	avl_delete(&devices, &dev->node);
	device_clear_flows(dev);
	if (dev->master) {
		bridger_nl_device_detach(dev);
		list_del(&dev->member_list);
	}
	free(dev->vlan);
	free(dev);
}

static struct device *device_get_offload_dev(struct device *dev)
{
	char path[128];
	char *name;
	glob_t g;
	int index;

	snprintf(path, sizeof(path), "/sys/class/net/%s/lower_*", dev->ifname);
	dev = NULL;
	glob(path, GLOB_NOSORT, NULL, &g);
	if (g.gl_pathc != 1)
		goto out;

	name = strrchr(g.gl_pathv[0], '/');
	if (!name)
		goto out;

	name += 7;
	index = if_nametoindex(name);
	if (!index)
		goto out;

	dev = device_get(index);

out:
	globfree(&g);
	return dev;
}

void device_update(struct device *dev)
{
	struct device *master, *odev;

	if (!init_done)
		return;

	device_clear_flows(dev);
	master = device_get(dev->master_ifindex);
	if (dev->master != master) {
		if (!list_empty(&dev->member_list))
			list_del_init(&dev->member_list);
	}

	if (master) {
		if (master->br)
			list_add_tail(&dev->member_list, &master->br->members);
		else
			master = NULL;
	}

	if (!!master != !!dev->master) {
		if (master)
			bridger_nl_device_attach(dev);
		else
			bridger_nl_device_detach(dev);
	}

	if (dev->master != master)
		D("Set device %s master to %s\n", dev->ifname,
		  master ? master->ifname : "(none)");

	dev->master = master;

	odev = device_get_offload_dev(dev);
	if (odev != dev->offload_dev)
		D("Set device %s offload device to %s\n", dev->ifname,
		  odev ? odev->ifname : "(none)");

	dev->offload_dev = odev;
}

static int device_vlan_index(struct device *dev, int id)
{
	int i;

	for (i = 0; i < dev->n_vlans; i++)
		if (dev->vlan[i].id == id)
			return i;

	return -1;
}

void device_vlan_add(struct device *dev, struct vlan *vlan)
{
	int i;

	i = device_vlan_index(dev, vlan->id);
	if (i >= 0) {
		if (!memcmp(&dev->vlan[i], vlan, sizeof(*vlan)))
			return;

		memcpy(&dev->vlan[i], vlan, sizeof(*vlan));
		D("Update vlan %s%s%d on device %s\n",
		  vlan->untagged ? "untaggged " : "",
		  vlan->pvid ? "pvid " : "",
		  vlan->id, dev->ifname);
		goto out;
	}


	D("Add vlan %s%s%d to device %s\n",
	  vlan->untagged ? "untaggged " : "",
	  vlan->pvid ? "pvid " : "",
	  vlan->id, dev->ifname);

	dev->n_vlans++;
	dev->vlan = realloc(dev->vlan, dev->n_vlans * sizeof(*vlan));
	memcpy(&dev->vlan[dev->n_vlans - 1], vlan, sizeof(*vlan));

out:
	if (vlan->pvid)
		dev->pvid = vlan->id;

	device_update(dev);
}

void device_vlan_remove(struct device *dev, int id)
{
	int i;

	i = device_vlan_index(dev, id);
	if (i < 0)
		return;

	D("Remove vlan %d from device %s\n", id, dev->ifname);
	if (id == dev->pvid)
		dev->pvid = 0;

	dev->n_vlans--;
	if (id >= dev->n_vlans)
		return;

	memmove(&dev->vlan[i], &dev->vlan[i + 1],
		(dev->n_vlans - id) * sizeof(*dev->vlan));
	device_update(dev);

	if (dev->n_vlans)
		return;

	free(dev->vlan);
	dev->vlan = NULL;
}

int bridger_device_init(void)
{
	struct device *dev;

	init_done = true;

	avl_for_each_element(&devices, dev, node)
		device_update(dev);

	return 0;
}

void bridger_device_stop(void)
{
	struct device *dev, *tmp;

	avl_for_each_element_safe(&devices, dev, node, tmp)
		device_free(dev);
}
