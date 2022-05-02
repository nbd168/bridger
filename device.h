// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __BRIDGER_DEVICE_H
#define __BRIDGER_DEVICE_H

enum device_type {
	DEVICE_TYPE_ETHERNET,
	DEVICE_TYPE_VLAN,
	DEVICE_TYPE_BRIDGE,
	__DEVICE_TYPE_MAX
};

struct device {
	struct avl_node node;
	int master_ifindex;

	enum device_type type;
	char ifname[IFNAMSIZ];

	uint8_t addr[ETH_ALEN];

	bool has_clsact;
	bool attached;
	bool update;
	bool cleanup;
	bool offload_update;

	struct device *master;
	struct device *offload_dev;

	struct list_head member_list;

	struct list_head fdb_entries;

	struct bridge *br;

	uint8_t phys_switch_id[32];
	uint8_t phys_switch_id_len;
	int pvid;

	int n_vlans;
	struct vlan *vlan;
};

struct bridge {
	struct device *dev;

	struct list_head members;
	uint16_t vlan_proto;
	bool vlan_enabled;

	struct avl_tree fdb;
};

struct vlan {
	union {
		struct {
			uint16_t id : 12;
			uint16_t untagged : 1;
			uint16_t pvid : 1;
			uint16_t tunnel : 1;
		};
		uint16_t data;
	};
};

int bridger_device_init(void);
void bridger_device_stop(void);

static inline int device_ifindex(struct device *dev)
{
	return (uintptr_t)dev->node.key;
}

static inline bool
device_match_phys_switch(struct device *dev1, struct device *dev2)
{
	return dev1->phys_switch_id_len &&
	       dev1->phys_switch_id_len == dev2->phys_switch_id_len &&
	       !memcmp(dev1->phys_switch_id, dev2->phys_switch_id,
		       dev1->phys_switch_id_len);
}

extern struct avl_tree devices;
enum device_type device_lookup_type(const char *type);
struct device *device_get(int ifindex);
struct device *device_create(int ifindex, enum device_type type, const char *name);
void device_set_bridge(struct device *dev, bool enabled);
void device_vlan_add(struct device *dev, struct vlan *vlan);
void device_vlan_remove(struct device *dev, int id);
int device_vlan_get_input(struct device *dev, uint16_t xdp_vlan);
uint16_t device_vlan_get_output(struct device *dev, int vid);
void device_update(struct device *dev);
void device_reset_offload_update(void);
void device_free(struct device *dev);

#endif
