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

	struct device *master;

	struct list_head member_list;

	struct list_head fdb_entries;

	struct bridge *br;

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

enum device_type device_lookup_type(const char *type);
struct device *device_get(int ifindex);
struct device *device_create(int ifindex, enum device_type type, const char *name);
void device_set_bridge(struct device *dev, bool enabled);
void device_vlan_add(struct device *dev, struct vlan *vlan);
void device_vlan_remove(struct device *dev, int id);
int device_vlan_get_input(struct device *dev, uint16_t xdp_vlan);
uint16_t device_vlan_get_output(struct device *dev, int vid);
void device_update(struct device *dev);
void device_free(struct device *dev);

#endif
