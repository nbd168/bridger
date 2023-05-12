// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */

#include <fnmatch.h>

#include <libubox/kvlist.h>
#include <libubus.h>

#include "bridger.h"

static struct ubus_auto_conn conn;
static KVLIST(blacklist, kvlist_blob_len);

bool bridger_ubus_dev_blacklisted(struct device *dev)
{
	struct blob_attr *list, *cur;
	const char *name;
	int rem;

	kvlist_for_each(&blacklist, name, list)
		blobmsg_for_each_attr(cur, list, rem) {
			if (!fnmatch(blobmsg_get_string(cur), dev->ifname, 0))
				return true;
			if (dev->master &&
			    !fnmatch(blobmsg_get_string(cur), dev->master->ifname, 0))
				return true;
		}

	return false;
}

static void bridger_blacklist_update(void)
{
	struct device *dev;

	avl_for_each_element(&devices, dev, node) {
		if (dev->attached ==
		    (dev->master && !bridger_ubus_dev_blacklisted(dev)))
			continue;

		device_update(dev);
	}
}

enum {
	BRIDGER_BLACKLIST_NAME,
	BRIDGER_BLACKLIST_DEVICES,
	__BRIDGER_BLACKLIST_MAX
};

static const struct blobmsg_policy blacklist_policy[__BRIDGER_BLACKLIST_MAX] = {
	[BRIDGER_BLACKLIST_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[BRIDGER_BLACKLIST_DEVICES] = { "devices", BLOBMSG_TYPE_ARRAY },
};

static int
bridger_set_blacklist(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct blob_attr *tb[__BRIDGER_BLACKLIST_MAX];
	const char *name;
	void *prev;
	bool changed;

	blobmsg_parse(blacklist_policy, __BRIDGER_BLACKLIST_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!tb[BRIDGER_BLACKLIST_NAME] || !tb[BRIDGER_BLACKLIST_DEVICES])
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (blobmsg_check_array(tb[BRIDGER_BLACKLIST_DEVICES], BLOBMSG_TYPE_STRING) < 0)
		return UBUS_STATUS_INVALID_ARGUMENT;

	name = blobmsg_get_string(tb[BRIDGER_BLACKLIST_NAME]);
	prev = kvlist_get(&blacklist, name);
	changed = !blob_attr_equal(prev, tb[BRIDGER_BLACKLIST_DEVICES]);
	kvlist_set(&blacklist, name, tb[BRIDGER_BLACKLIST_DEVICES]);

	if (changed)
		bridger_blacklist_update();

	return 0;
}

enum {
	BRIDGER_DEVCFG_NAME,
	BRIDGER_DEVCFG_REDIRECT,
	__BRIDGER_DEVCFG_MAX,
};

static const struct blobmsg_policy devcfg_policy[__BRIDGER_DEVCFG_MAX] = {
	[BRIDGER_DEVCFG_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[BRIDGER_DEVCFG_REDIRECT] = { "redirect", BLOBMSG_TYPE_STRING },
};

static int
bridger_set_device_config(struct ubus_context *ctx, struct ubus_object *obj,
			  struct ubus_request_data *req, const char *method,
			  struct blob_attr *msg)
{
	struct blob_attr *tb[__BRIDGER_DEVCFG_MAX], *cur;
	unsigned int redirect_dev = 0;
	struct device *dev;


	blobmsg_parse(devcfg_policy, __BRIDGER_DEVCFG_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[BRIDGER_DEVCFG_NAME]) == NULL)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((dev = device_get_by_name(blobmsg_get_string(cur))) == NULL)
		return UBUS_STATUS_NOT_FOUND;

	if ((cur = tb[BRIDGER_DEVCFG_REDIRECT]) != NULL &&
	    !(redirect_dev = if_nametoindex(blobmsg_get_string(cur))))
		return UBUS_STATUS_NOT_FOUND;

	if (device_set_redirect(dev, redirect_dev))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return 0;
}

static const struct ubus_method bridger_methods[] = {
	UBUS_METHOD("set_blacklist", bridger_set_blacklist, blacklist_policy),
	UBUS_METHOD("set_device_config", bridger_set_device_config, devcfg_policy),
};

static struct ubus_object_type bridger_object_type =
	UBUS_OBJECT_TYPE("bridger", bridger_methods);

static struct ubus_object bridger_object = {
	.name = "bridger",
	.type = &bridger_object_type,
	.methods = bridger_methods,
	.n_methods = ARRAY_SIZE(bridger_methods),
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &bridger_object);
}

int bridger_ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);

	return 0;
}

void bridger_ubus_stop(void)
{
	ubus_auto_shutdown(&conn);
}
