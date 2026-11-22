// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
/* musl only leaves struct ethhdr to its own header if that one comes first */
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <libubox/blobmsg.h>

#include "bridger.h"

#define MAT_READ_BURST		64
#define MAT_SCAN_INTERVAL	10

struct mat_upstream {
	struct avl_node node;
	uint8_t addr[MAT_ADDR_LEN];
	uint64_t time;
};

struct mat_queued {
	struct list_head list;
	uint8_t addr[MAT_ADDR_LEN];
	uint64_t time;
	size_t len;
	uint8_t data[];
};

const uint8_t mat_addr_v4_prefix[12] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
};

static LIST_HEAD(instances);
static uint8_t frame_buf[MAT_FRAME_MAX];

static const char * const source_names[] = {
	[MAT_SRC_LEARN] = "data",
	[MAT_SRC_NEIGH] = "neigh",
	[MAT_SRC_DHCP] = "dhcp",
};

uint64_t mat_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static uint64_t mat_time_diff(uint64_t later, uint64_t earlier)
{
	return later > earlier ? later - earlier : 0;
}

const char *mat_addr_str(const uint8_t *addr)
{
	static char str[INET6_ADDRSTRLEN];

	if (mat_addr_is_ipv4(addr))
		inet_ntop(AF_INET, addr + 12, str, sizeof(str));
	else
		inet_ntop(AF_INET6, addr, str, sizeof(str));

	return str;
}

static int mat_addr_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, MAT_ADDR_LEN);
}

static struct mat_instance *mat_instance_get(const char *sta)
{
	struct mat_instance *inst;

	list_for_each_entry(inst, &instances, list)
		if (!strcmp(inst->sta_name, sta))
			return inst;

	return NULL;
}

void mat_send_up(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	memcpy(frame + ETH_ALEN, inst->sta_mac, ETH_ALEN);
	if (send(inst->sta_sock, frame, len, 0) < 0) {
		inst->dropped++;
		return;
	}

	inst->tx_up++;
}

void mat_send_down(struct mat_instance *inst, const uint8_t *frame, size_t len)
{
	if (write(inst->tap.fd, frame, len) < 0) {
		inst->dropped++;
		return;
	}

	inst->tx_down++;
}

static void mat_probe(struct mat_instance *inst, struct mat_binding *b)
{
	if (mat_addr_is_ipv4(b->addr))
		mat_arp_request(inst, b->addr, b->mac);
}

static void mat_resolve(struct mat_instance *inst, const uint8_t *addr)
{
	if (mat_addr_is_ipv4(addr))
		mat_arp_request(inst, addr, NULL);
}

static void mat_queue_free(struct mat_instance *inst, struct mat_queued *q)
{
	list_del(&q->list);
	inst->queue_len--;
	free(q);
}

static void mat_queue_flush(struct mat_instance *inst, struct mat_binding *b)
{
	struct mat_queued *q, *tmp;

	list_for_each_entry_safe(q, tmp, &inst->queue, list) {
		if (memcmp(q->addr, b->addr, MAT_ADDR_LEN))
			continue;

		memcpy(q->data, b->mac, ETH_ALEN);
		mat_send_down(inst, q->data, q->len);
		mat_queue_free(inst, q);
	}
}

static void mat_queue_expire(struct mat_instance *inst, bool all)
{
	struct mat_queued *q, *tmp;
	uint64_t now = mat_now();

	list_for_each_entry_safe(q, tmp, &inst->queue, list) {
		if (!all && now - q->time < MAT_QUEUE_TIMEOUT)
			continue;

		inst->missed++;
		mat_queue_free(inst, q);
	}
}

static bool mat_addr_group_mac(const uint8_t *addr, uint8_t *mac)
{
	if (!mat_addr_is_ipv4(addr)) {
		mac[0] = 0x33;
		mac[1] = 0x33;
		memcpy(&mac[2], &addr[12], 4);
		return addr[0] == 0xff;
	}

	if (addr[12] == 0xff) {
		memset(mac, 0xff, ETH_ALEN);
		return true;
	}

	mac[0] = 0x01;
	mac[1] = 0x00;
	mac[2] = 0x5e;
	mac[3] = addr[13] & 0x7f;
	mac[4] = addr[14];
	mac[5] = addr[15];

	return (addr[12] & 0xf0) == 0xe0;
}

/*
 * A frame from the station that the programs did not forward. Its address
 * can have a binding: the programs also pass a frame on that they take for
 * a control frame, and a binding can be newer than the frame.
 */
static void mat_forward_down(struct mat_instance *inst, const uint8_t *addr,
			     uint8_t *frame, size_t len)
{
	uint8_t mac[ETH_ALEN];
	struct mat_binding *b;
	struct mat_queued *q;
	unsigned int n = 0;

	if (frame[0] & 1) {
		mat_send_down(inst, frame, len);
		return;
	}

	b = mat_binding_get(inst, addr);
	if (b || mat_addr_group_mac(addr, mac)) {
		memcpy(frame, b ? b->mac : mac, ETH_ALEN);
		mat_send_down(inst, frame, len);
		return;
	}

	list_for_each_entry(q, &inst->queue, list)
		if (!memcmp(q->addr, addr, MAT_ADDR_LEN))
			n++;

	if (n >= MAT_QUEUE_ADDR_MAX || inst->queue_len >= MAT_QUEUE_MAX) {
		inst->missed++;
		return;
	}

	q = malloc(sizeof(*q) + len);
	if (!q)
		return;

	memcpy(q->addr, addr, MAT_ADDR_LEN);
	memcpy(q->data, frame, len);
	q->len = len;
	q->time = mat_now();
	list_add_tail(&q->list, &inst->queue);
	inst->queue_len++;

	if (!n)
		mat_resolve(inst, addr);
}

static bool mat_upstream_fresh(struct mat_instance *inst, const uint8_t *addr)
{
	struct mat_upstream *u;

	u = avl_find_element(&inst->upstream, addr, u, node);

	return u && mat_now() - u->time < MAT_IDLE_TIMEOUT;
}

static void mat_upstream_free(struct mat_instance *inst, struct mat_upstream *u)
{
	avl_delete(&inst->upstream, &u->node);
	free(u);
}

static void mat_upstream_expire(struct mat_instance *inst, bool all)
{
	struct mat_upstream *u, *tmp;
	uint64_t now = mat_now();

	avl_for_each_element_safe(&inst->upstream, u, node, tmp)
		if (all || now - u->time >= MAT_IDLE_TIMEOUT)
			mat_upstream_free(inst, u);
}

static struct mat_upstream *mat_upstream_oldest(struct mat_instance *inst)
{
	struct mat_upstream *u, *oldest = NULL;

	avl_for_each_element(&inst->upstream, u, node)
		if (!oldest || u->time < oldest->time)
			oldest = u;

	if (oldest)
		avl_delete(&inst->upstream, &oldest->node);

	return oldest;
}

void mat_upstream_seen(struct mat_instance *inst, const uint8_t *addr)
{
	struct mat_upstream *u;

	if (mat_binding_get(inst, addr))
		return;

	u = avl_find_element(&inst->upstream, addr, u, node);
	if (u) {
		u->time = mat_now();
		return;
	}

	if (inst->upstream.count >= MAT_UPSTREAM_MAX)
		u = mat_upstream_oldest(inst);
	else
		u = calloc(1, sizeof(*u));
	if (!u)
		return;

	memcpy(u->addr, addr, MAT_ADDR_LEN);
	u->node.key = u->addr;
	u->time = mat_now();
	avl_insert(&inst->upstream, &u->node);
}

struct mat_binding *mat_binding_get(struct mat_instance *inst, const uint8_t *addr)
{
	struct mat_binding *b;

	return avl_find_element(&inst->bindings, addr, b, node);
}

static void mat_binding_probe_done(struct mat_instance *inst, struct mat_binding *b)
{
	if (!b->probing)
		return;

	b->probing = false;
	b->claim = false;
	inst->n_probing--;
}

static void mat_binding_probe_start(struct mat_instance *inst, struct mat_binding *b)
{
	b->probing = true;
	b->probe_time = mat_now();
	inst->n_probing++;
	mat_probe(inst, b);
}

void mat_binding_delete(struct mat_instance *inst, struct mat_binding *b)
{
	D("%s: delete %s\n", inst->sta_name, mat_addr_str(b->addr));
	mat_binding_probe_done(inst, b);
	mat_bpf_bind_delete(inst, b);
	avl_delete(&inst->bindings, &b->node);
	free(b);
}

void mat_binding_delete_dhcp(struct mat_instance *inst, const uint8_t *mac)
{
	struct mat_binding *b, *tmp;

	avl_for_each_element_safe(&inst->bindings, b, node, tmp)
		if (b->source == MAT_SRC_DHCP && !memcmp(b->mac, mac, ETH_ALEN))
			mat_binding_delete(inst, b);
}

static void mat_binding_assign(struct mat_instance *inst, struct mat_binding *b,
			       const uint8_t *mac, enum mat_source source,
			       uint64_t lifetime)
{
	uint64_t now = mat_now();

	D("%s: bind %s to %s (%s)\n", inst->sta_name, mat_addr_str(b->addr),
	  format_macaddr(mac), source_names[source]);

	mat_binding_probe_done(inst, b);
	memcpy(b->mac, mac, ETH_ALEN);
	b->source = source;
	b->expire = lifetime ? now + lifetime : 0;
	b->last_seen = now;
	mat_bpf_bind_set(inst, b);
	mat_queue_flush(inst, b);
}

static bool mat_binding_limit(struct mat_instance *inst, const uint8_t *mac)
{
	struct mat_binding *b;
	unsigned int n = 0;

	if (inst->bindings.count >= MAT_BIND_MAX)
		return true;

	avl_for_each_element(&inst->bindings, b, node)
		if (!memcmp(b->mac, mac, ETH_ALEN))
			n++;

	return n >= MAT_BIND_MAC_MAX;
}

void mat_binding_update(struct mat_instance *inst, const uint8_t *addr,
			const uint8_t *mac, enum mat_source source,
			uint64_t lifetime)
{
	struct mat_binding *b;
	uint64_t now = mat_now();

	if ((mac[0] & 1) || !memcmp(mac, inst->sta_mac, ETH_ALEN) ||
	    !memcmp(mac, inst->own_mac, ETH_ALEN))
		return;

	if (source != MAT_SRC_DHCP && mat_upstream_fresh(inst, addr))
		return;

	b = mat_binding_get(inst, addr);
	if (!b) {
		if (mat_binding_limit(inst, mac))
			return;

		b = calloc(1, sizeof(*b));
		if (!b)
			return;

		memcpy(b->addr, addr, MAT_ADDR_LEN);
		b->node.key = b->addr;
		avl_insert(&inst->bindings, &b->node);
		mat_binding_assign(inst, b, mac, source, lifetime);
		return;
	}

	if (!memcmp(b->mac, mac, ETH_ALEN)) {
		mat_binding_probe_done(inst, b);
		b->last_seen = now;
		if (source < b->source)
			return;

		b->source = source;
		if (source == MAT_SRC_DHCP)
			b->expire = lifetime ? now + lifetime : 0;
		return;
	}

	if (source == MAT_SRC_DHCP || source > b->source) {
		mat_binding_assign(inst, b, mac, source, lifetime);
		return;
	}

	if (b->probing) {
		if (b->claim && source < b->claim_source)
			return;
	} else {
		mat_binding_probe_start(inst, b);
	}

	b->claim = true;
	b->claim_source = source;
	memcpy(b->claim_mac, mac, ETH_ALEN);
}

void mat_learn_event(unsigned int sta_ifindex, const uint8_t *addr,
		     const uint8_t *mac)
{
	struct mat_instance *inst;

	list_for_each_entry(inst, &instances, list) {
		if (!inst->active || inst->sta_ifindex != sta_ifindex)
			continue;

		mat_binding_update(inst, addr, mac, MAT_SRC_LEARN, 0);
		return;
	}
}

static void mat_bindings_probe_check(struct mat_instance *inst)
{
	struct mat_binding *b, *tmp;
	uint64_t now = mat_now();

	avl_for_each_element_safe(&inst->bindings, b, node, tmp) {
		if (!b->probing || now - b->probe_time < MAT_PROBE_TIMEOUT)
			continue;

		if (b->claim)
			mat_binding_assign(inst, b, b->claim_mac, b->claim_source, 0);
		else
			mat_binding_delete(inst, b);
	}
}

static void mat_bindings_scan(struct mat_instance *inst)
{
	struct mat_binding *b;
	uint64_t now = mat_now();
	uint64_t seen;

	avl_for_each_element(&inst->bindings, b, node) {
		if (b->probing)
			continue;

		if (b->expire && now >= b->expire) {
			b->expire = 0;
			b->source = MAT_SRC_NEIGH;
		}

		if (b->expire)
			continue;

		seen = mat_bpf_bind_last_seen(inst, b);
		if (seen > b->last_seen)
			b->last_seen = seen;

		if (b->last_seen + MAT_IDLE_TIMEOUT <= now)
			mat_binding_probe_start(inst, b);
	}
}

static void mat_timer_cb(struct uloop_timeout *t)
{
	struct mat_instance *inst = container_of(t, struct mat_instance, timer);

	mat_arp_probes_expire(inst, false);
	mat_dhcp_xids_expire(inst, false);
	mat_queue_expire(inst, false);

	if (inst->n_probing)
		mat_bindings_probe_check(inst);

	if (++inst->tick % MAT_SCAN_INTERVAL == 0) {
		mat_bindings_scan(inst);
		mat_upstream_expire(inst, false);
	}

	uloop_timeout_set(t, 1000);
}

static void mat_handle_ipv4(struct mat_instance *inst, uint8_t *frame,
			    size_t len, bool down)
{
	uint8_t addr[MAT_ADDR_LEN];

	if (len < sizeof(struct ether_header) + 20)
		goto drop;

	if (mat_dhcp_match(frame, len)) {
		if (down)
			mat_dhcp_down(inst, frame, len);
		else
			mat_dhcp_up(inst, frame, len);
		return;
	}

	if (!down)
		goto drop;

	mat_addr_from_ipv4(addr, frame + sizeof(struct ether_header) + 16);
	mat_forward_down(inst, addr, frame, len);
	return;

drop:
	inst->dropped++;
}

static void mat_handle_frame(struct mat_instance *inst, uint8_t *frame, size_t len)
{
	static const uint8_t tag[] = {
		ETH_P_8021AD >> 8, ETH_P_8021AD & 0xff,
		MAT_TAG_TCI >> 8, MAT_TAG_TCI & 0xff
	};
	struct ether_header *eth;
	bool down = false;

	if (len < sizeof(*eth))
		return;

	if (len >= sizeof(*eth) + sizeof(tag) &&
	    !memcmp(frame + 2 * ETH_ALEN, tag, sizeof(tag))) {
		memmove(frame + sizeof(tag), frame, 2 * ETH_ALEN);
		frame += sizeof(tag);
		len -= sizeof(tag);
		down = true;
	}

	eth = (struct ether_header *)frame;
	if (down) {
		inst->rx_down++;
	} else {
		inst->rx_up++;
		if ((eth->ether_shost[0] & 1) ||
		    !memcmp(eth->ether_shost, inst->sta_mac, ETH_ALEN))
			goto drop;
	}

	switch (ntohs(eth->ether_type)) {
	case ETH_P_ARP:
		if (down)
			mat_arp_down(inst, frame, len);
		else
			mat_arp_up(inst, frame, len);
		return;
	case ETH_P_IP:
		mat_handle_ipv4(inst, frame, len, down);
		return;
	default:
		break;
	}

drop:
	inst->dropped++;
}

static void mat_tap_cb(struct uloop_fd *fd, unsigned int events)
{
	struct mat_instance *inst = container_of(fd, struct mat_instance, tap);
	ssize_t len;
	int i;

	for (i = 0; i < MAT_READ_BURST; i++) {
		len = read(fd->fd, frame_buf, sizeof(frame_buf));
		if (len <= 0)
			break;

		mat_handle_frame(inst, frame_buf, len);
	}
}

static bool mat_ipv6_disable(const char *ifname, bool disable)
{
	char path[64 + IFNAMSIZ];
	char old = '1';
	int fd;

	snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", ifname);
	fd = open(path, O_RDWR);
	if (fd < 0)
		return true;

	if (pread(fd, &old, 1, 0) != 1)
		old = '1';

	if (pwrite(fd, disable ? "1" : "0", 1, 0) < 0)
		D("Failed to set disable_ipv6 on %s\n", ifname);
	close(fd);

	return old != '0';
}

static int mat_tap_open(struct mat_instance *inst)
{
	struct ifreq ifr = {};
	int fd, sock;
	int ret = -1;
	int err;

	fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
		return -1;

	sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock < 0)
		goto error;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inst->port_name);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(fd, TUNSETIFF, &ifr))
		goto error;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr))
		goto error;

	/*
	 * The bridge holds the port's address as a local FDB entry, so the
	 * daemon's own frames need a different source address.
	 */
	memcpy(inst->own_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	inst->own_mac[5] ^= 1;

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inst->sta_name);
	if (!ioctl(sock, SIOCGIFMTU, &ifr)) {
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inst->port_name);
		ioctl(sock, SIOCSIFMTU, &ifr);
	}

	mat_ipv6_disable(inst->port_name, true);

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inst->port_name);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr))
		goto error;

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(sock, SIOCSIFFLAGS, &ifr))
		goto error;

	inst->port_ifindex = if_nametoindex(inst->port_name);
	if (!inst->port_ifindex)
		goto error;

	if (inst->bridge_name[0]) {
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", inst->bridge_name);
		ifr.ifr_ifindex = inst->port_ifindex;
		if (ioctl(sock, SIOCBRADDIF, &ifr))
			goto error;
	}

	inst->tap.fd = fd;
	ret = 0;

error:
	err = errno;
	if (sock >= 0)
		close(sock);
	if (ret)
		close(fd);
	errno = err;

	return ret;
}

static int mat_sta_open(struct mat_instance *inst)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_ifindex = inst->sta_ifindex,
	};
	struct packet_mreq mreq = {
		.mr_ifindex = inst->sta_ifindex,
		.mr_type = PACKET_MR_ALLMULTI,
	};
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll))) {
		close(fd);
		return -1;
	}

	setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	inst->sta_sock = fd;

	return 0;
}

static void mat_instance_flush(struct mat_instance *inst)
{
	struct mat_binding *b, *tmp;

	avl_for_each_element_safe(&inst->bindings, b, node, tmp)
		mat_binding_delete(inst, b);

	mat_upstream_expire(inst, true);
	mat_arp_probes_expire(inst, true);
	mat_dhcp_xids_expire(inst, true);
	mat_queue_expire(inst, true);
}

static void mat_instance_stop(struct mat_instance *inst)
{
	if (!inst->active)
		return;

	D("Stop client bridge %s\n", inst->sta_name);

	inst->active = false;
	uloop_timeout_cancel(&inst->timer);
	uloop_fd_delete(&inst->tap);

	mat_instance_flush(inst);
	mat_bpf_detach(inst);
	if (!inst->sta_ipv6_disabled)
		mat_ipv6_disable(inst->sta_name, false);

	close(inst->sta_sock);
	close(inst->tap.fd);
	inst->sta_ifindex = 0;
	inst->port_ifindex = 0;
}

static void mat_instance_start(struct mat_instance *inst, struct device *dev)
{
	if (inst->active)
		return;

	uloop_timeout_cancel(&inst->retry);
	inst->sta_ifindex = device_ifindex(dev);
	inst->carrier = dev->carrier;
	memcpy(inst->sta_mac, dev->addr, ETH_ALEN);

	if (mat_tap_open(inst)) {
		D("Failed to create port %s: %s\n", inst->port_name, strerror(errno));
		goto error;
	}

	if (mat_sta_open(inst)) {
		D("Failed to open %s: %s\n", inst->sta_name, strerror(errno));
		goto close_tap;
	}

	if (mat_bpf_attach(inst))
		goto close_sta;

	D("Start client bridge %s on port %s\n", inst->sta_name, inst->port_name);

	inst->sta_ipv6_disabled = mat_ipv6_disable(inst->sta_name, true);
	inst->active = true;
	inst->tap.cb = mat_tap_cb;
	uloop_fd_add(&inst->tap, ULOOP_READ);
	inst->timer.cb = mat_timer_cb;
	uloop_timeout_set(&inst->timer, 1000);
	return;

close_sta:
	close(inst->sta_sock);
close_tap:
	close(inst->tap.fd);
error:
	inst->sta_ifindex = 0;
	inst->port_ifindex = 0;
	uloop_timeout_set(&inst->retry, MAT_RETRY_INTERVAL);
}

/* the bridge of the port can appear after the station */
static void mat_retry_cb(struct uloop_timeout *t)
{
	struct mat_instance *inst = container_of(t, struct mat_instance, retry);
	struct device *dev;

	dev = device_get_by_name(inst->sta_name);
	if (dev)
		mat_instance_start(inst, dev);
}

void bridger_mat_device_update(struct device *dev)
{
	struct mat_instance *inst;

	inst = mat_instance_get(dev->ifname);
	if (!inst)
		return;

	if (inst->active &&
	    (inst->sta_ifindex != device_ifindex(dev) ||
	     memcmp(inst->sta_mac, dev->addr, ETH_ALEN)))
		mat_instance_stop(inst);

	/* a new link can be a link to another network */
	if (inst->active && dev->carrier && !inst->carrier)
		mat_instance_flush(inst);

	inst->carrier = dev->carrier;
	mat_instance_start(inst, dev);
}

void bridger_mat_device_free(struct device *dev)
{
	struct mat_instance *inst;

	list_for_each_entry(inst, &instances, list) {
		if (!inst->active)
			continue;

		if (inst->sta_ifindex == device_ifindex(dev)) {
			mat_instance_stop(inst);
			continue;
		}

		if (inst->port_ifindex != device_ifindex(dev))
			continue;

		mat_instance_stop(inst);
		uloop_timeout_set(&inst->retry, MAT_RETRY_INTERVAL);
	}
}

bool bridger_mat_dev_is_port(struct device *dev)
{
	struct mat_instance *inst;

	list_for_each_entry(inst, &instances, list)
		if (inst->active && inst->port_ifindex == device_ifindex(dev))
			return true;

	return false;
}

static void mat_instance_free(struct mat_instance *inst)
{
	mat_instance_stop(inst);
	uloop_timeout_cancel(&inst->retry);
	list_del(&inst->list);
	free(inst);
}

static unsigned int mat_instance_count(void)
{
	struct mat_instance *inst;
	unsigned int n = 0;

	list_for_each_entry(inst, &instances, list)
		n++;

	return n;
}

int bridger_mat_delete(const char *sta)
{
	struct mat_instance *inst;

	inst = mat_instance_get(sta);
	if (!inst)
		return -ENOENT;

	mat_instance_free(inst);

	return 0;
}

int bridger_mat_set(const char *sta, const char *port, const char *bridge,
		    enum mat_dhcp_mode dhcp_mode)
{
	struct mat_instance *inst;
	struct device *dev;

	if (strlen(sta) >= IFNAMSIZ || strlen(port) >= IFNAMSIZ ||
	    strlen(bridge) >= IFNAMSIZ)
		return -EINVAL;

	inst = mat_instance_get(sta);
	if (inst && !strcmp(inst->port_name, port) &&
	    !strcmp(inst->bridge_name, bridge)) {
		inst->dhcp_mode = dhcp_mode;
		return 0;
	}

	if (inst)
		mat_instance_free(inst);
	else if (mat_instance_count() >= MAT_INSTANCE_MAX)
		return -ENOSPC;

	inst = calloc(1, sizeof(*inst));
	if (!inst)
		return -ENOMEM;

	strcpy(inst->sta_name, sta);
	strcpy(inst->port_name, port);
	strcpy(inst->bridge_name, bridge);
	inst->dhcp_mode = dhcp_mode;
	avl_init(&inst->bindings, mat_addr_cmp, false, NULL);
	avl_init(&inst->upstream, mat_addr_cmp, false, NULL);
	INIT_LIST_HEAD(&inst->arp_probes);
	INIT_LIST_HEAD(&inst->queue);
	INIT_LIST_HEAD(&inst->dhcp_xids);
	inst->retry.cb = mat_retry_cb;
	list_add_tail(&inst->list, &instances);

	dev = device_get_by_name(sta);
	if (dev)
		mat_instance_start(inst, dev);

	return 0;
}

void bridger_mat_stop(void)
{
	struct mat_instance *inst, *tmp;

	list_for_each_entry_safe(inst, tmp, &instances, list)
		mat_instance_free(inst);
}

static void mat_status_bindings(struct mat_instance *inst, struct blob_buf *b)
{
	struct mat_binding *bind;
	uint64_t now = mat_now();
	void *c, *e;

	c = blobmsg_open_array(b, "bindings");
	avl_for_each_element(&inst->bindings, bind, node) {
		e = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "address", mat_addr_str(bind->addr));
		blobmsg_add_string(b, "mac", format_macaddr(bind->mac));
		blobmsg_add_string(b, "source", source_names[bind->source]);
		blobmsg_add_u32(b, "age", mat_time_diff(now, bind->last_seen) / 1000);
		if (bind->expire)
			blobmsg_add_u32(b, "expires", mat_time_diff(bind->expire, now) / 1000);
		if (bind->probing)
			blobmsg_add_u8(b, "probing", 1);
		blobmsg_close_table(b, e);
	}
	blobmsg_close_array(b, c);
}

void bridger_mat_status(struct blob_buf *b)
{
	struct mat_instance *inst;
	void *c, *e;

	c = blobmsg_open_table(b, "client_bridge");
	list_for_each_entry(inst, &instances, list) {
		e = blobmsg_open_table(b, inst->sta_name);
		blobmsg_add_string(b, "port", inst->port_name);
		if (inst->bridge_name[0])
			blobmsg_add_string(b, "bridge", inst->bridge_name);
		blobmsg_add_string(b, "dhcp_mode",
				   inst->dhcp_mode == MAT_DHCP_CHADDR ? "chaddr" : "broadcast");
		blobmsg_add_u8(b, "active", inst->active);
		blobmsg_add_u64(b, "rx_up", inst->rx_up);
		blobmsg_add_u64(b, "rx_down", inst->rx_down);
		blobmsg_add_u64(b, "tx_up", inst->tx_up);
		blobmsg_add_u64(b, "tx_down", inst->tx_down);
		blobmsg_add_u64(b, "missed", inst->missed);
		blobmsg_add_u64(b, "dropped", inst->dropped);
		if (inst->active)
			mat_status_bindings(inst, b);
		blobmsg_close_table(b, e);
	}
	blobmsg_close_table(b, c);
}
