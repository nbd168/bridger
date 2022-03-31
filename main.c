// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */

#include "bridger.h"

int debug_level = 0;

const char *format_macaddr(const uint8_t *mac)
{
	static char str[sizeof("ff:ff:ff:ff:ff:ff ")];

	snprintf(str, sizeof(str), "%02x:%02x:%02x:%02x:%02x:%02x",
	mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return str;
}

int main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug_level++;
			break;
		default:
			break;
		}
	}

	uloop_init();

	if (bridger_bpf_init()) {
		perror("bridger_bpf_init");
		return 1;
	}

	if (bridger_nl_init()) {
		perror("bridger_nl_init");
		return 1;
	}

	bridger_device_init();
	bridger_flow_init();

	uloop_run();

	bridger_device_stop();

	uloop_done();

	return 0;
}
