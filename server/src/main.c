/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fwvpnd.h"

/* Global fwvpnd (daemon) context */
static fw_ctx_t g_fw_ctx;
/* Default configuration */
static fw_cfg_t g_fw_cfg = {
	.db_path     = "/var/fwvpn/db/vpn.db",
	.listen_addr = "127.0.0.1",
	.listen_port = 8080,
	.server_addr = "10.0.0.1",
	.vpn_subnet  = "10.0.0.0/24",
	.wg_if       = "wg0",
};

static void
usage(int exitcode)
{
	fprintf(exitcode > 0 ? stderr : stdout, "usage: fwvpnd [-h]\n");
	exit(exitcode);
}

int
main(int argc, char *argv[])
{
	int ch;

	/* Parse argv */
	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			usage(0);
		default:
			usage(1);
		}
	}

	argc -= optind;
	argv += optind;

	/* OpenBSD pledge(2) */
	if (pledge("stdio dns inet rpath wpath", NULL) == -1)
		err(1, "pledge");

	/* Initialize server */
	if (fw_init(&g_fw_cfg) != FW_OK)
		err(1, "fw_init: failed to initialize server");

	/* Start server */
	if (fw_start() != FW_OK)
		err(1, "fw_start: failed to start server");

	/* Cleanup on exit */
	fw_cleanup();

	return 0;
}
