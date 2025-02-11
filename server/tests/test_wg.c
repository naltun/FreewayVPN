/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 *
 * test_wg.c - Simple test program to validate WireGuard API
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wireguard.h"

int
main()
{
	struct wg_interface_io iface;
	fw_err_t ret;
	wg_handle_t wg;

    /* Check if we're running as root */
	if (getuid() != 0)
		err(1, "must run as root");

    /*
     * 1
     */
	printf("Test open wg0 interface...\n");
	if ((ret = wg_open_iface(&wg, "wg0")) != FW_OK)
		err(1, "wg_open_iface: failed to open WireGuard interface");

    /*
     * 2
     */
	printf("Test create wg0 interface...\n");
	if ((ret = wg_create_iface(&wg)) != FW_OK)
		err(1, "wg_create_iface: failed to create WireGuard interface");

    /*
     * 3
     */
	printf("Test configure interface with port 51820...\n");
	memset(&iface, 0, sizeof(iface));
	iface.i_flags = WG_INTERFACE_HAS_PORT;
	iface.i_port = 51820;
	if ((ret = wg_set_iface(&wg, &iface)) != FW_OK)
		err(1, "wg_set_iface: failed to configure interface with port");

    /*
     * 4
     */
	printf("Test get listen port...\n");
	memset(&iface, 0, sizeof(iface));
	if ((ret = wg_get_iface(&wg, &iface)) != FW_OK)
		err(1, "wg_get_iface: failed to get interface configuration");

    /*
     * 5 -- destroy interface before closing it to prevent EEXIST error
     */
	printf("Test destroy wg0 interface...\n");
	if ((ret = wg_destroy_iface(&wg)) != FW_OK)
		err(1, "wg_destroy_iface: failed to destroy interface");

    /*
     * 6
     */
	printf("Test close wg0 interface...\n");
	wg_close_iface(&wg);

	printf("\nTests completed successfully!\n");

	return 0;
}
