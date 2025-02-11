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
#include <unistd.h>

#include "fwvpnd.h"
#include "wireguard.h"

int
main()
{
    uint16_t port;
    fw_err_t ret;
    wg_handle_t wg;

    /* Check if we're running as root */
    if (getuid() != 0)
        err(1, "must run as root");

    /* Test opening wg0 interface */
    printf("Opening WireGuard interface wg0...\n");
    if ((ret = wg_open_iface(&wg, "wg0")) != FW_OK)
        err(1, "failed to open WireGuard interface");

    /* Test creating wg0 interface */
    printf("Creating WireGuard interface...\n");
    if ((ret = wg_create_iface(&wg)) != FW_OK)
        err(1, "failed to create WireGuard interface");

    /* Set WireGuard listen port to 51820 */
    printf("Setting listen port to 51820...\n");
    if ((ret = wg_set_listen_port(&wg, 51820)) != FW_OK)
        err(1, "failed to set listen port");

    /* Verify listen port */
    printf("Verifying listen port...\n");
    if ((ret = wg_get_listen_port(&wg, &port)) != FW_OK)
        err(1, "failed to get listen port");

    printf("Listening on port %u\n", port);

    /* Clean up */
    printf("Destroying interface...\n");
    if ((ret = wg_destroy_iface(&wg)) != FW_OK)
        err(1, "failed to destroy interface");

    /* Close WireGuard interface handle */
    wg_close_iface(&wg);

    printf("Tests completed successfully!\n");

    return 0;
}
