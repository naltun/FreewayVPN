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

#include "base64.h"
#include "wireguard.h"

int
main()
{
	char b64_buf[WG_KEY_B64_LEN];
	uint8_t decoded_key[WG_KEY_LEN];
	uint8_t pubkey[WG_KEY_LEN];
	uint8_t privkey[WG_KEY_LEN];

	struct wg_interface_io iface;
	fw_err_t ret;
	wg_handle_t wg;

    /* Check if we're running as root */
	if (getuid() != 0)
		errx(1, "must run as root");

    /*
     * TEST
     */
	printf("Test open wg0 interface...\n");
	if ((ret = wg_open_iface(&wg, "wg0")) != FW_OK)
		errx(1, "wg_open_iface: failed to open interface");

    /*
     * TEST
     */
	printf("Test create wg0 interface...\n");
	if ((ret = wg_create_iface(&wg)) != FW_OK)
		errx(1, "wg_create_iface: failed to create interface");

    /*
     * TEST
     */
	printf("Test configure interface with port 51820...\n");
	memset(&iface, 0, sizeof(iface));
	iface.i_flags = WG_INTERFACE_HAS_PORT;
	iface.i_port = 51820;
	if ((ret = wg_set_iface(&wg, &iface)) != FW_OK)
		errx(1, "wg_set_iface: failed to configure interface");

    /*
     * TEST
     */
	printf("Test generate keypair...\n");
	if ((ret = wg_gen_keypair(privkey, pubkey)) != FW_OK)
		errx(1, "wg_gen_keypair: failed to generate keypair");

    /*
     * TEST
     */
	printf("Test set private key...\n");
	if ((ret = wg_set_privkey(&wg, privkey)) != FW_OK)
		errx(1, "wg_set_privkey: failed to set private key");

    /*
     * TEST
     */
	printf("Test get public key...\n");
	if ((ret = wg_get_pubkey(&wg, pubkey)) != FW_OK)
		errx(1, "wg_get_pubkey: failed to get public key");

    /*
     * TEST
     */
	printf("Test encode private key to base64...\n");
	if ((ret = wg_key_to_b64(b64_buf, sizeof(b64_buf), privkey)) != FW_OK)
		errx(1, "wg_key_to_b64: failed to encode private key");

    /*
     * TEST
     */
	printf("Test decode private key from base64...\n");
	if ((ret = wg_key_from_b64(decoded_key, b64_buf)) != FW_OK)
		errx(1, "wg_key_from_b64: failed to decode private key");

    /*
     * TEST
     */
	printf("Test decoded key matches original...\n");
	if (memcmp(privkey, decoded_key, WG_KEY_LEN) != 0)
		errx(1,
		    "key verification: decoded key doesn't match original\n");

    /*
     * TEST
     */
	printf("Test get listen port...\n");
	memset(&iface, 0, sizeof(iface));
	if ((ret = wg_get_iface(&wg, &iface)) != FW_OK)
		errx(1, "wg_get_iface: failed to get interface configuration");

    /*
     * TEST -- destroy interface before closing it to prevent EEXIST error
     */
	printf("Test destroy wg0 interface...\n");
	if ((ret = wg_destroy_iface(&wg)) != FW_OK)
		errx(1, "wg_destroy_iface: failed to destroy interface");

    /*
     * TEST
     */
	printf("Test close wg0 interface...\n");
	wg_close_iface(&wg);

	printf("\nTests completed successfully!\n");

	return 0;
}
