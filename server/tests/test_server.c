/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
/*
 * test_server.c - Simple test program to validate fwvpnd
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "base64.h"
#include "fwvpnd.h"
#include "wireguard.h"

int
main()
{
	struct wg_interface_io iface;
	struct wg_peer_io peer;

	uint8_t peer_privkey[WG_KEY_LEN];
	uint8_t peer_pubkey[WG_KEY_LEN];

	char b64_buf[WG_KEY_B64_LEN];

	uint8_t decoded_key[WG_KEY_LEN];
	uint8_t privkey[WG_KEY_LEN];
	uint8_t pubkey[WG_KEY_LEN];

	fw_err_t ret;
	wg_handle_t wg;

    /* Check if we're running as root */
	if (getuid() != 0)
		errx(1, "must run as root");

    /*
     * START wg(4) tests
     */
	printf("Starting wg(4) tests...\n");

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
		errx(1, "key verification: decoded key doesn't match original");

    /*
     * TEST
     */
	printf("Test get listen port...\n");
	memset(&iface, 0, sizeof(iface));
	if ((ret = wg_get_iface(&wg, &iface)) != FW_OK)
		errx(1, "wg_get_iface: failed to get interface configuration");

    /*
     * TEST
     */
	printf("Test add peer...\n");

	memset(&peer, 0, sizeof(peer));

    /* Generate peer keys */
	if ((ret = wg_gen_keypair(peer_privkey, peer_pubkey)) != FW_OK)
		errx(1, "wg_gen_keypair: failed to generate peer keypair");

    /* Configure peer */
	memcpy(peer.p_public, peer_pubkey, WG_KEY_LEN);
	peer.p_flags = WG_PEER_HAS_PUBLIC;
	if ((ret = wg_add_peer(&wg, &peer)) != FW_OK)
		errx(1, "wg_add_peer: failed to add peer");

    /*
     * TEST
     */
	printf("Test get peer...\n");
	memset(&peer, 0, sizeof(peer));
    /* Get peer */
	if ((ret = wg_get_peer(&wg, peer_pubkey, &peer)) != FW_OK)
		errx(1, "wg_get_peer: failed to get peer");

    /*
     * TEST
     */
	printf("Test verify peer public key...\n");
	if (memcmp(peer.p_public, peer_pubkey, WG_KEY_LEN) != 0)
		errx(1, "peer verification: peer public key does not match");

    /*
     * TEST
     */
	printf("Test remove peer...\n");
	if ((ret = wg_remove_peer(&wg, peer_pubkey)) != FW_OK)
		errx(1, "wg_remove_peer: failed to remove peer");

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
	if (wg.sock != -1)
		errx(1, "wg_close_iface: failed to close interface");

    /*
     * END wg(4) API tests
     */

    /*
     * START fwvpnd API tests
     */
	printf("\nStarting fwvpnd tests...\n");

    /*
     * TEST
     */
	printf("Test init fwpnvd with NULL configuration...\n");
	if ((ret = fw_init(NULL)) != FW_ERR)
		errx(1, "fw_init: fwvpnd initialized with NULL config");

    /*
     * TEST
     */
	printf("Test init fwvpnd with valid configuration...\n");
	fw_cfg_t cfg = {
		.db_path     = ":memory:",
		.listen_port = 51820,
		.wg_iface    = "wg0",
	};
	if ((ret = fw_init(&cfg)) != FW_OK)
		errx(1, "fw_init: failed to initialize with valid config");

    /*
     * TEST
     */
	printf("Test start fwvpnd...\n");
	if ((ret = fw_start()) != FW_OK)
		errx(1, "fw_start: failed to start fwvpnd");

    /*
     * TEST
     */
	printf("Test double start fwvpnd...\n");
	if ((ret = fw_start()) != FW_OK)
		errx(1, "fw_start: second start should return OK");

    /*
     * Clean up test environment
     */
	printf("\nCleaning up test environment...\n");
	if (wg_open_iface(&wg, "wg0") == FW_OK) {
		if ((ret = wg_destroy_iface(&wg)) != FW_OK)
			errx(1,
			    "wg_destroy_iface: failed to destroy interface");
		wg_close_iface(&wg);
	}

    /*
     * END fwvpnd API tests
     */

	printf("Tests completed successfully!\n");

	return 0;
}
