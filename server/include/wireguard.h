/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_wg.h>

#include "common.h"

/* Base64-encoded WireGuard key length (with nullbyte) */
#define WG_KEY_B64_LEN 45

/* Maximum allowed peers */
#define WG_PEERS_MAX 1024

/* WireGuard interface handle */
typedef struct wg_handle {
	char ifname[IFNAMSIZ];  /* Interface name      */
	int sock;               /* Socket for ioctl(2) */
} wg_handle_t;

/*
 * Function prototypes
 */

/* wg(4) interface */
void wg_close_iface(wg_handle_t *);
fw_err_t wg_create_iface(wg_handle_t *);
fw_err_t wg_destroy_iface(wg_handle_t *);
fw_err_t wg_get_iface(wg_handle_t *, struct wg_interface_io *);
fw_err_t wg_open_iface(wg_handle_t *, const char *);
fw_err_t wg_set_iface(wg_handle_t *, struct wg_interface_io *);

/* Key management */
fw_err_t wg_gen_keypair(uint8_t [WG_KEY_LEN], uint8_t [WG_KEY_LEN]);
fw_err_t wg_get_pubkey(wg_handle_t *, uint8_t [WG_KEY_LEN]);
fw_err_t wg_set_privkey(wg_handle_t *, const uint8_t [WG_KEY_LEN]);

/* Peer management */
fw_err_t wg_add_peer(wg_handle_t *, struct wg_peer_io *);
fw_err_t wg_remove_peer(wg_handle_t *, const uint8_t [WG_KEY_LEN]);
fw_err_t wg_get_peer(wg_handle_t *, const uint8_t [WG_KEY_LEN],
    struct wg_peer_io *);

/* Helpers */
fw_err_t wg_key_to_b64(char *, size_t, uint8_t [WG_KEY_LEN]);
fw_err_t wg_key_from_b64(uint8_t [WG_KEY_LEN], const char *);

#endif /* WIREGUARD_H */
