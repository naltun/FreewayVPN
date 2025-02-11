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

/* WireGuard interface handle */
typedef struct wg_handle {
	int sock;               /* Socket for ioctl(2) */
	char ifname[IFNAMSIZ];  /* Interface name */
} wg_handle_t;

/* Function prototypes */

/* Interface management */
void wg_close_iface(wg_handle_t *);
fw_err_t wg_create_iface(wg_handle_t *);
fw_err_t wg_destroy_iface(wg_handle_t *);
fw_err_t wg_open_iface(wg_handle_t *, const char *);

/* Interface configuration */
fw_err_t wg_set_privkey(wg_handle_t *, const uint8_t[WG_KEY_LEN]);
fw_err_t wg_get_listen_port(wg_handle_t *, uint16_t *);
fw_err_t wg_set_listen_port(wg_handle_t *, uint16_t);

/* WireGuard peer management */
fw_err_t wg_add_peer(wg_handle_t *, const struct wg_peer_io *);
fw_err_t wg_del_peer(wg_handle_t *, const uint8_t[WG_KEY_LEN]);
fw_err_t wg_get_peer(wg_handle_t *, const uint8_t[WG_KEY_LEN], struct wg_peer_io *);

/* WireGuard key management */
fw_err_t wg_gen_privkey(uint8_t[WG_KEY_LEN]);
fw_err_t wg_gen_pubkey(const uint8_t, uint8_t[WG_KEY_LEN]);

#endif /* WIREGUARD_H */
