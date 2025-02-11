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

/* FreewayVPN error codes */
typedef enum {
	FW_OK  = 0,
	FW_ERR = -1,
} fw_err_t;

/* WireGuard interface handle */
typedef struct wg_handle {
	char ifname[IFNAMSIZ];  /* Interface name      */
	int sock;               /* Socket for ioctl(2) */
} wg_handle_t;

/* Function prototypes */
void wg_close_iface(wg_handle_t *);
fw_err_t wg_create_iface(wg_handle_t *);
fw_err_t wg_destroy_iface(wg_handle_t *);
fw_err_t wg_get_iface(wg_handle_t *, struct wg_interface_io *);
fw_err_t wg_open_iface(wg_handle_t *, const char *);
fw_err_t wg_set_iface(wg_handle_t *, struct wg_interface_io *);

#endif /* WIREGUARD_H */
