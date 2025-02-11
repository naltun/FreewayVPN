/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_wg.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "wireguard.h"

/* Close WireGuard interface handle */
void
wg_close_iface(wg_handle_t *wg)
{
	if (wg->sock != -1) {
		close(wg->sock);
		wg->sock = -1;
	}
}

/* Create WireGuard interface */
fw_err_t
wg_create_iface(wg_handle_t *wg)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, wg->ifname, IFNAMSIZ);

	if (ioctl(wg->sock, SIOCIFCREATE, &ifr) == -1)
		return FW_ERR;

	return FW_OK;
}

/* Destroy WireGuard interface */
fw_err_t
wg_destroy_iface(wg_handle_t *wg)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, wg->ifname, IFNAMSIZ);

	if (ioctl(wg->sock, SIOCIFDESTROY, &ifr) == -1)
		return FW_ERR;

	return FW_OK;
}

/* Get WireGuard interface configuration */
fw_err_t
wg_get_iface(wg_handle_t *wg, struct wg_interface_io *iface)
{
	struct wg_data_io dio;

	memset(&dio, 0, sizeof(dio));
	strlcpy(dio.wgd_name, wg->ifname, IFNAMSIZ);
	dio.wgd_interface = iface;
	dio.wgd_size = sizeof(*iface);

	if (ioctl(wg->sock, SIOCGWG, &dio) == -1)
		return FW_ERR;

	return FW_OK;
}

/* Open WireGuard interface handle */
fw_err_t
wg_open_iface(wg_handle_t *wg, const char *ifname)
{
	if (strlen(ifname) >= IFNAMSIZ) {
		errno = EINVAL;
		return FW_ERR;
	}

	wg->sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (wg->sock == -1)
		return FW_ERR;

	strlcpy(wg->ifname, ifname, IFNAMSIZ);

	return FW_OK;
}

/* Set WireGuard interface configuration */
fw_err_t
wg_set_iface(wg_handle_t *wg, struct wg_interface_io *iface)
{
	struct wg_data_io dio;

	memset(&dio, 0, sizeof(dio));
	strlcpy(dio.wgd_name, wg->ifname, IFNAMSIZ);
	dio.wgd_interface = iface;
	dio.wgd_size = sizeof(*iface);

	if (ioctl(wg->sock, SIOCSWG, &dio) == -1)
		return FW_ERR;

	return FW_OK;
}
