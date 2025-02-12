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

#include <sodium.h>

#include "base64.h"
#include "wireguard.h"

/*
 * START wg(4) interface functions
 */

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

/*
 * END wg(4) interface functions
 */

/*
 * START key management functions
 */

/* Generate keypair */
fw_err_t
wg_gen_keypair(uint8_t privkey[WG_KEY_LEN], uint8_t pubkey[WG_KEY_LEN])
{
    if (sodium_init() < 0)
        return FW_ERR;

    crypto_box_keypair(pubkey, privkey);

    return FW_OK;
}

/* Get interface public key */
fw_err_t
wg_get_pubkey(wg_handle_t *wg, uint8_t key[WG_KEY_LEN])
{
    struct wg_interface_io iface;

    memset(&iface, 0, sizeof(iface));
    if (wg_get_iface(wg, &iface) != FW_OK)
        return FW_ERR;

    if (!(iface.i_flags & WG_INTERFACE_HAS_PUBLIC))
        return FW_ERR;

    /* (void *) or uint8_t? */
    memcpy((void *)key, iface.i_public, WG_KEY_LEN);

    return FW_OK;
}

/* Set interface private key */
fw_err_t
wg_set_privkey(wg_handle_t *wg, const uint8_t key[WG_KEY_LEN])
{
    struct wg_interface_io iface;

    memset(&iface, 0, sizeof(iface));
    iface.i_flags = WG_INTERFACE_HAS_PRIVATE;
    memcpy(iface.i_private, key, WG_KEY_LEN);

    return wg_set_iface(wg, &iface);
}

/* Convert key to base64 */
fw_err_t
wg_key_to_b64(char *dst, size_t dstlen, uint8_t key[WG_KEY_LEN])
{
    int len;

    if (dstlen < WG_KEY_B64_LEN)
        return FW_ERR;

    /* See server/src/base64/b64_ntop.c */
    len = b64_ntop(key, WG_KEY_LEN, dst, dstlen);
    if (len == -1)
        return FW_ERR;

    return FW_OK;
}

/* Convert base64 to key */
fw_err_t
wg_key_from_b64(uint8_t key[WG_KEY_LEN], const char *src)
{
    int len;

    /* See server/src/base64/b64_pton.c */
    len = b64_pton(src, key, WG_KEY_LEN);
    if (len == -1 || len != WG_KEY_LEN)
        return FW_ERR;

    return FW_OK;
}

/*
 * END key management functions
 */
