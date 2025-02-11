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

/*
 * START interface management functions
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

/*
 * END interface management functions
 */

/*
 * START interface configuration functions
 */

/* Set WireGuard private key */
fw_err_t
wg_set_privkey(wg_handle_t *wg, const uint8_t key[MAX_KEY_LEN])
{
	struct wg_key_io kio;

	memset(&kio, 0, sizeof(kio));
	strlcpy(kio.wki_name, wg->ifname, IFNAMSIZ);
	memcpy(kio.wki_key, key, WG_KEY_LEN);

	if (ioctl(wg->sock, SIOCSWGKEY, &kio) == -1)
		return FW_ERR;

	return FW_OK;
}

/* Get WireGuard listen port */
fw_err_t
wg_get_listen_port(wg_handle_t *wg, uint16_t *port)
{
	struct wg_port_io pio;

	memset(&pio, 0, sizeof(pio));
	strlcpy(pio.wpi_name, wg->ifname, IFNAMSIZ);

	if (ioctl(wg->sock, SIOCGWGPORT, &pio) == -1)
		return FW_ERR;

	*port = pio.wpi_port;

	return FW_OK;
}

/* Set WireGuard listen port */
fw_err_t
wg_set_listen_port(wg_handle_t *wg, uint16_t port)
{
	struct wg_port_io pio;

	memset(&pio, 0, sizeof(pio));
	strlcpy(pio.wpi_name, wg->ifname, IFNAMSIZ);
	pio.wpi_port = port;

	if (ioctl(wg->sock, SIOCSWGPORT, &pio) == -1)
		return FW_ERR;

	return FW_OK;
}

/*
 * END interface configuration functions
 */

/*
 * START peer management functions
 */

/* Add WireGuard peer */
fw_err_t
wg_add_peer(wg_handle_t *wg, const struct wg_peer_io *peer)
{
	struct wg_peer_io pio;

	memcpy(&pio, peer, sizeof(pio));
	strlcpy(pio.wpi_name, wg->ifname, IFNAMSIZ);

	if (ioctl(wg->sock, SIOCAWGPEER, &pio) == -1)
		return FW_ERR;

	return FW_OK;
}

/* Delete WireGuard peer */
fw_err_t
wg_del_peer(wg_handle_t *wg, const uint8_t pubkey[WG_KEY_LEN])
{
	struct wg_peer_io pio;

	memset(&pio, 0, sizeof(pio));
	strlcpy(pio.wpi_name, wg->ifname, IFNAMSIZ);
	memcpy(pio.wpi_key, pubkey, WG_KEY_LEN);

	if (ioctl(wg->sock, SIOCAWGPEER, &pio) == -1)
		return FW_ERR;

	return FW_OK;
}

/* Get WireGuard peer info */
fw_err_t
wg_get_peer(wg_handle_t *wg, const uint8_t pubkey[WG_KEY_LEN],
    struct wg_peer_io *peer)
{
	struct wg_peer_io pio;

	memset(&pio, 0, sizeof(pio));
	strlcpy(pio.wpi_name, wg->ifname, IFNAMSIZ);
	memcpy(pio.wpi_key, pubkey, WG_KEY_LEN);

	if (ioctl(wg->sock, SIOCGWGPEER, &pio) == -1)
		return FW_ERR;

	memcpy(peer, &pio, sizeof(pio));

	return FW_OK;
}

/*
 * END peer management functions
 */

/*
 * START key management functions
 */

/* Generate WireGuard private key */
fw_err_t
wg_gen_privkey(uint8_t key[WG_KEY_LEN])
{
	int fd;
	ssize_t n;

	/* Read from OpenBSD random(4) since we can disregard portability */
	fd = open("/dev/random", O_RDONLY);
	if (fd == -1)
		return FW_ERR;

	n = read(fd, key, WG_KEY_LEN);
	close(fd);

	if (n != WG_KEY_LEN)
		return FW_ERR;

	return FW_OK;
}

/* Generate WireGuard public key from private key */
fw_err_t
wg_gen_pubkey(const uint8_t secret[WG_KEY_LEN], uint8_t public[WG_KEY_LEN])
{
	/* Use curve25519 to generate a public key */
	/* XXX: Implement curve25519 (e.g., libsodium) */
	return FW_OK;
}

/*
 * END key management functions
 */
