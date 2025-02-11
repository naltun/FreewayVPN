/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef FWVPND_H
#define FWVPND_H

#include <sys/types.h>
#include <sqlite3.h>

/* Max lengths for various fields */
#define MAX_EMAIL_LEN  254  /* RFC 5321             */
#define MAX_IP_LEN     16   /* IPv4                 */
#define MAX_KEY_LEN    64   /* Private / Public key */
#define MAX_TOKEN_LEN  512  /* JSON web token       */

/* Error codes */
typedef enum {
	FW_OK       = 0,
	FW_ERR      = -1,
	FW_AUTH_ERR = -2,
	FW_DB_ERR   = -3,
	FW_WG_ERR   = -4,
} fw_err_t;

/* Server configuration */
typedef struct {
	char *db_path;      /* Path to SQLite DB          */
	char *listen_addr;  /* HTTP server listen address */
	int listen_port;    /* HTTP server port           */
	char *server_addr;  /* VPN server address         */
	char *vpn_subnet;   /* VPN subnet (CIDR)          */
	char *wg_if;        /* WireGuard interface name   */
} fw_cfg_t;

/* Server context */
typedef struct {
	fw_cfg_t config;   /* FreewayVPN server config */
	sqlite3 *db_conn;  /* Database connection      */
	void *wg_handle;   /* Wireguard control handle */
} fw_ctx_t;

/* Function prototypes */
void fw_cleanup(void);
fw_err_t fw_init(fw_cfg_t *);
fw_err_t fw_start(void);

#endif /* FWVPND_H */
