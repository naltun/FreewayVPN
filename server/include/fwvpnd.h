/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#ifndef FWVPND_H
#define FWVPND_H

#include <sys/types.h>

#include <time.h>

#include <sqlite3.h>

#include "common.h"

/* Max lengths for various fields */
#define MAX_EMAIL_LEN  254  /* RFC 5321             */
#define MAX_IP_LEN     16   /* IPv4                 */
#define MAX_KEY_LEN    64   /* Private / Public key */
#define MAX_TOKEN_LEN  512  /* JSON web token       */

/* Peer statuses */
typedef enum {
	FW_PEER_CONNECTED    = 0,
	FW_PEER_DISCONNECTED = 1,
	FW_PEER_ERR          = 2,
} fw_peerstate_t;

/* fwvpnd running states */
typedef enum {
	FW_STATE_ERROR   = 0,
	FW_STATE_RUNNING = 1,
	FW_STATE_STOPPED = 2,
} fw_daemonstate_t;

/* fwvpnd configuration */
typedef struct {
	char *db_path;      /* Path to SQLite DB        */
	char *listen_addr;  /* server listen address    */
	int listen_port;    /* server port              */
	char *server_addr;  /* server address           */
	char *vpn_subnet;   /* subnet (CIDR)            */
	char *wg_iface;     /* WireGuard interface name */
} fw_cfg_t;

/* fwvpnd (daemon) context */
typedef struct {
	size_t peer_count;       /* Number of active peers   */
	void *wg_handle;         /* Wireguard control handle */
	sqlite3 *db_conn;        /* Database connection      */
	fw_cfg_t config;         /* FreewayVPN server config */
	fw_daemonstate_t state;  /* FreewayVPN daemon state  */
} fw_ctx_t;

/* Peer information context */
typedef struct {
	char allowed_ips[MAX_IP_LEN];  /* Allowed IP addresses        */
	time_t last_handshake;         /* Time of last peer handshake */
	char pubkey[MAX_KEY_LEN];      /* Peer public WireGuard key   */
	fw_peerstate_t state;          /* Peer connect state          */
} fw_peer_t;

/*
 * Function prototypes
 */

/* Peer management */
fw_err_t fw_add_peer(fw_ctx_t *, const char *, const char *);
fw_err_t fw_get_peer(fw_ctx_t *, const char *, fw_peer_t *);
fw_err_t fw_remove_peer(fw_ctx_t *, const char *);
fw_err_t fw_list_peers(fw_ctx_t *, fw_peer_t **, size_t *);

/* Server management */
void fw_cleanup(void);
fw_err_t fw_init(fw_cfg_t *);
fw_err_t fw_start(void);

/* Metrics */
fw_err_t fw_get_server_status(fw_ctx_t *, fw_daemonstate_t *);
fw_err_t fw_get_server_stats(fw_ctx_t *, size_t *, size_t *);

#endif /* FWVPND_H */
