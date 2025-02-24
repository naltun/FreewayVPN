/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fwvpnd.h"
#include "wireguard.h"

/* Global fwvpnd (daemon) context */
static fw_ctx_t *g_fw_ctx = NULL;

/* Initialize fwvpnd */
fw_err_t
fw_init(fw_cfg_t *g_fw_cfg)
{
	wg_handle_t *wg;

	if (g_fw_cfg == NULL)
		return FW_ERR;

    /* Initialize global fwvpnd context */
	g_fw_ctx = calloc(1, sizeof(fw_ctx_t));
	memcpy(&g_fw_ctx->config, g_fw_cfg, sizeof(fw_cfg_t));

    /* Initialize DB connection */
	if (sqlite3_open(g_fw_cfg->db_path, &g_fw_ctx->db_conn) != SQLITE_OK) {
		free(g_fw_ctx);
		g_fw_ctx = NULL;
		return FW_DB_ERR;
	}

    /* Open wg(4) interface handle */
	wg = calloc(1, sizeof(wg_handle_t));
	if (wg_open_iface(wg, g_fw_cfg->wg_iface) != FW_OK) {
		sqlite3_close(g_fw_ctx->db_conn);
		free(wg);
		return FW_WG_ERR;
	}

    /* Store wg(4) handle in context */
	g_fw_ctx->wg_handle = wg;
    /* Initialize context state */
	g_fw_ctx->state = FW_STATE_STOPPED;
	g_fw_ctx->peer_count = 0;

	return FW_OK;
}

/* Cleanup fwvpnd */
void
fw_cleanup(void)
{
	if (g_fw_ctx == NULL)
		return;

	if (g_fw_ctx->wg_handle != NULL) {
		wg_destroy_iface(g_fw_ctx->wg_handle);
		wg_close_iface(g_fw_ctx->wg_handle);
		free(g_fw_ctx->wg_handle);
	}

	if (g_fw_ctx->db_conn != NULL)
		sqlite3_close(g_fw_ctx->db_conn);

	free(g_fw_ctx);
	g_fw_ctx = NULL;
}

/* Start fwvpnd */
fw_err_t
fw_start(void)
{
	struct wg_interface_io iface;
	fw_err_t ret;

	if (g_fw_ctx == NULL)
		return FW_ERR;

	if (g_fw_ctx->state == FW_STATE_RUNNING)
		return FW_OK;

	if ((ret = wg_create_iface(g_fw_ctx->wg_handle)) != FW_OK)
		return ret;

    /* Configure wg(4) interface */
	memset(&iface, 0, sizeof(iface));
	iface.i_flags = WG_INTERFACE_HAS_PORT;
	iface.i_port = g_fw_ctx->config.listen_port;

	if ((ret = wg_set_iface(g_fw_ctx->wg_handle, &iface)) != FW_OK) {
		wg_destroy_iface(g_fw_ctx->wg_handle);
		return ret;
	}

    /* XXX: Set up IPC socket */
    /* XXX: Load existing peers from DB */

	g_fw_ctx->state = FW_STATE_RUNNING;

	return FW_OK;
}
