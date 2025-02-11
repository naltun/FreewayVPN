/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>

#include "fwvpnd.h"

/* Global server context */
static fw_ctx_t *ctx = NULL;

/* Initialize SQLite database */
static fw_err_t
init_db(const char *db_path)
{
	char *err = NULL;
	const char *init_sql =
	    "PRAGMA foreign_keys = ON;"
	    "CREATE TABLE IF NOT EXISTS users ("
	    "	created_at INTEGER,"
	    "	id TEXT PRIMARY KEY,"
	    "	email TEXT UNIQUE,"
	    "	password TEXT NOT NULL,"
	    "	last_login INTEGER"
	    ");"
	    "CREATE TABLE IF NOT EXISTS vpn_configs ("
	    "	user_id TEXT PRIMARY KEY,"
	    "	assigned_ip TEXT UNIQUE,"
	    "	created_at INTEGER,"
	    "	private_key TEXT UNIQUE,"
	    "	public_key TEXT UNIQUE,"
	    "	FOREIGN KEY(user_id) REFERENCES users(id)"
	    ");"
	    "CREATE TABLE IF NOT EXISTS sessions ("
	    "	token TEXT PRIMARY KEY,"
	    "	expires_at INTEGER,"
	    "	user_id TEXT,"
	    "	FOREIGN KEY(user_id) REFERENCES users(id)"
	    ");";

	/* Open database connection */
	if (sqlite3_open(db_path, &ctx->db_conn) != SQLITE_OK) {
		warn("can't open database: %s", sqlite3_errmsg(ctx->db_conn));
		return FW_DB_ERR;
	}

	/* Initialize schema */
	if (sqlite3_exec(ctx->db_conn, init_sql, NULL, NULL, &err) !=
	    SQLITE_OK) {
		warn("SQLite error: %s", err);
		return FW_DB_ERR;
	}

	return FW_OK;
}

/* Initialize WireGuard interface */
static fw_err_t
init_wg(const char *wg_if)
{
	/* XXX: Implement WireGuard interface setup */
	ctx->wg_handle = NULL;  /* Placeholder for now */
	return FW_OK;
}

/* Initialize FreewayVPN server */
fw_err_t
fw_init(fw_cfg_t *cfg)
{
	/* Allocate context if it doesn't exist */
	if (ctx == NULL)
		ctx = calloc(1, sizeof(fw_ctx_t));

	/* Copy configuration */
	memcpy(&ctx->config, cfg, sizeof(fw_cfg_t));

	/* Initialize database */
	if (init_db(cfg->db_path) != FW_OK) {
		warn("database initialization failed");
		return FW_DB_ERR;
	}

	/* Initialize WireGuard */
	if (init_wg(cfg->wg_if) != FW_OK) {
		warn("WireGuard initialization failed");
		return FW_WG_ERR;
	}

	return FW_OK;
}

/* Start FreewayVPN server */
fw_err_t
fw_start()
{
	/* XXX: Implement HTTP server */
	/* For now, just sleep */
	for (;;)
		sleep(1);

	return FW_OK;
}

/* Cleanup server */
void
fw_cleanup()
{
	if (ctx != NULL) {
		/* Close database connection */
		if (ctx->db_conn != NULL)
			sqlite3_close(ctx->db_conn);

		/* XXX: Cleanup WireGuard interface */

		free(ctx);
		ctx = NULL;
	}
}
