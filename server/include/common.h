#ifndef COMMON_H
#define COMMON_H

/* Error types */
typedef enum fw_err_t {
	FW_OK = 0,
	FW_ERR = -1,
	FW_AUTH_ERR = -2,
	FW_DB_ERR = -3,
	FW_WG_ERR = -4,
} fw_err_t;

#endif /* COMMON_H */
