/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */

#ifndef NV_OPOF_UTIL_H
#define NV_OPOF_UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

#define CONFIG_FILE		"/opt/mellanox/nv_opof/nv_opof.conf"

#define log_error(M, ...) \
	syslog(LOG_ERR, "[ERROR] %s:%d:%s: (errno: %d - %s) " M "\n", \
                    __FILE__, __LINE__, __func__, errno, strerror(errno), \
                    ##__VA_ARGS__)

#define log_info(M, ...) \
	syslog(LOG_INFO,  "[INFO]  %s:%d:%s: " M "\n", \
                    __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#define log_debug(M, ...) \
	syslog(LOG_DEBUG, "[DEBUG] %s:%d:%s: " M "\n", \
                    __FILE__, __LINE__, __func__, ##__VA_ARGS__)


void nv_opof_signal_handler_install(void);
void nv_opof_signal_handler_uninstall(void);

void nv_opof_log_open(void);
void nv_opof_log_close(void);
void nv_opof_set_log_level(int level);

int nv_opof_config_load(const char *file_path);

#ifdef __cplusplus
}
#endif

#endif
