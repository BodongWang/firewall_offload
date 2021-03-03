/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */

#ifndef NV_OPOF_RPC_H
#define NV_OPOF_RPC_H

#include "jsonrpc-c.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RPC_PORT		(12180)

struct nv_opof_rpc_context {
	struct jrpc_server	rpc_server;
	pthread_t		rpc_server_tid;
	pthread_mutex_t		rpc_lock;
};

int nv_opof_rpc_start(struct nv_opof_rpc_context *rpc_ctx);
void nv_opof_rpc_stop(struct nv_opof_rpc_context *rpc_ctx);

#ifdef __cplusplus
}
#endif

#endif
