/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/wait.h>
#include <signal.h>

#include "nv_opof_rpc.h"
#include "nv_opof.h"
#include "opof.h"

#define MAX_STRING_LEN		(20)
/* For string conversion */
char string[MAX_STRING_LEN];

#define JSON_STR_NUM_TO_OBJ(obj, str, format, num) do { \
	memset(string, 0, MAX_STRING_LEN); \
	snprintf(string, MAX_STRING_LEN, format, num); \
	cJSON_AddStringToObject(obj, str, string); } while(0) \

#define JSON_NUM_STR_TO_OBJ(obj, num, format, str) do { \
	memset(string, 0, MAX_STRING_LEN); \
	snprintf(string, MAX_STRING_LEN, format, num); \
	cJSON_AddStringToObject(obj, string, str); } while(0) \

#define JSON_2NUM_STR_TO_OBJ(obj, num1, num2, format, str) do { \
	memset(string, 0, MAX_STRING_LEN); \
	snprintf(string, MAX_STRING_LEN, format, num1, num2); \
	cJSON_AddStringToObject(obj, string, str); } while(0) \

static void parse_response(cJSON *res_obj, sessionResponse_t *res)
{
	JSON_STR_NUM_TO_OBJ(res_obj, "Session ID", "%lu",
			    res->sessionId);
	JSON_STR_NUM_TO_OBJ(res_obj, "In Packets", "%lu",
			    res->inPackets);
	JSON_STR_NUM_TO_OBJ(res_obj, "In Bytes", "%lu",
			    res->inBytes);
	JSON_STR_NUM_TO_OBJ(res_obj, "Out Packets", "%lu",
			    res->outPackets);
	JSON_STR_NUM_TO_OBJ(res_obj, "Out Bytes", "%lu",
			    res->outBytes);
	cJSON_AddStringToObject(res_obj, "State",
				get_session_state(res->sessionState));
	cJSON_AddStringToObject(res_obj, "Close Code",
				get_close_code(res->sessionCloseCode));
}

cJSON *query(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	struct nv_opof_rpc_context *rpc_ctx;
	sessionResponse_t response;
	int ret;
	(void)id;

	rpc_ctx = (struct nv_opof_rpc_context *)ctx->data;

	memset(&response, 0, sizeof(response));

	cJSON *sess_id = cJSON_GetObjectItem(params, "id");
	cJSON *result = cJSON_CreateObject();

	pthread_mutex_lock(&rpc_ctx->rpc_lock);
	ret = opof_get_session_server(sess_id->valueint, &response);
	if(ret == _NOT_FOUND) {
		cJSON_AddStringToObject(result, "Error",
					"Session doesn't exist");
		goto unlock;
	}

	parse_response(result, &response);

unlock:
	pthread_mutex_unlock(&rpc_ctx->rpc_lock);

	return result;
}

cJSON *stats(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	struct nv_opof_rpc_context *rpc_ctx;
	sessionResponse_t response;
	(void)id;

	cJSON *clear = cJSON_GetObjectItem(params, "clear");

	if (clear->valueint) {
		rte_atomic32_clear(&off_config_g.stats.active);
		rte_atomic32_clear(&off_config_g.stats.aged);
		rte_atomic32_clear(&off_config_g.stats.zero_in);
		rte_atomic32_clear(&off_config_g.stats.zero_out);
		rte_atomic32_clear(&off_config_g.stats.zero_io);
		rte_atomic32_clear(&off_config_g.stats.client_del);
		rte_atomic32_clear(&off_config_g.stats.age_thread_hb);
		rte_atomic32_clear(&off_config_g.stats.flows_in);
		rte_atomic32_clear(&off_config_g.stats.flows_del);
		rte_atomic32_clear(&off_config_g.stats.flows_get_closed);
		rte_atomic64_clear(&off_config_g.stats.flows_in_maxtsc);
		rte_atomic64_clear(&off_config_g.stats.flows_in_tottsc);
		rte_atomic64_clear(&off_config_g.stats.flows_del_maxtsc);
		rte_atomic64_clear(&off_config_g.stats.flows_del_tottsc);
		rte_atomic64_clear(&off_config_g.stats.flows_get_closed_maxtsc);
		rte_atomic64_clear(&off_config_g.stats.flows_get_closed_tottsc);
		return cJSON_CreateString("SUCCEED");
	}

	rpc_ctx = (struct nv_opof_rpc_context *)ctx->data;

	memset(&response, 0, sizeof(response));

	cJSON *result = cJSON_CreateObject();

	pthread_mutex_lock(&rpc_ctx->rpc_lock);
	JSON_STR_NUM_TO_OBJ(result, "Active Sessions", "%d",
			    rte_atomic32_read(&off_config_g.stats.active));
	JSON_STR_NUM_TO_OBJ(result, "Aged Sessions", "%d",
			    rte_atomic32_read(&off_config_g.stats.aged));
	JSON_STR_NUM_TO_OBJ(result, "Zero In Sessions", "%d",
			    rte_atomic32_read(&off_config_g.stats.zero_in));
	JSON_STR_NUM_TO_OBJ(result, "Zero Out Sessions", "%d",
			    rte_atomic32_read(&off_config_g.stats.zero_out));
	JSON_STR_NUM_TO_OBJ(result, "Zero In&Out Sessions", "%d",
			    rte_atomic32_read(&off_config_g.stats.zero_io));
	JSON_STR_NUM_TO_OBJ(result, "Client Del Sessions", "%d",
			    rte_atomic32_read(&off_config_g.stats.client_del));
	JSON_STR_NUM_TO_OBJ(result, "Aging Thread Heartbeat", "%u",
			    rte_atomic32_read(&off_config_g.stats.age_thread_hb));
	JSON_STR_NUM_TO_OBJ(result, "Insertion Average(us)", "%lu",
			    rte_atomic64_read(&off_config_g.stats.flows_in_tottsc) /
			    rte_atomic32_read(&off_config_g.stats.flows_in));
	JSON_STR_NUM_TO_OBJ(result, "Insertion Maximum(us)", "%lu",
			    rte_atomic64_read(&off_config_g.stats.flows_in_maxtsc));
	JSON_STR_NUM_TO_OBJ(result, "Deletion Average(us)", "%lu",
			    rte_atomic64_read(&off_config_g.stats.flows_del_tottsc) /
			    rte_atomic32_read(&off_config_g.stats.flows_del));
	JSON_STR_NUM_TO_OBJ(result, "Deletion Maximum(us)", "%lu",
			    rte_atomic64_read(&off_config_g.stats.flows_del_maxtsc));
	JSON_STR_NUM_TO_OBJ(result, "Get Closed Average(us)", "%lu",
			    rte_atomic64_read(&off_config_g.stats.flows_get_closed_tottsc) /
			    rte_atomic32_read(&off_config_g.stats.flows_get_closed));
	JSON_STR_NUM_TO_OBJ(result, "Get Closed Maximum(us)", "%lu",
			    rte_atomic64_read(&off_config_g.stats.flows_get_closed_maxtsc));
	pthread_mutex_unlock(&rpc_ctx->rpc_lock);

	return result;
}

cJSON *delete(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	struct nv_opof_rpc_context *rpc_ctx;
	sessionResponse_t response;
	int ret = 0;
	(void)id;

	rpc_ctx = (struct nv_opof_rpc_context *)ctx->data;

	memset(&response, 0, sizeof(response));

	cJSON *sess_id = cJSON_GetObjectItem(params, "id");
	cJSON *result = cJSON_CreateObject();

	pthread_mutex_lock(&rpc_ctx->rpc_lock);
	ret = opof_del_session_server(sess_id->valueint, &response);
	if(ret == _NOT_FOUND) {
		cJSON_AddStringToObject(result, "Error",
					"Session doesn't exist");
		goto unlock;
	}

	if (ret)
		JSON_STR_NUM_TO_OBJ(result, "Error", "%d", ret);
	else
		result = cJSON_CreateString("SUCCEED");

unlock:
	pthread_mutex_unlock(&rpc_ctx->rpc_lock);
	return result;
}

cJSON *add(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	struct nv_opof_rpc_context *rpc_ctx;
	addSessionResponse_t response;
	sessionRequest_t request;
	uint64_t tic, toc;
	uint32_t rate;
	int ret = 0;
	(void)id;

	rpc_ctx = (struct nv_opof_rpc_context *)ctx->data;

	memset(&response, 0, sizeof(response));
	memset(&request, 0, sizeof(request));

	cJSON *num = cJSON_GetObjectItem(params, "num");
	cJSON *rte = cJSON_GetObjectItem(params, "rte");
	cJSON *result = cJSON_CreateObject();

	request.actType = 1;
	request.proto = 6;
	request.ipver = _IPV4;
	request.inlif = 1;
	request.srcIP.s_addr = 0x1000000; // 1.0.0.0
	request.dstIP.s_addr = 0xc3010103; // 195.1.1.3
	request.srcPort = 5002;
	request.dstPort = 5003;

	pthread_mutex_lock(&rpc_ctx->rpc_lock);
	if (rte->valueint) {
		rate = offload_flow_test(INITIATOR_PORT_ID, num->valueint);
		goto rte_unlock;
	}

	tic = rte_rdtsc();
	while ((int)request.sessId < num->valueint) {
		ret = opof_add_session_server(&request, &response);
		if (ret != _OK) {
			JSON_STR_NUM_TO_OBJ(result, "Failed at iter", "%lu",
						request.sessId);
			goto unlock;
		}
		request.sessId++;
	}

	toc = rte_rdtsc() - tic;

	rate = (uint64_t)num->valueint * rte_get_tsc_hz() / toc;

unlock:
	opof_del_all_session_server();
rte_unlock:
	JSON_STR_NUM_TO_OBJ(result, "CPS", "%u", rate);
	pthread_mutex_unlock(&rpc_ctx->rpc_lock);
	return result;
}

cJSON *log_level(jrpc_context *ctx, cJSON *params, cJSON *id)
{
	cJSON *level = cJSON_GetObjectItem(params, "level");
	int val = 0;
	(void)ctx;
	(void)id;

	if (!strcmp("info", level->valuestring))
		val = LOG_INFO;
	else if (!strcmp("err", level->valuestring))
		val = LOG_ERR;
	else if (!strcmp("debug", level->valuestring))
		val = LOG_DEBUG;
	else if (!strcmp("warn", level->valuestring))
		val = LOG_WARNING;

	log_info("Set log level to %s", level->valuestring);

	nv_opof_set_log_level(val);

	return cJSON_CreateString("SUCCEED");
}

static void *nv_opof_rpc_handler(void *ctx)
{
	struct nv_opof_rpc_context *rpc_ctx;

	assert(ctx);
	rpc_ctx = (struct nv_opof_rpc_context *)ctx;

	jrpc_server_init(&rpc_ctx->rpc_server, RPC_PORT);

	jrpc_register_procedure(&rpc_ctx->rpc_server, delete, "delete",
				ctx);
	jrpc_register_procedure(&rpc_ctx->rpc_server, stats, "stats",
				ctx);
	jrpc_register_procedure(&rpc_ctx->rpc_server, query, "query",
				ctx);
	jrpc_register_procedure(&rpc_ctx->rpc_server, add, "add",
				ctx);
	jrpc_register_procedure(&rpc_ctx->rpc_server, log_level,
				"log_level", ctx);

	jrpc_server_run(&rpc_ctx->rpc_server);
	pthread_exit(NULL);
}

int nv_opof_rpc_start(struct nv_opof_rpc_context *rpc_ctx)
{
	pthread_attr_t pattr = {};
	int rc;

	pthread_attr_init(&pattr);
	pthread_attr_setdetachstate(&pattr, PTHREAD_CREATE_JOINABLE);

	rc = pthread_create(&rpc_ctx->rpc_server_tid, &pattr,
			    nv_opof_rpc_handler, rpc_ctx);
	if (rc)
		log_error("Failed to create RPC server thread");

	pthread_mutex_init(&rpc_ctx->rpc_lock, NULL);

	return rc;
}

void nv_opof_rpc_stop(struct nv_opof_rpc_context *rpc_ctx)
{
	pthread_mutex_destroy(&rpc_ctx->rpc_lock);
	pthread_cancel(rpc_ctx->rpc_server_tid);
	jrpc_server_stop(&rpc_ctx->rpc_server);
}
