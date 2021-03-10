/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include <stdlib.h>
#include <time.h>

#include "opof.h"
#include "opof_error.h"
#include "opof_serverlib.h"
#include "opof_test_util.h"

#include "nv_opof.h"

char *get_session_state(uint8_t state)
{
	switch(state)
	{
	case 0:
		return "EST";
	case 1:
		return "CLS_1";
	case 2:
		return "CLS_2";
	case 3:
		return "CLOSED";
	default:
		return "UNKOWN";
	}
}

char *get_close_code(uint8_t code)
{
	switch(code)
	{
	case 0:
		return "NA";
	case 1:
		return "FINACK";
	case 2:
		return "RST";
	case 3:
		return "AGE_OUT";
	default:
		return "UNKOWN";
	}
}

static void display_response(sessionResponse_t *response,
			     uint8_t *cmd)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	log_debug("\n" "CMD        " "ID        "
	       "IN_PACKETS   IN_BYTES      OUT_PACKETS  OUT_BYTES     "
	       "STATE   " "CLOSE   " "\n"
	       "%-11s"
	       "%-10lu"
	       "%-13lu" "%-14lu" "%-13lu" "%-14lu"
	       "%-8s" "%-8s" "\n",
	       cmd, response->sessionId,
	       response->inPackets,
	       response->inBytes,
	       response->outPackets,
	       response->outBytes,
	       get_session_state(response->sessionState),
	       get_close_code(response->sessionCloseCode));
}

static void display_request(sessionRequest_t *request,
			    uint8_t *cmd)
{
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	if (request->ipver == _IPV6) {
		request->srcIP.s_addr = 0;
		request->dstIP.s_addr = 0;
	}

	log_debug("\n" "CMD  " "ID        IN  OUT  VLAN  "
		  "SRC_IPv4         SRC_PORT  DST_IPv4         DST_PORT  "
		  "PROTO  IP  ACT  AGE" "\n"
		  "%-5s" "%-10lu" "%-4u" "%-5u" "%-6u"
		  "%03u.%03u.%03u.%03u  " "%-10u" "%03u.%03u.%03u.%03u  "
		  "%-10u" "%-7s" "%-4u" "%-5s" "%-4u" "\n",
		  cmd, request->sessId,
		  request->inlif & 0xFFFF,
		  request->outlif & 0xFFFF,
		  request->inlif >> 16,
		  (request->srcIP.s_addr >> 24) & 0xFF,
		  (request->srcIP.s_addr >> 16) & 0xFF,
		  (request->srcIP.s_addr >> 8) & 0xFF,
		  request->srcIP.s_addr & 0xFF,
		  request->srcPort,
		  (request->dstIP.s_addr >> 24) & 0xFF,
		  (request->dstIP.s_addr >> 16) & 0xFF,
		  (request->dstIP.s_addr >> 8) & 0xFF,
		  request->dstIP.s_addr & 0xFF,
		  request->dstPort,
		  request->proto == 6 ? "TCP" : "UDP",
		  request->ipver == _IPV4 ? 4 : 6,
		  request->actType == 1 ? "FWD" : "DROP",
		  request->cacheTimeout);

	if (request->ipver == _IPV6)
		log_debug("\n"
			  "srcIPv6: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
			  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x "
			  "dstIPv6: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:"
			  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			  request->srcIPV6.s6_addr[0],
			  request->srcIPV6.s6_addr[1],
			  request->srcIPV6.s6_addr[2],
			  request->srcIPV6.s6_addr[3],
			  request->srcIPV6.s6_addr[4],
			  request->srcIPV6.s6_addr[5],
			  request->srcIPV6.s6_addr[6],
			  request->srcIPV6.s6_addr[7],
			  request->srcIPV6.s6_addr[8],
			  request->srcIPV6.s6_addr[9],
			  request->srcIPV6.s6_addr[10],
			  request->srcIPV6.s6_addr[11],
			  request->srcIPV6.s6_addr[12],
			  request->srcIPV6.s6_addr[13],
			  request->srcIPV6.s6_addr[14],
			  request->srcIPV6.s6_addr[15],
			  request->dstIPV6.s6_addr[0],
			  request->dstIPV6.s6_addr[1],
			  request->dstIPV6.s6_addr[2],
			  request->dstIPV6.s6_addr[3],
			  request->dstIPV6.s6_addr[4],
			  request->dstIPV6.s6_addr[5],
			  request->dstIPV6.s6_addr[6],
			  request->dstIPV6.s6_addr[7],
			  request->dstIPV6.s6_addr[8],
			  request->dstIPV6.s6_addr[9],
			  request->dstIPV6.s6_addr[10],
			  request->dstIPV6.s6_addr[11],
			  request->dstIPV6.s6_addr[12],
			  request->dstIPV6.s6_addr[13],
			  request->dstIPV6.s6_addr[14],
			  request->dstIPV6.s6_addr[15]);
}

int opof_get_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));
	response->sessionId = sessionId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (!session)
		return _NOT_FOUND;

	offload_flow_query(session->flow_in.portid, session->flow_in.flow,
			   &response->inPackets, &response->inBytes);

	offload_flow_query(session->flow_out.portid, session->flow_out.flow,
			   &response->outPackets, &response->outBytes);

	response->sessionState = session->state;
	response->sessionCloseCode = session->close_code;

	return _OK;
}

int opof_del_flow(struct fw_session *session)
{
	struct rte_hash *ht = off_config_g.session_ht;
	sessionResponse_t *session_stat;
	int ret = 0;

	session->state = _CLOSED;
	session_stat = rte_zmalloc("stats",
				   sizeof(sessionResponse_t),
				   RTE_CACHE_LINE_SIZE);
	opof_get_session_server(session->key.sess_id,
				session_stat);

	ret = offload_flow_destroy(session->flow_in.portid,
				   session->flow_in.flow);

	if (ret)
		goto out;

	ret = offload_flow_destroy(session->flow_out.portid,
				   session->flow_out.flow);

	if (ret)
		goto out;

	rte_hash_del_key(ht, &session->key);

	if (rte_ring_enqueue(off_config_g.session_fifo, session_stat))
		log_error("no enough room in session session_fifo");

	rte_free(session);

	rte_atomic32_dec(&off_config_g.stats.active);

	return ret;

out:
	rte_free(session_stat);
	return ret;
}

int opof_add_session_server(sessionRequest_t *parameters,
			    addSessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	memset(&key, 0, sizeof(key));

	display_request(parameters, "add");

	key.sess_id = parameters->sessId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (session) {
		log_debug("Session (%lu) already exists",
			  session->key.sess_id);
		return _ALREADY_EXISTS;
	}

	session = rte_zmalloc("session",
			      sizeof(struct fw_session),
			      RTE_CACHE_LINE_SIZE);

	session->key.sess_id = parameters->sessId;
	pthread_mutex_init(&session->lock, NULL);

	session->info.src_ip = parameters->srcIP.s_addr;
	session->info.dst_ip = parameters->dstIP.s_addr;
	memcpy(&session->info.src_ipv6, &parameters->srcIPV6.s6_addr,
	       sizeof(struct in6_addr));
	memcpy(&session->info.dst_ipv6, &parameters->dstIPV6.s6_addr,
	       sizeof(struct in6_addr));
	session->info.src_port = parameters->srcPort;
	session->info.dst_port = parameters->dstPort;
	session->info.ip_ver = parameters->ipver == _IPV4 ?
			       IPPROTO_IP : IPPROTO_IPV6;
	session->info.proto = parameters->proto;
	session->info.vlan = parameters->inlif >> 16;

	if (parameters->cacheTimeout >= MAX_TIMEOUT) {
		log_info("WARNING: "
			 "requested timeout(%u), max(%u), use default(%u)",
			 parameters->cacheTimeout, MAX_TIMEOUT,
			 DEFAULT_TIMEOUT);
		session->timeout = DEFAULT_TIMEOUT;
	}else {
		session->timeout = parameters->cacheTimeout;
	}

	if ((parameters->inlif & 0xFFFF) == 1) {
		session->flow_in.portid = INITIATOR_PORT_ID;
		session->flow_out.portid = RESPONDER_PORT_ID;
	} else {
		session->flow_in.portid = RESPONDER_PORT_ID;
		session->flow_out.portid = INITIATOR_PORT_ID;
	}

	ret = offload_flow_add(session->flow_in.portid, session,
			       (enum flow_action)parameters->actType,
			       DIR_IN);

	if (ret)
		return _INTERNAL;

	ret = offload_flow_add(session->flow_out.portid, session,
			       (enum flow_action)parameters->actType,
			       DIR_OUT);

	if (!ret) {
		session->state = _ESTABLISHED;
		rte_hash_add_key_data(ht, &session->key, (void *)session);
		rte_atomic32_inc(&off_config_g.stats.active);
	} else {
		offload_flow_destroy(session->flow_in.portid,
				     session->flow_in.flow);
		log_error("ERR(%d): Failed to add session (%lu)",
		       ret, session->key.sess_id);
		return _INTERNAL;
	}

	return _OK;
}

int opof_del_session_server(unsigned long sessionId,
			    sessionResponse_t *response)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	struct session_key key;
	int ret;

	key.sess_id = sessionId;

	memset(response, 0, sizeof(*response));
	response->sessionId = sessionId;

	ret = rte_hash_lookup_data(ht, &key, (void **)&session);
	if (!session)
		return _NOT_FOUND;

	pthread_mutex_lock(&session->lock);
	ret = opof_del_flow(session);
	pthread_mutex_unlock(&session->lock);

	rte_atomic32_inc(&off_config_g.stats.client_del);

	return ret ? _INTERNAL : _OK;
}

void opof_del_all_session_server(void)
{
	struct rte_hash *ht = off_config_g.session_ht;
	struct fw_session *session = NULL;
	const void *next_key = NULL;
	uint32_t iter = 0;

	while (rte_hash_iterate(ht, &next_key,
				(void **)&session, &iter) >= 0) {
		pthread_mutex_lock(&session->lock);
		opof_del_flow(session);
		pthread_mutex_unlock(&session->lock);
	}
}

int opof_get_closed_sessions_server(statisticsRequestArgs_t *request,
				    sessionResponse_t responses[])
{
	int size = request->pageSize;
	int deq, count, ret, i;
	sessionResponse_t **session_stats;

	count = rte_ring_count(off_config_g.session_fifo);

	size = MIN(MIN(size, count), BUFFER_MAX);

	session_stats = rte_zmalloc("temp",
				    sizeof(sessionResponse_t *) * size,
				    RTE_CACHE_LINE_SIZE);

	deq = rte_ring_dequeue_bulk(off_config_g.session_fifo,
				    (void **)session_stats, size,
				    NULL);
	if (deq) {
		for (i = 0; i < deq; i++) {
			memcpy(&responses[i], session_stats[i],
			       sizeof(sessionResponse_t));

			if (!responses[i].inPackets)
				rte_atomic32_inc(&off_config_g.stats.zero_in);
			if (!responses[i].outPackets)
				rte_atomic32_inc(&off_config_g.stats.zero_out);
			if (!responses[i].inPackets &&
			    !responses[i].outPackets)
				rte_atomic32_inc(&off_config_g.stats.zero_io);

			display_response(&responses[i], "get_close");
		}
	}

	rte_free(session_stats);

	return deq;
}

int opof_get_all_sessions_server(int pageSize, uint64_t *startSession,int
				 pageCount, sessionResponse_t **responses)
{
	return _OK;
}
