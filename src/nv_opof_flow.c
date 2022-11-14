/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "nv_opof.h"

#define MAX_FLOW_ITEM (9)
#define MAX_ACTION_ITEM (6)

static struct rte_flow_item eth_item = {
	RTE_FLOW_ITEM_TYPE_ETH,
	0, 0, 0
};

static struct rte_flow_item end_item = {
	RTE_FLOW_ITEM_TYPE_END,
	0, 0, 0
};

struct rte_flow_action_jump nic_rx_group = {
	.group = NIC_RX_GROUP,
};

static struct rte_flow_action jump_action = {
	RTE_FLOW_ACTION_TYPE_JUMP,
	&nic_rx_group
};

static struct rte_flow_action drop_action = {
	RTE_FLOW_ACTION_TYPE_DROP,
	0
};

static struct rte_flow_action end_action = {
	RTE_FLOW_ACTION_TYPE_END,
	0
};

static struct rte_flow_item_ipv4 ipv4_mask = {
	.hdr.next_proto_id = 0xFF,
	.hdr.src_addr = 0xFFFFFFFF,
	.hdr.dst_addr = 0xFFFFFFFF,
};

static struct rte_flow_item_ipv6 ipv6_mask = {
	.hdr.src_addr =
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff",
	.hdr.dst_addr =
		"\xff\xff\xff\xff\xff\xff\xff\xff"
		"\xff\xff\xff\xff\xff\xff\xff\xff",
};

static struct rte_flow_item_udp udp_mask = {
	.hdr.src_port = 0xFFFF,
	.hdr.dst_port = 0xFFFF,
};

static struct rte_flow_item_tcp tcp_mask = {
	.hdr.src_port = 0xFFFF,
	.hdr.dst_port = 0xFFFF,
	.hdr.tcp_flags = RTE_TCP_FIN_FLAG |
		RTE_TCP_SYN_FLAG |
		RTE_TCP_RST_FLAG,
};

static int
port_id_is_invalid(portid_t port_id, enum print_warning warning)
{
	uint16_t pid;

	RTE_ETH_FOREACH_DEV(pid)
		if (port_id == pid)
			return 0;

	if (warning == ENABLED_WARN)
		log_error("Invalid port %d", port_id);

	return 1;
}

#define PORT_FLOW_COMPLAIN(err) port_flow_complain(__func__, err)

static int port_flow_complain(const char *func, struct rte_flow_error *error)
{
	static const char *const errstrlist[] = {
		[RTE_FLOW_ERROR_TYPE_NONE] = "no error",
		[RTE_FLOW_ERROR_TYPE_UNSPECIFIED] = "cause unspecified",
		[RTE_FLOW_ERROR_TYPE_HANDLE] = "flow rule (handle)",
		[RTE_FLOW_ERROR_TYPE_ATTR_GROUP] = "group field",
		[RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY] = "priority field",
		[RTE_FLOW_ERROR_TYPE_ATTR_INGRESS] = "ingress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_EGRESS] = "egress field",
		[RTE_FLOW_ERROR_TYPE_ATTR_TRANSFER] = "transfer field",
		[RTE_FLOW_ERROR_TYPE_ATTR] = "attributes structure",
		[RTE_FLOW_ERROR_TYPE_ITEM_NUM] = "pattern length",
		[RTE_FLOW_ERROR_TYPE_ITEM_SPEC] = "item specification",
		[RTE_FLOW_ERROR_TYPE_ITEM_LAST] = "item specification range",
		[RTE_FLOW_ERROR_TYPE_ITEM_MASK] = "item specification mask",
		[RTE_FLOW_ERROR_TYPE_ITEM] = "specific pattern item",
		[RTE_FLOW_ERROR_TYPE_ACTION_NUM] = "number of actions",
		[RTE_FLOW_ERROR_TYPE_ACTION_CONF] = "action configuration",
		[RTE_FLOW_ERROR_TYPE_ACTION] = "specific action",
	};
	const char *errstr;
	char buf[32];
	int err = rte_errno;

	if ((unsigned int)error->type >= RTE_DIM(errstrlist) ||
	    !errstrlist[error->type])
		errstr = "unknown type";
	else
		errstr = errstrlist[error->type];

	log_error("%s(): Caught PMD error type %d (%s): %s%s: %s", func,
		  error->type, errstr,
		  error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
					   error->cause), buf) : "",
		  error->message ? error->message : "(no stated reason)",
		  rte_strerror(err));
	return -err;
}

struct rte_flow *
nv_opof_add_simple_flow(uint16_t port_id,
		struct rte_flow_attr *attr,
		struct rte_flow_item pattern[],
		struct rte_flow_action actions[],
		const char *flow_name)
{
	struct rte_flow_error error = {};
	struct rte_flow *flow = NULL;

	flow = rte_flow_create(port_id, attr, pattern,
			       actions, &error);

	if (!flow)
		log_error("%s flow creation failed(0x%x): %s",
		       flow_name, error.type, error.message ?
		       error.message : "(no stated reason)");

	return flow;
}

int offload_flow_test(portid_t port_id, uint32_t num)
{
	struct rte_flow_item flow_pattern[MAX_FLOW_ITEM];
	struct rte_flow_action actions[MAX_ACTION_ITEM];
	struct rte_flow_action_age age = {};
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item ip_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item tcp_item;
	enum rte_flow_item_type ip_type;
	void *ip_spec, *ip_mask;
	int i = 0, flow_index = 0;
	struct rte_flow **flows;
	uint64_t tic, toc;
	uint32_t rate;
	static struct rte_flow_attr attr = {
		.ingress = 1,
		.transfer = 1,
		.priority = FDB_FWD_PRIORITY,
	};

	struct rte_flow_action age_action = {
		RTE_FLOW_ACTION_TYPE_AGE,
		&age
	};

	memset(&flow_pattern, 0, sizeof(flow_pattern));

	/* Eth item*/
	flow_pattern[flow_index++] = eth_item;

	/* IP item */
	ip_type = RTE_FLOW_ITEM_TYPE_IPV4;

	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	ipv4_spec.hdr.next_proto_id = IPPROTO_TCP;
	ipv4_spec.hdr.src_addr = 0xc3010102;
	ipv4_spec.hdr.dst_addr = 0xc3010103;
	ip_spec = &ipv4_spec;

	ip_mask = &ipv4_mask;

	ip_item.type = ip_type;
	ip_item.spec = ip_spec;
	ip_item.mask = ip_mask;
	ip_item.last = NULL;

	flow_pattern[flow_index++] = ip_item;

	memset(&tcp_spec, 0, sizeof(tcp_spec));

	tcp_spec.hdr.src_port = 6002;
	tcp_spec.hdr.dst_port = 6003;

	tcp_spec.hdr.tcp_flags = 0;

	tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
	tcp_item.spec = &tcp_spec;
	tcp_item.mask = &tcp_mask;
	tcp_item.last = NULL;

	flow_pattern[flow_index++] = tcp_item;

	flow_pattern[flow_index] = end_item;
	if (flow_index >= MAX_FLOW_ITEM) {
		log_error("Offload flow: flow item overflow");
		return -EINVAL;
	}

	age.timeout = 300;
	actions[i++] = age_action;
	actions[i++] = jump_action;
	actions[i++] = end_action;

	flows = rte_zmalloc("flows",
			    sizeof(struct rte_flow*) * num,
			    RTE_CACHE_LINE_SIZE);

	log_info("Insert flows %d", num);
        tic = rte_rdtsc();
	for (i = 0; i < (int)num; i++) {
		ipv4_spec.hdr.src_addr++;
		flows[i] = rte_flow_create(port_id, &attr, flow_pattern,
					   actions, NULL);
		if (!flows[i])
			break;
	}

        toc = rte_rdtsc() - tic;

	rate = (long double)i * rte_get_tsc_hz() / toc;
	num = i;

	log_info("Destroy flows %d", num);
	for (i = 0; i < (int)num; i++)
		if (flows[i] && rte_flow_destroy(port_id, flows[i], NULL))
			log_error("Failed to destory flow %u", i);

	log_info("Done");

	rte_free(flows);

	return rate;
}

int nv_opof_offload_flow_add(portid_t port_id,
		     struct fw_session *session,
		     enum flow_dir dir)
{
	struct rte_flow_item flow_pattern[MAX_FLOW_ITEM] = {};
	struct rte_flow_action actions[MAX_ACTION_ITEM] = {};
	struct rte_flow_action_age age = {};
	struct rte_flow_action_count flow_count = {};
	struct rte_flow_item_vlan vlan_spec = {};
	struct rte_flow_item vlan_item = {};
	struct rte_flow_item outer_ip_item = {};
	struct rte_flow_item outer_udp_item = {};
	struct rte_flow_item outer_gtp_item = {};
	struct rte_flow_item_ipv4 ipv4_spec = {};
	struct rte_flow_item_ipv6 ipv6_spec = {};
	struct rte_flow_item ip_item = {};
	struct rte_flow_item_udp udp_spec = {};
	struct rte_flow_item udp_item = {};
	struct rte_flow_item_tcp tcp_spec = {};
	struct rte_flow_item tcp_item = {};
	struct rte_flow_error flow_error = {};
	enum rte_flow_item_type ip_type;
	void *ip_spec, *ip_mask;
	struct rte_flow *flow = NULL;
	uint8_t i = 0, flow_index = 0;

	struct offload_flow * p_offload_flow = dir == DIR_IN ? &session->flow_in : &session->flow_out;

	static struct rte_flow_attr attr = {
		.ingress = 1,
		.transfer = 1,
	};
	struct rte_flow_action age_action = {
		RTE_FLOW_ACTION_TYPE_AGE,
		&age
	};
	struct rte_flow_action count_action = {
		RTE_FLOW_ACTION_TYPE_COUNT,
		&flow_count
	};
	struct rte_flow_action_set_mac dst_mac = {};
	struct rte_flow_action_set_mac src_mac = {};
	struct rte_flow_action dst_mac_action = {
		RTE_FLOW_ACTION_TYPE_SET_MAC_DST,
		&dst_mac
	};
	struct rte_flow_action src_mac_action = {
		RTE_FLOW_ACTION_TYPE_SET_MAC_SRC,
		&src_mac,
	};

	struct rte_ether_addr mac_addr;
	rte_eth_macaddr_get(port_id, &mac_addr);
	memcpy(src_mac.mac_addr, &mac_addr, 6);
	memcpy(dst_mac.mac_addr, off_config_g.overwrite_dst_mac.addr_bytes, 6);

	attr.priority = session->action==ACTION_FORWARD ? FDB_FWD_PRIORITY : FDB_DROP_PRIORITY;

	/* Eth item*/
	flow_pattern[flow_index++] = eth_item;

	/* Vlan item */
	if (session->info.vlan) {
		vlan_item.type = RTE_FLOW_ITEM_TYPE_VLAN;
		vlan_item.spec = &vlan_spec;
		vlan_item.mask = &rte_flow_item_vlan_mask,

		vlan_spec.tci = htons(session->info.vlan);

		flow_pattern[flow_index++] = vlan_item;
	}

	if (session->info.tunnel) {
		outer_ip_item.type = RTE_FLOW_ITEM_TYPE_IPV4;
		outer_udp_item.type = RTE_FLOW_ITEM_TYPE_UDP;
		outer_gtp_item.type = RTE_FLOW_ITEM_TYPE_GTP;
		flow_pattern[flow_index++] = outer_ip_item;
		flow_pattern[flow_index++] = outer_udp_item;
		flow_pattern[flow_index++] = outer_gtp_item;
	}

	/* IP item */
	switch (session->info.ip_ver) {
	case IPPROTO_IP:
		ip_type = RTE_FLOW_ITEM_TYPE_IPV4;

		ipv4_spec.hdr.next_proto_id = session->info.proto;
		if (dir == DIR_IN) {
			ipv4_spec.hdr.src_addr = htonl(session->info.src_ip);
			ipv4_spec.hdr.dst_addr = htonl(session->info.dst_ip);
		} else if (dir == DIR_OUT) {
			ipv4_spec.hdr.src_addr = htonl(session->info.dst_ip);
			ipv4_spec.hdr.dst_addr = htonl(session->info.src_ip);
		}
		ip_spec = &ipv4_spec;
		ip_mask = &ipv4_mask;
		break;
	case IPPROTO_IPV6:
		ip_type = RTE_FLOW_ITEM_TYPE_IPV6;

		ipv6_spec.hdr.proto = session->info.proto;

		if (dir == DIR_IN) {
			memcpy(&ipv6_spec.hdr.src_addr,
			       &session->info.src_ipv6,
			       sizeof(struct in6_addr));
			memcpy(&ipv6_spec.hdr.dst_addr,
			       &session->info.dst_ipv6,
			       sizeof(struct in6_addr));
		} else if (dir == DIR_OUT) {
			memcpy(&ipv6_spec.hdr.src_addr,
			       &session->info.dst_ipv6,
			       sizeof(struct in6_addr));
			memcpy(&ipv6_spec.hdr.dst_addr,
			       &session->info.src_ipv6,
			       sizeof(struct in6_addr));
		}
		ip_spec = &ipv6_spec;
		ip_mask = &ipv6_mask;
		break;
	}

	ip_item.type = ip_type;
	ip_item.spec = ip_spec;
	ip_item.mask = ip_mask;

	flow_pattern[flow_index++] = ip_item;

	/* L4 proto item */
	switch (session->info.proto) {
	case IPPROTO_UDP:
		if (dir == DIR_IN) {
			udp_spec.hdr.src_port = htons(session->info.src_port);
			udp_spec.hdr.dst_port = htons(session->info.dst_port);
		} else if (dir == DIR_OUT) {
			udp_spec.hdr.src_port = htons(session->info.dst_port);
			udp_spec.hdr.dst_port = htons(session->info.src_port);
		}

		udp_item.type = RTE_FLOW_ITEM_TYPE_UDP;
		udp_item.spec = &udp_spec;
		udp_item.mask = &udp_mask;

		flow_pattern[flow_index++] = udp_item;
		break;
	case IPPROTO_TCP:
		if (dir == DIR_IN) {
			tcp_spec.hdr.src_port = htons(session->info.src_port);
			tcp_spec.hdr.dst_port = htons(session->info.dst_port);
		} else if (dir == DIR_OUT) {
			tcp_spec.hdr.src_port = htons(session->info.dst_port);
			tcp_spec.hdr.dst_port = htons(session->info.src_port);
		}

		tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
		tcp_item.spec = &tcp_spec;
		tcp_item.mask = &tcp_mask;

		flow_pattern[flow_index++] = tcp_item;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	flow_pattern[flow_index] = end_item;

	if (session->timeout)
		age.timeout = session->timeout;
	else
		age.timeout = DEFAULT_TIMEOUT;

	age.context = p_offload_flow;

	/* Fill actions */
	actions[i++] = age_action;
	actions[i++] = count_action;
	if (session->action == ACTION_FORWARD) {
		if (off_config_g.overwrite_dst_mac_enabled) {
			actions[i++] = dst_mac_action;
			actions[i++] = src_mac_action;
		}
		actions[i++] = jump_action;
	} else {
		actions[i++] = drop_action;
	}
	actions[i++] = end_action;

	flow = rte_flow_create(port_id, &attr, flow_pattern,
			       actions, &flow_error);
	if (!flow) {
		log_error("Port %d: flow creation failed; error %d:%s", 
			port_id, flow_error.type, flow_error.message);
		return -EINVAL;
	}

	p_offload_flow->session = session;
	p_offload_flow->flow = flow;
	p_offload_flow->portid = port_id;
	rte_atomic32_set(&p_offload_flow->ref_count, 1);

	return 0;
}

int nv_opof_offload_flow_query(portid_t port_id, struct rte_flow *flow,
		       int64_t *packets, int64_t *bytes)
{
	struct rte_flow_query_count flow_count = {
		.reset = 0,
		.hits_set = 1,
		.bytes_set = 1,
		.hits = 0,
		.bytes = 0,
	};
	struct rte_flow_action action[2];
	struct rte_flow_error error;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return -EINVAL;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[0].conf = &flow_count;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x55, sizeof(error));

	if (rte_flow_query(port_id, flow, action, &flow_count, &error))
		return PORT_FLOW_COMPLAIN(&error);

	*packets = flow_count.hits;
	*bytes = flow_count.bytes;

	return 0;
}

int nv_opof_offload_flow_destroy(portid_t port_id, struct rte_flow *flow)
{
	struct rte_flow_error error;
	int ret = 0;

	if (!flow)
		return 0;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return -EINVAL;

	memset(&error, 0x33, sizeof(error));
	if (rte_flow_destroy(port_id, flow, &error))
		ret = PORT_FLOW_COMPLAIN(&error);

	return ret;
}

void nv_opof_offload_flow_aged(portid_t port_id)
{
	int nb_context, total = 0, idx;
	struct rte_flow_error error;
	struct fw_session *session;
	struct offload_flow *flow;
	void **contexts;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	pthread_mutex_lock(&off_config_g.ht_lock);
	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total < 0) {
		PORT_FLOW_COMPLAIN(&error);
		goto unlock;
	}

	if (total == 0)
		goto unlock;

	contexts = rte_zmalloc("aged_ctx", sizeof(void *) * total,
			       RTE_CACHE_LINE_SIZE);
	if (contexts == NULL)
		goto unlock;

	nb_context = rte_flow_get_aged_flows(port_id, contexts,
					     total, &error);
	if (nb_context != total)
		goto free;

	for (idx = 0; idx < nb_context; idx++) {
		rte_atomic32_inc(&off_config_g.stats.age_thread_hb);
		flow = (struct offload_flow *)contexts[idx];
		if (!flow)
			continue;
		session = flow->session;

		rte_atomic32_set(&flow->ref_count, 0);

		/* Only delete flow when both directions are aged out.
		 * This hides the bug that the counter on one of the
		 * direction is not updating
		 */
		bool all_flows_timed_out = rte_atomic32_read(&session->flow_in.ref_count) == 0 && 
		                           rte_atomic32_read(&session->flow_out.ref_count) == 0;
		if (all_flows_timed_out) {
			session->close_code = _TIMEOUT;
			ret = opof_del_flow(session);
			if (!ret)
				rte_atomic32_inc(&off_config_g.stats.aged);
		}
		// Else, leave all flows for this session in place.
		// Note they will be returned by future calls to rte_flow_get_aged_flows().
	}

free:
	rte_free(contexts);
unlock:
	pthread_mutex_unlock(&off_config_g.ht_lock);
}

int nv_opof_offload_flow_flush(portid_t port_id)
{
	struct rte_flow_error error;
	int ret = 0;

	memset(&error, 0x44, sizeof(error));
	if (rte_flow_flush(port_id, &error)) {
		ret = PORT_FLOW_COMPLAIN(&error);
	}

	return ret;
}
