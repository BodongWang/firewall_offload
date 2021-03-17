/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "nv_opof.h"

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
};

static struct rte_flow_action end_action = {
	RTE_FLOW_ACTION_TYPE_END,
	0
};

static struct rte_flow_attr attr;

static int
port_id_is_invalid(portid_t port_id, enum print_warning warning)
{
	uint16_t pid;

	if (port_id == (portid_t)RTE_PORT_ALL)
		return 0;

	RTE_ETH_FOREACH_DEV(pid)
		if (port_id == pid)
			return 0;

	if (warning == ENABLED_WARN)
		log_error("Invalid port %d", port_id);

	return 1;
}

static int port_flow_complain(struct rte_flow_error *error)
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

	log_error("%s(): Caught PMD error type %d (%s): %s%s: %s", __func__,
		  error->type, errstr,
		  error->cause ? (snprintf(buf, sizeof(buf), "cause: %p, ",
					   error->cause), buf) : "",
		  error->message ? error->message : "(no stated reason)",
		  rte_strerror(err));
	return -err;
}

struct rte_flow *
add_simple_flow(uint16_t port_id,
		struct rte_flow_attr *attr,
		struct rte_flow_item pattern[],
		struct rte_flow_action actions[],
		const char *flow_name)
{
	struct rte_flow *flow = NULL;
	struct rte_flow_error error;
	int res;

	memset(&error, 0, sizeof(error));
	res = rte_flow_validate(port_id, attr, pattern, actions, &error);
	if (!res)
		flow = rte_flow_create(port_id, attr, pattern,
				       actions, &error);
	else
		log_error("%s flow validation failed", flow_name);

	if (!flow)
		log_error("%s flow creation failed(0x%x): %s",
		       flow_name, error.type,
		       error.message ? error.message :
		       "(no stated reason)");

	return flow;
}

int offload_flow_add(portid_t port_id,
		     struct fw_session *session,
		     enum flow_action action,
		     enum flow_dir dir)
{
#define MAX_FLOW_ITEM (6)
#define MAX_ACTION_ITEM (6)
	struct rte_flow_item flow_pattern[MAX_FLOW_ITEM];
	struct rte_flow_action actions[MAX_ACTION_ITEM];
	struct rte_flow_action_age age = {};
	struct rte_flow_item_vlan vlan_spec;
	struct rte_flow_item vlan_item;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_ipv6 ipv6_mask;
	struct rte_flow_item ip_item;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item udp_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item tcp_item;
	enum rte_flow_item_type ip_type;
	void *ip_spec, *ip_mask;
	struct rte_flow *flow = NULL;
	uint8_t i = 0, flow_index = 0;
	int ret = -1;

	struct rte_flow_action age_action = {
		RTE_FLOW_ACTION_TYPE_AGE,
		&age
	};

	memset(&flow_pattern, 0, sizeof(flow_pattern));

	/* Eth item*/
	flow_pattern[flow_index++] = eth_item;

	/* Vlan item */
	if (session->info.vlan) {
		memset(&vlan_item, 0, sizeof(vlan_item));
		vlan_item.type = RTE_FLOW_ITEM_TYPE_VLAN;
		vlan_item.spec = &vlan_spec;
		vlan_item.mask = &rte_flow_item_vlan_mask,

		memset(&vlan_spec, 0, sizeof(vlan_spec));
		vlan_spec.tci = htons(session->info.vlan);
		vlan_spec.inner_type = 0;

		flow_pattern[flow_index++] = vlan_item;
	}

	/* IP item */
	switch (session->info.ip_ver) {
	case IPPROTO_IP:
		ip_type = RTE_FLOW_ITEM_TYPE_IPV4;

		memset(&ipv4_spec, 0, sizeof(ipv4_spec));
		ipv4_spec.hdr.next_proto_id = session->info.proto;
		if (dir == DIR_IN) {
			ipv4_spec.hdr.src_addr = htonl(session->info.src_ip);
			ipv4_spec.hdr.dst_addr = htonl(session->info.dst_ip);
		} else if (dir == DIR_OUT) {
			ipv4_spec.hdr.src_addr = htonl(session->info.dst_ip);
			ipv4_spec.hdr.dst_addr = htonl(session->info.src_ip);
		}
		ip_spec = &ipv4_spec;

		memset(&ipv4_mask, 0, sizeof(ipv4_mask));
		ipv4_mask.hdr.next_proto_id = 0xFF;
		ipv4_mask.hdr.src_addr = 0xFFFFFFFF;
		ipv4_mask.hdr.dst_addr = 0xFFFFFFFF;
		ip_mask = &ipv4_mask;
		break;
	case IPPROTO_IPV6:
		ip_type = RTE_FLOW_ITEM_TYPE_IPV6;

		memset(&ipv6_spec, 0, sizeof(ipv6_spec));
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

		memset(&ipv6_mask, 0, sizeof(ipv6_mask));
		ipv6_mask.hdr.proto = 0xFF;
		memset(&ipv6_mask.hdr.src_addr, 1, sizeof(struct in6_addr));
		memset(&ipv6_mask.hdr.dst_addr, 1, sizeof(struct in6_addr));
		ip_mask = &ipv6_mask;
		break;
	}

	ip_item.type = ip_type;
	ip_item.spec = ip_spec;
	ip_item.mask = ip_mask;
	ip_item.last = NULL;

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
		udp_spec.hdr.dgram_len = 0;
		udp_spec.hdr.dgram_cksum = 0;

		udp_mask.hdr.src_port = 0xFFFF;
		udp_mask.hdr.dst_port = 0xFFFF;
		udp_mask.hdr.dgram_len = 0;
		udp_mask.hdr.dgram_cksum = 0;

		udp_item.type = RTE_FLOW_ITEM_TYPE_UDP;
		udp_item.spec = &udp_spec;
		udp_item.mask = &udp_mask;
		udp_item.last = NULL;

		flow_pattern[flow_index++] = udp_item;
		break;
	case IPPROTO_TCP:
		memset(&tcp_spec, 0, sizeof(tcp_spec));

		if (dir == DIR_IN) {
			tcp_spec.hdr.src_port = htons(session->info.src_port);
			tcp_spec.hdr.dst_port = htons(session->info.dst_port);
		} else if (dir == DIR_OUT) {
			tcp_spec.hdr.src_port = htons(session->info.dst_port);
			tcp_spec.hdr.dst_port = htons(session->info.src_port);
		}

		tcp_spec.hdr.tcp_flags = 0;

		memset(&tcp_mask, 0, sizeof(tcp_mask));
		tcp_mask.hdr.src_port = 0xFFFF;
		tcp_mask.hdr.dst_port = 0xFFFF;
		tcp_mask.hdr.tcp_flags = RTE_TCP_FIN_FLAG |
					 RTE_TCP_SYN_FLAG |
					 RTE_TCP_RST_FLAG;

		tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
		tcp_item.spec = &tcp_spec;
		tcp_item.mask = &tcp_mask;
		tcp_item.last = NULL;

		flow_pattern[flow_index++] = tcp_item;
		break;
	default:
		return -EPROTONOSUPPORT;
	}

	flow_pattern[flow_index] = end_item;
	if (flow_index >= MAX_FLOW_ITEM) {
		log_error("Offload flow: flow item overflow");
		return -EINVAL;
	}

	attr.ingress = 1;
	attr.transfer = 1;

	if (session->timeout)
		age.timeout = session->timeout;
	else
		age.timeout = DEFAULT_TIMEOUT;

	if (dir == DIR_IN) {
		age.context = &session->flow_in;
	} else {
		age.context = &session->flow_out;
	}

	/* Fill actions */
	memset(&actions, 0, sizeof(actions));
	switch(action)
	{
	case ACTION_FORWARD:
		attr.priority = FDB_FWD_PRIORITY;
		actions[i++] = jump_action;
		actions[i++] = age_action;
		actions[i++] = end_action;
		break;
	case ACTION_DROP:
		attr.priority = FDB_DROP_PRIORITY;
		actions[i++] = drop_action;
		actions[i++] = age_action;
		actions[i++] = end_action;
		break;
	default:
		log_error("Offload flow: invalid action");
		return -EOPNOTSUPP;
	}

	flow = add_simple_flow(port_id, &attr, flow_pattern,
			       actions, "offload");

	if (dir == DIR_IN) {
		session->flow_in.session = session;
		session->flow_in.flow = flow;
		session->flow_in.portid = port_id;
		rte_atomic32_set(&session->flow_in.ref_count, 1);
	} else {
		session->flow_out.session = session;
		session->flow_out.flow = flow;
		session->flow_out.portid = port_id;
		rte_atomic32_set(&session->flow_out.ref_count, 1);
	}

	return 0;
}

int offload_flow_query(portid_t port_id, struct rte_flow *flow,
		       uint64_t *packets, uint64_t *bytes)
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

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return -EINVAL;

	memset(action, 0, sizeof(action));
	action[0].type = RTE_FLOW_ACTION_TYPE_COUNT;
	action[0].conf = &flow_count;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x55, sizeof(error));

	if (rte_flow_query(port_id, flow, action, &flow_count, &error))
		return port_flow_complain(&error);

	*packets = flow_count.hits;
	*bytes = flow_count.bytes;

	return 0;
}

int offload_flow_destroy(portid_t port_id, struct rte_flow *flow)
{
	struct rte_flow_error error;
	int ret = 0;

	if (!flow)
		return 0;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return -EINVAL;

	memset(&error, 0x33, sizeof(error));
	if (rte_flow_destroy(port_id, flow, &error))
		ret = port_flow_complain(&error);

	return ret;
}

void offload_flow_aged(portid_t port_id)
{
	int nb_context, total = 0, idx;
	struct rte_flow_error error;
	struct fw_session *session;
	struct offload_flow *flow;
	void **contexts;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN) ||
	    port_id == (portid_t)RTE_PORT_ALL)
		return;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total < 0) {
		port_flow_complain(&error);
		return;
	}
	if (total == 0)
		return;
	contexts = malloc(sizeof(void *) * total);
	if (contexts == NULL)
		return;
	nb_context = rte_flow_get_aged_flows(port_id, contexts,
					     total, &error);
	if (nb_context != total) {
		free(contexts);
		return;
	}

	for (idx = 0; idx < nb_context; idx++) {
		flow = (struct offload_flow *)contexts[idx];
		if (!flow)
			continue;
		session = flow->session;

		rte_atomic32_set(&flow->ref_count, 0);

		/* Only delete flow when both directions are aged out.
		 * This hides the bug that the counter on one of the
		 * direction is not updating
		 */
		if (!rte_atomic32_read(&session->flow_in.ref_count) &&
		    !rte_atomic32_read(&session->flow_out.ref_count)) {
			session->close_code = _TIMEOUT;
			ret = opof_del_flow(session);
			if (!ret)
				rte_atomic32_inc(&off_config_g.stats.aged);
		}
	}
	free(contexts);
}

int offload_flow_flush(portid_t port_id)
{
	struct rte_flow_error error;
	int ret = 0;

	memset(&error, 0x44, sizeof(error));
	if (rte_flow_flush(port_id, &error)) {
		ret = port_flow_complain(&error);
		if (port_id_is_invalid(port_id, DISABLED_WARN) ||
		    port_id == (portid_t)RTE_PORT_ALL)
			return ret;
	}

	return ret;
}
