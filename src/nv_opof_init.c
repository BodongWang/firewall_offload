/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */
#include "nv_opof.h"

uint16_t nb_rxd = RX_RING_SIZE;
uint16_t nb_txd = TX_RING_SIZE;
queueid_t nb_txq = NUM_REGULAR_Q;
queueid_t nb_rxq = NUM_REGULAR_Q;
queueid_t nb_hpq = NUM_HP_Q;
queueid_t hp_qi = NUM_REGULAR_Q + NUM_HP_Q - 1;

static int nv_opof_setup_hairpin_queues(portid_t pi, portid_t peer_pi)
{
	queueid_t qi;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind= true,
		.tx_explicit = true
	};
	int i, diag;

	for (qi = nb_txq, i = 0; qi < nb_hpq + nb_txq; qi++) {
		hairpin_conf.peers[0].port = peer_pi;
		hairpin_conf.peers[0].queue = i + nb_rxq;
		diag = rte_eth_tx_hairpin_queue_setup
			(pi, qi, nb_txd, &hairpin_conf);
		i++;
		if (diag == 0)
			continue;

		log_error("Fail to configure port %d TX hairpin "
			  "queues %u, err=%d", pi, i, diag);
		return -1;
	}

	for (qi = nb_rxq, i = 0; qi < nb_hpq + nb_rxq; qi++) {
		hairpin_conf.peers[0].port = peer_pi;
		hairpin_conf.peers[0].queue = i + nb_txq;
		diag = rte_eth_rx_hairpin_queue_setup
			(pi, qi, nb_rxd, &hairpin_conf);
		i++;
		if (diag == 0)
			continue;

		log_error("Fail to configure port %d RX hairpin "
			  "queues %u", pi, i);
		return -1;
	}

	log_info("Port(%d): Set up hairpin with peer %d", pi, peer_pi);

	return 0;
}

static struct rte_flow *
nv_opof_create_fdb_miss_flow(uint16_t port_id, portid_t dest_port_id)
{
	struct rte_flow_attr attr = {
		.ingress = 1,
		.transfer = 1,
		.priority = FDB_NO_MATCH_PRIORITY,
	};
	struct rte_flow_action_port_id dest_port = {
		.id = dest_port_id,
	};
	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
		{ .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &dest_port },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};

	return nv_opof_add_simple_flow(port_id, &attr, pattern,
			       action, "Fdb miss");
}

static struct rte_flow *
nv_opof_create_to_uplink_flow(uint16_t port_id, portid_t dest_port_id)
{
	struct rte_flow_attr attr = {
		.ingress = 1,
		.transfer = 1,
		.priority = FDB_NO_MATCH_PRIORITY,
	};
	struct rte_flow_action_port_id dest_port = {
		.id = dest_port_id,
	};

	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
		{ .type = RTE_FLOW_ACTION_TYPE_PORT_ID, .conf = &dest_port },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};

	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};

	return nv_opof_add_simple_flow(port_id, &attr, pattern,
			       action, "Fdb miss");
}

static struct rte_flow * 
nv_opof_create_hairpin_flow(uint16_t port_id)
{
	uint16_t hpq_indices[NUM_HP_Q];

	struct rte_flow_action_rss rss_conf = {
		.func = RTE_ETH_HASH_FUNCTION_DEFAULT,
		.level = 0,
		.types = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
		.queue_num = nb_hpq,
		.queue = hpq_indices,
	};
	struct rte_flow_attr attr = {
		.ingress = 1,
		.group = 0,
	};
	struct rte_flow_action action[] = {
		{ .type = RTE_FLOW_ACTION_TYPE_COUNT },
		{ .type = RTE_FLOW_ACTION_TYPE_RSS, .conf = &rss_conf },
		{ .type = RTE_FLOW_ACTION_TYPE_END },
	};
	struct rte_flow_item pattern[] = {
		{ .type = RTE_FLOW_ITEM_TYPE_ETH },
		{ .type = RTE_FLOW_ITEM_TYPE_END },
	};

	for (int i=0; i<NUM_HP_Q; i++) {
		hpq_indices[i] = NUM_REGULAR_Q + i;
	}

	return nv_opof_add_simple_flow(port_id, &attr, pattern,
			       action, "Haripin");
}

uint32_t next_sample_session_id = MAX_SESSION;
uint32_t num_sample_flows = 0;

int nv_opof_create_sample_fwd_flow(int proto,
				  enum flow_action action,
				  int dir)
{
	addSessionResponse_t response;
	sessionRequest_t request;
	int ret = 0;

	memset(&response, 0, sizeof(response));
	memset(&request, 0, sizeof(request));

	request.sessId = --next_sample_session_id;
	request.actType = action;
	request.proto = proto;

	if (dir) {
		++num_sample_flows;
	}

	if (dir) {
		request.inlif = 2;
		request.srcIP.s_addr = 0x10000000 + num_sample_flows; // 16.0.0.1, ...
		request.dstIP.s_addr = 0x30000000 + num_sample_flows; // 48.0.0.1, ...
		//request.dstPort = 5003;
		//request.srcPort = 5002;
		request.srcPort = 53;
		request.dstPort = 53;
	} else {
		request.inlif = 1;
		request.dstIP.s_addr = 0x10000000 + num_sample_flows; // 16.0.0.1
		request.srcIP.s_addr = 0x30000000 + num_sample_flows; // 48.0.0.1
		request.srcPort = 53;
		request.dstPort = 53;
	}

	request.cacheTimeout = 60;

	ret = opof_add_session_server(&request, &response);
	if (!ret)
		log_info("Warning: Sample flow created for session (%lu) src %x dst %x",
		       request.sessId, request.srcIP.s_addr, request.dstIP.s_addr);

	return ret;
}

int nv_opof_init_flows(portid_t pid)
{
	if (off_config_g.phy_port[pid] != PORT_ID_INVALID) {
		if (nv_opof_create_to_uplink_flow(pid, off_config_g.phy_port[pid]) == NULL)
			return -EAGAIN;
	}
	/* Default RX rule to forward to hairpin queue. */
	if (off_config_g.peer_port[pid] != PORT_ID_INVALID) {
		struct rte_flow * hpq_flow = nv_opof_create_hairpin_flow(pid);
		if (hpq_flow == NULL)
			return -EAGAIN;
	}
	/* Default RX rule to forward no match pkt to vport. */
	if (off_config_g.vf_port[pid] != PORT_ID_INVALID) {
		if (!nv_opof_create_fdb_miss_flow(pid, off_config_g.vf_port[pid]))
			return -EAGAIN;
	}

	return 0;
}

int nv_opof_port_init(portid_t pid, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		},
	};
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	int retval;
	uint16_t q;

	if (!rte_eth_dev_is_valid_port(pid))
		return -EINVAL;

	rte_eth_dev_info_get(pid, &dev_info);

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(pid, nb_rxq + nb_hpq,
				       nb_txq + nb_hpq, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(pid, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet pid. */
	for (q = 0; q < nb_rxq; q++) {
		retval = rte_eth_rx_queue_setup(pid, q, nb_rxd,
				rte_eth_dev_socket_id(pid), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet pid. */
	for (q = 0; q < nb_txq; q++) {
		retval = rte_eth_tx_queue_setup(pid, q, nb_txd,
				rte_eth_dev_socket_id(pid), &txconf);
		if (retval < 0)
			return retval;
	}

	if (off_config_g.peer_port[pid] != PORT_ID_INVALID)
		nv_opof_setup_hairpin_queues(pid, off_config_g.peer_port[pid]);

	/* Start the Ethernet pid. */
	retval = rte_eth_dev_start(pid);
	if (retval < 0) {
		log_error("Can't start eth dev");
		return retval;
	}

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(pid);
	if (retval != 0)
		return retval;

	return 0;
}

int nv_opof_hairpin_bind_port(portid_t pid)
{
	uint16_t peer_id;
	int diag;

	peer_id = off_config_g.peer_port[pid];

	diag = rte_eth_hairpin_bind(pid, peer_id);
	if (diag) {
		log_error("Failed to bind hairpin TX port %u to %u: %s",
			 pid, peer_id, rte_strerror(-diag));
		return diag;
	}

	diag = rte_eth_hairpin_bind(peer_id, pid);
	if (diag) {
		log_error("Failed to bind hairpin RX port %u to %u: %s",
			 peer_id, pid, rte_strerror(-diag));
		return diag;
	}

	return 0;
}
