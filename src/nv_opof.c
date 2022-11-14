/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */
#include "nv_opof.h"
#include "nv_opof_rpc.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

static struct nv_opof_rpc_context rpc_ctx = {};
struct fw_offload_config off_config_g = {
	.grpc_addr = DEFAULT_GRPC_ADDR,
	.grpc_port = DEFAULT_GRPC_PORT,
};

static uint32_t next_pow2(uint32_t x)
{
	return x == 1 ? 1 : 1 << (64 - __builtin_clzl(x - 1));
}

static struct rte_hash* nv_opof_create_session_hash_table(void)
{
	struct rte_hash_parameters params;
	struct rte_hash *h;
	char name[16];

	memset(&params, 0, sizeof(params));
	snprintf(name, sizeof(name), "session_ht");
	params.name = name;
	params.entries = MAX_SESSION;
	params.key_len = sizeof(struct session_key);
	params.hash_func_init_val = 0;
	params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;

	h = rte_hash_create(&params);

	return h;
}

static void nv_opof_config_init()
{
	// destination of packets from the FW
	off_config_g.phy_port[portid_pf0] = PORT_ID_INVALID;
	off_config_g.phy_port[portid_pf0_vf0] = portid_pf0;
	off_config_g.phy_port[portid_pf1] = PORT_ID_INVALID;
	off_config_g.phy_port[portid_pf1_vf0] = portid_pf1;

	// destination of offloaded packets
	off_config_g.peer_port[portid_pf0] = portid_pf1;
	off_config_g.peer_port[portid_pf0_vf0] = PORT_ID_INVALID;
	off_config_g.peer_port[portid_pf1] = portid_pf0;
	off_config_g.peer_port[portid_pf1_vf0] = PORT_ID_INVALID;

	// destination of packets from the uplink
	off_config_g.vf_port[portid_pf0] = portid_pf0_vf0;
	off_config_g.vf_port[portid_pf0_vf0] = PORT_ID_INVALID;
	off_config_g.vf_port[portid_pf1] = portid_pf1_vf0;
	off_config_g.vf_port[portid_pf1_vf0] = PORT_ID_INVALID;

	off_config_g.is_port_used[portid_pf0] = true;
	off_config_g.is_port_used[portid_pf0_vf0] = true;
	off_config_g.is_port_used[portid_pf1] = true;
	off_config_g.is_port_used[portid_pf1_vf0] = true;

	pthread_mutex_init(&off_config_g.ht_lock, NULL);
	off_config_g.session_ht = nv_opof_create_session_hash_table();
	off_config_g.session_fifo = rte_ring_create("sess_fifo",
						    next_pow2(MAX_SESSION), 0, 0);
}

static void config_destroy(void)
{
	rte_ring_free(off_config_g.session_fifo);
	rte_hash_free(off_config_g.session_ht);
}

void nv_opof_clean_up(void)
{
	portid_t portid;

	nv_opof_rpc_stop(&rpc_ctx);
	opof_del_all_session_server();
	config_destroy();

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		nv_opof_offload_flow_flush(portid);
		//FIXME: segfault for 2nd port
		//rte_eth_dev_close(portid);
	}

	log_info("nv_opof closed");
	nv_opof_log_close();
	nv_opof_signal_handler_uninstall();
}

int main(int argc, char *argv[])
{
	uint16_t portid;
	int ret;
	int samples_flows_to_create = 0;

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	
	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	uint16_t nb_ports = rte_eth_dev_count_avail();

	uint16_t min_vfs_per_uplink = 2;
	uint16_t min_ports = 2 * min_vfs_per_uplink;

	if (nb_ports < min_ports)
		rte_exit(EXIT_FAILURE, "Error: %d VF(s) are needed for each port\n",
		min_vfs_per_uplink);

	/* Creates a new mempool in memory to hold the mbufs. */
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	nv_opof_signal_handler_install();
	nv_opof_log_open();

	log_info("nv_opof started, version %s", NV_OPOF_VERSION);

	ret = nv_opof_config_load(CONFIG_FILE);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot load config file\n");

	nv_opof_config_init();

	for (int i=1; i<argc; i++) {
		if (!strcmp(argv[i], "--create_sample")) {
			samples_flows_to_create = 1;
			if (i + 1 < argc && argv[i+1][0] != '-') {
				samples_flows_to_create = atoi(argv[i+1]);
			}
		}
		else if (!strcmp(argv[i], "--dmac")) {
			if (i + 1 < argc) {
				if (rte_ether_unformat_addr(argv[i+1], &off_config_g.overwrite_dst_mac) < 0)
					rte_exit(EXIT_FAILURE, "Failed to parse dst mac: %s\n", argv[i+1]);
				off_config_g.overwrite_dst_mac_enabled = true;
			}
		}
	}

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid) {
		if (off_config_g.is_port_used[portid] && nv_opof_port_init(portid, mbuf_pool) != 0) {
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if (off_config_g.is_port_used[portid] &&
			off_config_g.peer_port[portid] != PORT_ID_INVALID &&
			nv_opof_hairpin_bind_port(portid) != 0)
		{
			rte_exit(EXIT_FAILURE,
				"Cannot bind hairpin port %"PRIu16 "\n",portid);
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		if (off_config_g.is_port_used[portid]) {
			nv_opof_init_flows(portid);
		}
	}

	for (int i = 0; i < samples_flows_to_create; i++) {
		nv_opof_create_sample_fwd_flow(IPPROTO_UDP, ACTION_FORWARD, true);
		nv_opof_create_sample_fwd_flow(IPPROTO_UDP, ACTION_FORWARD, false);
	}

	nv_opof_lcore_init();

	rte_eal_mp_remote_launch(&nv_opof_thread_mux, NULL, SKIP_MAIN);

	ret = nv_opof_rpc_start(&rpc_ctx);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot enable rpc interface\n");

	rte_eal_mp_wait_lcore();

	return 0;
}
