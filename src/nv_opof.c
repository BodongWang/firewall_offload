/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */
#include "nv_opof.h"
#include "nv_opof_rpc.h"

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250

static struct nv_opof_rpc_context rpc_ctx = {};
struct fw_offload_config off_config_g;

static uint32_t next_pow2(uint32_t x)
{
	return x == 1 ? 1 : 1 << (64 - __builtin_clzl(x - 1));
}

static struct rte_hash* create_session_hash_table(void)
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

static void config_init(void)
{
	memset(&off_config_g, 0, sizeof(struct fw_offload_config));

	strcpy(off_config_g.grpc_addr, DEFAULT_GRPC_ADDR);
	off_config_g.grpc_port = DEFAULT_GRPC_PORT;

	off_config_g.phy_port[portid_pf0] = portid_pf0;
	off_config_g.phy_port[portid_pf0_vf0] = portid_pf0;
	off_config_g.phy_port[portid_pf1] = portid_pf1;
	off_config_g.phy_port[portid_pf1_vf0] = portid_pf1;

	off_config_g.peer_port[portid_pf0] = portid_pf1;
	off_config_g.peer_port[portid_pf0_vf0] = portid_pf1_vf0;
	off_config_g.peer_port[portid_pf1] = portid_pf0;
	off_config_g.peer_port[portid_pf1_vf0] = portid_pf0_vf0;

	off_config_g.vf_port[portid_pf0] = portid_pf0_vf0;
	off_config_g.vf_port[portid_pf0_vf0] = portid_pf0_vf0;
	off_config_g.vf_port[portid_pf1] = portid_pf1_vf0;
	off_config_g.vf_port[portid_pf1_vf0] = portid_pf1_vf0;

	off_config_g.session_ht = create_session_hash_table();
	off_config_g.session_fifo = rte_ring_create("sess_fifo",
						    next_pow2(MAX_SESSION), 0, 0);

	off_config_g.ports = rte_zmalloc("ports",
					 sizeof(struct rte_port) *
					 RTE_MAX_ETHPORTS,
					 RTE_CACHE_LINE_SIZE);
	if (!off_config_g.ports)
		rte_exit(EXIT_FAILURE,
			 "rte_zmalloc(%d struct rte_port) failed\n",
			 RTE_MAX_ETHPORTS);
}

static void config_destroy(void)
{
	rte_free(off_config_g.ports);
	rte_ring_free(off_config_g.session_fifo);
	rte_hash_free(off_config_g.session_ht);
}

void clean_up(void)
{
	portid_t portid;

	nv_opof_rpc_stop(&rpc_ctx);
	opof_del_all_session_server();
	config_destroy();

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		offload_flow_flush(portid);
		//FIXME: segfault for 2nd port
		//rte_eth_dev_close(portid);
	}

	log_info("nv_opof closed");
	nv_opof_log_close();
	nv_opof_signal_handler_uninstall();
}

int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
	int ret;

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 4)
		rte_exit(EXIT_FAILURE, "Error: 1 VF is needed for each port\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	nv_opof_signal_handler_install();
	nv_opof_log_open();

	log_info("nv_opof started");
	ret = nv_opof_config_load(CONFIG_FILE);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot load config file\n");

	config_init();

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool))
			rte_exit(EXIT_FAILURE,
				 "Cannot init port %"PRIu16 "\n", portid);

	RTE_ETH_FOREACH_DEV(portid)
		if (hairpin_bind_port(portid))
			rte_exit(EXIT_FAILURE,
				 "Cannot bind hairpin port %"PRIu16 "\n",portid);

	lcore_init();

	rte_eal_mp_remote_launch(&thread_mux, NULL, CALL_MAIN);

	ret = nv_opof_rpc_start(&rpc_ctx);
	if (ret)
		rte_exit(EXIT_FAILURE, "Cannot enable rpc interface\n");

	rte_eal_mp_wait_lcore();

	return 0;
}
