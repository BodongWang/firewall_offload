/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Nvidia
 */

#ifndef NV_OPOF_H
#define NV_OPOF_H

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/cdefs.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ring_elem.h>

#include "opof_serverlib.h"
#include "nv_opof_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NV_OPOF_VERSION "1.1.0"

#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024

#define MAX_LCORES	(16u)

#define NUM_REGULAR_Q	(1)
#define NUM_HP_Q	(4)

#define MAX_SESSION		(4000000u)
#define SAMPLE_SESSION_FWD	(MAX_SESSION - 1)
#define SAMPLE_SESSION_DROP	(MAX_SESSION - 2)

#define GRPC_ADDR_SIZE		(32)
#define DEFAULT_GRPC_ADDR	"169.254.33.51"
#define DEFAULT_GRPC_PORT	3443

#define PORT_ID_INVALID ((portid_t)-1)

typedef uint16_t queueid_t;
typedef uint16_t portid_t;

extern struct fw_offload_config off_config_g;

enum {
	portid_pf0,
	portid_pf0_vf0,
	portid_pf1,
	portid_pf1_vf0,
	MAX_DPDK_PORT
};

enum {
	INITIATOR_PORT_ID = portid_pf0,
	RESPONDER_PORT_ID = portid_pf1
};

// Note that regardless of priority, FDB (transfer) rules always
// take precedence / execute before NIC (non-transfer) rules.
// When the FDB executes a jump to a non-existing group
// (NIC_RX_GROUP), only then are the NIC-domain rules evaluated.
#define FDB_DROP_PRIORITY     1
#define FDB_FWD_PRIORITY      2
#define FDB_NO_MATCH_PRIORITY 3

// The ID of a non-existing FDB flow group.
// Once a packet lookup reaches this group, it
// transitions from the FDB domain to the NIC RX domain.
// From the NIC RX domain, a packet can be hairpin-
// queued and sent out the uplink port.
enum {
	NIC_RX_GROUP = 0xA,
};

enum lcore_type {
	LCORE_TYPE_MIN		= 1,
	LCORE_TYPE_GRPC		= 1,
	LCORE_TYPE_AGING	= 2,
	LCORE_TYPE_MAX		= 3
};

enum {
	/* unit sec */
	DEFAULT_TIMEOUT		= 10,
	MAX_TIMEOUT		= 3275
};

enum print_warning {
	ENABLED_WARN = 0,
	DISABLED_WARN
};

enum flow_action {
	ACTION_DROP	= 0,
	ACTION_FORWARD	= 1
};

enum flow_dir {
	DIR_IN	= 0,
	DIR_OUT	= 1
};

struct lcore_priv {
	enum lcore_type	type;
	uint8_t		id;
};

struct aging_priv {
	uint8_t lcore_id;
};

struct session_info {
	uint32_t dst_ip;         /**< Dest IPv4 address in big endian. */
	uint32_t src_ip;         /**< Source IPv4 address in big endian. */
	uint8_t dst_ipv6[16];    /**< Dest IPv6 address in big endian. */
	uint8_t src_ipv6[16];    /**< Source IPv6 address in big endian. */
	uint16_t dst_port;       /**< Dest port in big endian. */
	uint16_t src_port;       /**< Source Port in big endian. */
	uint8_t ip_ver;          /**< IP version. */
	uint8_t proto;           /**< L4 Protocol. */
	uint16_t vlan;
	bool tunnel;
};

struct session_key {
	uint64_t sess_id;
};

// This structure is passed as the age.context parameter to ensure flows are properly
// aged out and removed, but only after all the flows associated with a session have
// individually timed out.
struct offload_flow {
	struct fw_session *session;
	struct rte_flow *flow;
	rte_atomic32_t ref_count;
	portid_t portid;
};

struct fw_session {
	struct session_key		key;
	struct session_info		info;
	enum flow_action        action;

	struct offload_flow		flow_in;
	struct offload_flow		flow_out;

	uint8_t				state;
	uint8_t				close_code;
	uint32_t			timeout;
};

struct offload_stats {
	rte_atomic32_t active;
	rte_atomic32_t aged;
	rte_atomic32_t zero_in;
	rte_atomic32_t zero_out;
	rte_atomic32_t zero_io;
	rte_atomic32_t client_del;
	rte_atomic32_t age_thread_hb;
	rte_atomic32_t flows_in;
	rte_atomic32_t flows_del;
	rte_atomic32_t flows_get_closed;
	rte_atomic64_t flows_in_maxtsc;
	rte_atomic64_t flows_in_tottsc;
	rte_atomic64_t flows_del_maxtsc;
	rte_atomic64_t flows_del_tottsc;
	rte_atomic64_t flows_get_closed_maxtsc;
	rte_atomic64_t flows_get_closed_tottsc;
};

struct fw_offload_config {
	struct lcore_priv	lcores[MAX_LCORES];
	struct aging_priv	aging;
	struct rte_ring		*session_fifo;
	struct rte_hash		*session_ht;
	pthread_mutex_t		ht_lock;
	struct offload_stats	stats;

	bool     is_port_used[MAX_DPDK_PORT]; /**< whether to initialize the port */
	portid_t phy_port[MAX_DPDK_PORT]; /**< specifies the destination for pkts from the VF representors */
	portid_t peer_port[MAX_DPDK_PORT]; /**< specifies the hairpin pairs */
	portid_t vf_port[MAX_DPDK_PORT]; /**< specifies "miss" destination for pkts from PF uplinks */

	char grpc_addr[GRPC_ADDR_SIZE];
	uint16_t grpc_port;

	bool overwrite_dst_mac_enabled;
	struct rte_ether_addr overwrite_dst_mac;	
};

int nv_opof_port_init(portid_t pid, struct rte_mempool *mbuf_pool);
int nv_opof_hairpin_bind_port(portid_t pid);
int nv_opof_init_flows(portid_t pid);
int nv_opof_create_sample_fwd_flow(int proto, enum flow_action action, int dir);

void nv_opof_lcore_init(void);
void nv_opof_clean_up(void);
void nv_opof_force_quit(void);
int nv_opof_thread_mux(void *data __rte_unused);

struct rte_flow *
nv_opof_add_simple_flow(uint16_t port_id,
		struct rte_flow_attr *attr,
		struct rte_flow_item pattern[],
		struct rte_flow_action actions[],
		const char *flow_name);

int nv_opof_offload_flow_add(portid_t port_id,
		     struct fw_session * session,
		     enum flow_dir dir);
int nv_opof_offload_flow_query(portid_t port_id,
		       struct rte_flow *flow,
		       int64_t *packets,
		       int64_t *bytes);
int nv_opof_offload_flow_destroy(portid_t port_id,
			 struct rte_flow *flow);
void nv_opof_offload_flow_aged(portid_t port_id);
int nv_opof_offload_flow_flush(portid_t port_id);

int opof_del_flow(struct fw_session *session);
void opof_del_all_session_server(void);
int _opof_del_session_server(unsigned long sessionId,
			     sessionResponse_t *response);

char *get_session_state(uint8_t state);
char *get_close_code(uint8_t code);
int offload_flow_test(portid_t port_id, uint32_t num);

#ifdef __cplusplus
}
#endif

#endif
