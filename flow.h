#ifndef __BRIDGER_FLOW_H
#define __BRIDGER_FLOW_H

struct bridger_flow {
	struct avl_node node;
	struct avl_node sort_node;
	struct bridger_flow_key key;
	struct bridger_offload_flow offload;

	uint64_t avg_packets;
	uint64_t cur_packets;

	struct fdb_entry *fdb_in, *fdb_out;
	struct list_head fdb_in_list, fdb_out_list;
};

int bridger_flow_init(void);
void bridger_flow_delete(struct bridger_flow *flow);
void bridger_check_pending_flow(struct bridger_flow_key *key, struct bridger_pending_flow *val);

#endif
