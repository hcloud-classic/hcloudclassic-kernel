/*
 *  hcc/proc/libproc.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/pid.h>
#include <gdm/io_linker.h>

/* Generic function to assign a default owner to a pid-named gdm object */
hcc_node_t global_pid_default_owner(struct gdm_set *set, objid_t objid,
					  const hcc_nodemask_t *nodes,
					  int nr_nodes)
{
	hcc_node_t node;

	BUG_ON(!(objid & GLOBAL_PID_MASK));
	node = ORIG_NODE(objid);
	if (node < 0 || node >= HCC_MAX_NODES)
		/* Invalid ID */
		node = hcc_node_id;
	if (node != hcc_node_id
	    && unlikely(!__hcc_node_isset(node, nodes)))
		node = __next_hcc_node_in_ring(node, nodes);
	return node;
}
