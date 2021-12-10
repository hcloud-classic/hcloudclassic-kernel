#ifndef __HCC_GSCHEDULER_PLACEMENT_H__
#define __HCC_GSCHEDULER_PLACEMENT_H__

#include <hcc/sys/types.h>

struct task_struct;

/**
 * Compute the "best" node on which a new task should be placed.
 * The node is chosen by asking to each gscheduler attached to parent. Ties
 * are broken as described in placement.c
 *
 * @param parent	creator of the new task
 *
 * @return		a valid node id (at least when computed), or
 *			HCC_NODE_ID_NONE if no gscheduler attached to
 *			parent cares
 */
hcc_node_t new_task_node(struct task_struct *parent);

#endif /* __HCC_GSCHEDULER_PLACEMENT_H__ */
