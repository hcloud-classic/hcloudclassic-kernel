/*
 *  hcc/gscheduler/placement.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <hcc/sys/types.h>
#include <hcc/gscheduler/process_set.h>
#include <hcc/gscheduler/policy.h>
#include <hcc/gscheduler/gscheduler.h>

struct task_struct;

static hcc_node_t gscheduler_new_task_node(struct gscheduler *gscheduler,
						struct task_struct *parent)
{
	struct gscheduler_policy *p;
	hcc_node_t node = HCC_NODE_ID_NONE;

	p = gscheduler_get_gscheduler_policy(gscheduler);
	if (!p)
		goto out;
	node = gscheduler_policy_new_task_node(p, parent);
	gscheduler_policy_put(p);
out:
	return node;
}


/*
 * The parsing order of gschedulers is:
 * - all universal gscheduler in reversed attachment order (last attached to all
 *   processes is parsed first);
 * - all gschedulers attached to parent, in reversed attachment order.
 *
 * The first gscheduler returning a valid node id wins.
 */
hcc_node_t new_task_node(struct task_struct *parent)
{
	hcc_node_t node = HCC_NODE_ID_NONE;
	struct gscheduler *s;
#define QUERY_GSCHEDULER(s)				   \
		node = gscheduler_new_task_node(s, parent); \
		if (node != HCC_NODE_ID_NONE) {	   \
			gscheduler_put(s);		   \
			goto out;			   \
		}

	rcu_read_lock();
	do_each_gscheduler_universal(s) {
		QUERY_GSCHEDULER(s);
	} while_each_gscheduler_universal(s);
	do_each_gscheduler_task(s, parent) {
		QUERY_GSCHEDULER(s);
	} while_each_gscheduler_task(s, parent);
out:
	rcu_read_unlock();

	return node;
}
