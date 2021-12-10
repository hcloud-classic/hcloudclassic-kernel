/*
 *  hcc/gscheduler/policies/round_robin_balancer.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

/**
 * Simple per node round robin placement policy.
 *
 * The first node chosen is the next node in ring, and subsequent nodes are
 * obtained in node id order.
 *
 * E.g: let a cluster have node ids 0 2 3 5
 *      - from node 0, the sequence will be 2 3 5 0 2 3 5 0 2 ...
 *      - from node 2, the sequence will be 3 5 0 2 3 5 0 2 3 ...
 *
 * All instance are strictly independent.
 *
 * @author Innogrid HCC
 */

#include <linux/module.h>
#include <linux/spinlock.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>
#include <hcc/gscheduler/policy.h>
#include <hcc/gscheduler/gscheduler.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Innogrid HCC");
MODULE_DESCRIPTION("Load balancing policy based on round robin placement");

struct round_robin_balancer {
	struct gscheduler_policy policy;
	hcc_node_t last_target;
};

static inline
struct round_robin_balancer *
to_round_robin_balancer(struct gscheduler_policy *policy)
{
	return container_of(policy, struct round_robin_balancer, policy);
}

static inline void rrb_lock(struct round_robin_balancer *rrb)
{
	spin_lock(&rrb->policy.lock);
}

static inline void rrb_unlock(struct round_robin_balancer *rrb)
{
	spin_unlock(&rrb->policy.lock);
}

static
hcc_node_t
round_robin_balancer_new_task_node(struct gscheduler_policy *policy,
				   struct task_struct *parent)
{
	struct round_robin_balancer *rrb = to_round_robin_balancer(policy);
	struct gscheduler *s = gscheduler_policy_get_gscheduler(policy);
	hcc_nodemask_t nodes;
	hcc_node_t node = HCC_NODE_ID_NONE;

	if (!s)
		goto out;
	gscheduler_get_node_set(s, &nodes);

	rrb_lock(rrb);
	node = rrb->last_target;
	if (node == HCC_NODE_ID_NONE)
		node = hcc_node_id;
	node = next_hcc_node_in_ring(node, nodes);
	rrb->last_target = node;
	rrb_unlock(rrb);

	gscheduler_put(s);
out:
	return node;
}

/* gscheduler_policy_attributes */

static
ssize_t last_target_attr_show(struct gscheduler_policy *policy, char *page)
{
	struct round_robin_balancer *rrb = to_round_robin_balancer(policy);
	return sprintf(page, "%d\n", rrb->last_target);
}

static struct gscheduler_policy_attribute last_target_attr = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "last_target",
		.ca_mode = S_IRUGO,
	},
	.show = last_target_attr_show,
};

static struct gscheduler_policy_attribute *round_robin_balancer_attrs[] = {
	&last_target_attr,
	NULL
};

/* gscheduler_policy_type*/

static struct gscheduler_policy *round_robin_balancer_new(const char *name);
static void round_robin_balancer_destroy(struct gscheduler_policy *policy);

static struct gscheduler_policy_operations round_robin_balancer_ops = {
	.new = round_robin_balancer_new,
	.destroy = round_robin_balancer_destroy,
	.new_task_node = round_robin_balancer_new_task_node,
};

static GSCHEDULER_POLICY_TYPE(round_robin_balancer, "round_robin_balancer",
			     &round_robin_balancer_ops,
			     round_robin_balancer_attrs);

static struct gscheduler_policy *round_robin_balancer_new(const char *name)
{
	struct round_robin_balancer *rrb = kmalloc(sizeof(*rrb), GFP_KERNEL);
	int err;

	if (!rrb)
		goto err_rrb;
	rrb->last_target = HCC_NODE_ID_NONE;
	err = gscheduler_policy_init(&rrb->policy, name, &round_robin_balancer,
				    NULL);
	if (err)
		goto err_policy;

	return &rrb->policy;

err_policy:
	kfree(rrb);
err_rrb:
	return NULL;
}

static void round_robin_balancer_destroy(struct gscheduler_policy *policy)
{
	struct round_robin_balancer *rrb = to_round_robin_balancer(policy);
	gscheduler_policy_cleanup(policy);
	kfree(rrb);
}

/* module init/exit */

int round_robin_balancer_init(void)
{
	return gscheduler_policy_type_register(&round_robin_balancer);
}

void round_robin_balancer_exit(void)
{
	gscheduler_policy_type_unregister(&round_robin_balancer);
}

module_init(round_robin_balancer_init);
module_exit(round_robin_balancer_exit);
