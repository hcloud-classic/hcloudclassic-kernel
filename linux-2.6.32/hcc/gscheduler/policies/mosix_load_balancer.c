/*
 *  hcc/gscheduler/policies/mosix_load_balancer.c
 *
 *  Copyright (C) 2019-2021 Innogrid HCC
 */

/**
 * Simplified MOSIX load balancing scheduling policy relying on a caching
 * module to access remote values.
 *
 *  @author Innogrid HCC
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/spinlock.h>
#include <linux/rculist.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>
#include <hcc/pid.h>
#include <hcc/migration.h>
#include <hcc/gscheduler/policy.h>
#include <hcc/gscheduler/port.h>
#include <hcc/gscheduler/gscheduler.h>
#include <hcc/gscheduler/process_set.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Innogrid HCC");
MODULE_DESCRIPTION("Simplified MOSIX load balancing policy");

enum port_id {
	PORT_LOCAL_LOAD,
	PORT_REMOTE_LOAD,
	PORT_SINGLE_PROCESS_LOAD,
	PORT_PROCESS_LOAD,
	PORT_MAX,
};

struct mosix_load_balancer {
	struct gscheduler_policy policy;
	int stab_factor; /* in percents of a single process load */
	struct gscheduler_port ports[PORT_MAX];
	unsigned long tmp_load;
};

static inline
struct mosix_load_balancer *
to_mosix_load_balancer(struct gscheduler_policy *policy)
{
	return container_of(policy, struct mosix_load_balancer, policy);
}

static inline void lb_lock(struct mosix_load_balancer *lb)
{
	spin_lock(&lb->policy.lock);
}

static inline void lb_unlock(struct mosix_load_balancer *lb)
{
	spin_unlock(&lb->policy.lock);
}

static struct pid *find_target_task(struct mosix_load_balancer *lb)
{
	struct gscheduler *gscheduler =
		gscheduler_policy_get_gscheduler(&lb->policy);
	struct process_set *processes;
	struct task_struct *p;
	unsigned long load, highest_load, second_highest_load;
	struct task_struct *max_p, *second_max_p;
	struct pid *ret_pid = NULL;
	pid_t pid;
	int ret;

	if (!gscheduler)
		goto out;
	processes = gscheduler_get_process_set(gscheduler);
	if (!processes)
		goto put_gscheduler;

	highest_load = 0;
	second_highest_load = 0;
	max_p = second_max_p = NULL;

	process_set_prepare_do_each_process(processes);

	process_set_do_each_process(p, processes) {
		if (!may_migrate(p))
			continue;

		pid = task_pid_knr(p);
		ret = gscheduler_port_get_value(&lb->ports[PORT_PROCESS_LOAD],
					       &load, 1, &pid, 1);
		if (ret < 1)
			continue;
		if (load > highest_load) {
			second_highest_load = highest_load;
			second_max_p = max_p;
			max_p = p;
			highest_load = load;
		} else if (load > second_highest_load) {
			second_highest_load = load;
			second_max_p = p;
		}
	} process_set_while_each_process(p, processes);

	if (second_max_p)
		p = second_max_p;
	else {
		if (max_p)
			p = max_p;
		else
			p = NULL;
	}

	if (p)
		ret_pid = get_pid(task_pid(p));

	process_set_cleanup_do_each_process(processes);

	process_set_put(processes);
put_gscheduler:
	gscheduler_put(gscheduler);

out:
	return ret_pid;
}

/*
 * Give the load of a remote node with a fictive extra CPU-bound process
 *
 *  @author Innogrid HCC
 */
static int get_stable_remote_load(struct mosix_load_balancer *lb,
				  hcc_node_t node, unsigned long *load)
{
	unsigned long node_load;
	unsigned long single_process_load;
	int ret;

	ret = gscheduler_port_get_remote_value(&lb->ports[PORT_REMOTE_LOAD],
					      node,
					      &lb->tmp_load, 1,
					      NULL, 0);
	if (ret < 1)
		goto no_load;
	node_load = lb->tmp_load;
	ret = gscheduler_port_get_remote_value(
		&lb->ports[PORT_SINGLE_PROCESS_LOAD],
		node,
		&lb->tmp_load, 1,
		NULL, 0);
	if (ret < 1)
		goto no_load;
	single_process_load = lb->tmp_load;

	*load = node_load + single_process_load * lb->stab_factor / 100;
	return 0;

no_load:
	return -EAGAIN;
}

hcc_node_t __find_target_node(struct mosix_load_balancer *lb,
				    const hcc_nodemask_t *nodes,
				    unsigned long high_load)
{
	unsigned long lowest_remote_load, remote_load;
	hcc_node_t target_node = HCC_NODE_ID_NONE;
	hcc_node_t i;
	int ret;

	lowest_remote_load = high_load;

	__for_each_hcc_node_mask(i, nodes) {
		if (unlikely(i == hcc_node_id))
			continue;

		ret = get_stable_remote_load(lb, i, &remote_load);
		if (ret)
			continue;
		if (remote_load < lowest_remote_load) {
			lowest_remote_load = remote_load;
			target_node = i;
		}
	}

	return target_node;
}

/**
 * If some node have an estimated processor load lower than the local one,
 *  return the node having the lowest load;
 *  otherwise, return HCC_NODE_ID_NONE.
 */
hcc_node_t find_target_node(struct mosix_load_balancer *lb,
				  unsigned long current_load)
{
	struct gscheduler *s = gscheduler_policy_get_gscheduler(&lb->policy);
	hcc_nodemask_t nodes;
	hcc_node_t target_node = HCC_NODE_ID_NONE;

	if (s) {
		gscheduler_get_node_set(s, &nodes);
		target_node = __find_target_node(lb, &nodes, current_load);
		gscheduler_put(s);
	}

	return target_node;
}

static void balance(struct mosix_load_balancer *lb, unsigned long current_load)
{
	struct pid *target_pid;
	struct task_struct *target_task;
	hcc_node_t target_node;

	lb_lock(lb);

	/* First, try to find a task that could be migrated */
	target_pid = find_target_task(lb);
	if (!target_pid)
		goto out;

	/* Second, check whether migrating the task could improve balance */
	target_node = find_target_node(lb, current_load);
	if (target_node == HCC_NODE_ID_NONE)
		goto out_put_pid;

	/* Third, migrate the selected task to the selected node */
	rcu_read_lock();
	target_task = pid_task(target_pid, PIDTYPE_PID);
	if (target_task)
		__migrate_linux_threads(target_task, MIGR_LOCAL_PROCESS,
					target_node);
	rcu_read_unlock();

out_put_pid:
	put_pid(target_pid);

out:
	lb_unlock(lb);
}

/* Expell migratable tasks we manage */
static void __expell_all(struct mosix_load_balancer *lb,
			 const hcc_nodemask_t *nodes)
{
	struct gscheduler *gscheduler;
	struct process_set *processes;
	struct task_struct *t;
	hcc_node_t node;
	hcc_node_t fallback_node = __first_hcc_node(nodes);
	int err;

	gscheduler = gscheduler_policy_get_gscheduler(&lb->policy);
	if (!gscheduler)
		return;

	processes = gscheduler_get_process_set(gscheduler);
	if (!processes)
		goto put_gscheduler;

	lb_lock(lb);
	process_set_prepare_do_each_process(processes);

	process_set_do_each_process(t, processes) {
		if (!may_migrate(t)) {
			printk(KERN_WARNING "mosix_load_balancer:"
			       " task %d(%s) is not migratable!\n",
			       task_pid_knr(t), t->comm);
			continue;
		}

		node = __find_target_node(lb, nodes, ULONG_MAX);
		if (node == HCC_NODE_ID_NONE)
			node = fallback_node;

		err = __migrate_linux_threads(t, MIGR_LOCAL_PROCESS, node);
		if (err && err != -EALREADY)
			printk(KERN_WARNING "mosix_load_balancer:"
			       " task %d(%s) could not be migrated!\n",
			       task_pid_knr(t), t->comm);
	} process_set_while_each_process(t, processes);

	process_set_cleanup_do_each_process(processes);
	lb_unlock(lb);

	process_set_put(processes);
put_gscheduler:
	gscheduler_put(gscheduler);
}

static
void mosix_load_balancer_update_node_set(struct gscheduler_policy *policy,
					 const hcc_nodemask_t *new_set,
					 const hcc_nodemask_t *removed_set,
					 const hcc_nodemask_t *added_set)
{
	struct mosix_load_balancer *lb = to_mosix_load_balancer(policy);
	if (__hcc_node_isset(hcc_node_id, removed_set))
		__expell_all(lb, new_set);
}

/* gscheduler_policy_attributes */

static
ssize_t stab_factor_attr_show(struct gscheduler_policy *policy, char *page)
{
	struct mosix_load_balancer *lb = to_mosix_load_balancer(policy);
	return sprintf(page, "%d\n", lb->stab_factor);
}

static ssize_t stab_factor_attr_store(struct gscheduler_policy *policy,
				      const char *page, size_t count)
{
	struct mosix_load_balancer *lb = to_mosix_load_balancer(policy);
	char *pos;
	unsigned int tmp;

	tmp = simple_strtoul(page, &pos, 10);
	if (((*pos == '\n' && pos - page == count - 1)
	     || (*pos == '\0' && pos - page == count))
	    && pos != page) {
		lb_lock(lb);
		lb->stab_factor = tmp;
		lb_unlock(lb);
		return count;
	}
	return -EINVAL;
}

static struct gscheduler_policy_attribute stab_factor_attr = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "stab_factor",
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = stab_factor_attr_show,
	.store = stab_factor_attr_store,
};

static struct gscheduler_policy_attribute *mosix_load_balancer_attrs[] = {
	&stab_factor_attr,
	NULL
};

/* local_load_port */

DEFINE_GSCHEDULER_PORT_UPDATE_VALUE(local_load_port, port)
{
	struct mosix_load_balancer *lb;
	unsigned long new_load;
	int ret;

	lb = container_of(port, typeof(*lb), ports[PORT_LOCAL_LOAD]);
	ret = gscheduler_port_get_value(port, &new_load, 1, NULL, 0);
	if (ret < 1)
		return;

	balance(lb, new_load);
}

static BEGIN_GSCHEDULER_PORT_TYPE(local_load_port),
	.GSCHEDULER_PORT_UPDATE_VALUE(local_load_port),
	.GSCHEDULER_PORT_VALUE_TYPE(local_load_port, unsigned long),
END_GSCHEDULER_PORT_TYPE(local_load_port);

/* remote_load_port */

static BEGIN_GSCHEDULER_PORT_TYPE(remote_load_port),
	.GSCHEDULER_PORT_VALUE_TYPE(remote_load_port, unsigned long),
END_GSCHEDULER_PORT_TYPE(remote_load_port);

/* single_process_load_port */

static BEGIN_GSCHEDULER_PORT_TYPE(single_process_load_port),
	.GSCHEDULER_PORT_VALUE_TYPE(single_process_load_port, unsigned long),
END_GSCHEDULER_PORT_TYPE(single_process_load_port);

/* process_load_port */

static BEGIN_GSCHEDULER_PORT_TYPE(process_load_port),
	.GSCHEDULER_PORT_VALUE_TYPE(process_load_port, unsigned long),
	.GSCHEDULER_PORT_PARAM_TYPE(process_load_port, pid_t),
END_GSCHEDULER_PORT_TYPE(process_load_port);

/* gscheduler_policy_type*/

static struct gscheduler_policy *mosix_load_balancer_new(const char *name);
static void mosix_load_balancer_destroy(struct gscheduler_policy *policy);

static struct gscheduler_policy_operations mosix_load_balancer_ops = {
	.new = mosix_load_balancer_new,
	.destroy = mosix_load_balancer_destroy,
	.update_node_set = mosix_load_balancer_update_node_set,
};

static GSCHEDULER_POLICY_TYPE(mosix_load_balancer, "mosix_load_balancer",
			     &mosix_load_balancer_ops,
			     mosix_load_balancer_attrs);

static struct gscheduler_policy *mosix_load_balancer_new(const char *name)
{
	struct mosix_load_balancer *lb = kmalloc(sizeof(*lb), GFP_KERNEL);
	struct config_group *def_groups[PORT_MAX + 1];
	int i;
	int err;

	if (!lb)
		goto err_lb;

	lb->stab_factor = 130;

	err = gscheduler_port_init(&lb->ports[PORT_LOCAL_LOAD],
				  "local_load", &local_load_port_type, NULL,
				  NULL);
	if (err)
		goto err_local_load;
	err = gscheduler_port_init(&lb->ports[PORT_REMOTE_LOAD],
				  "remote_load", &remote_load_port_type, NULL,
				  NULL);
	if (err)
		goto err_remote_load;
	err = gscheduler_port_init(&lb->ports[PORT_SINGLE_PROCESS_LOAD] ,
				  "single_process_load",
				  &single_process_load_port_type,
				  NULL,
				  NULL);
	if (err)
		goto err_single_process_load;
	err = gscheduler_port_init(&lb->ports[PORT_PROCESS_LOAD],
				  "process_load",
				  &process_load_port_type,
				  NULL,
				  NULL);
	if (err)
		goto err_process_load;

	for (i = 0; i < PORT_MAX; i++)
		def_groups[i] = gscheduler_port_config_group(&lb->ports[i]);
	def_groups[PORT_MAX] = NULL;

	err = gscheduler_policy_init(&lb->policy, name, &mosix_load_balancer,
				    def_groups);
	if (err)
		goto err_policy;

	return &lb->policy;

err_policy:
	gscheduler_port_cleanup(&lb->ports[PORT_PROCESS_LOAD]);
err_process_load:
	gscheduler_port_cleanup(&lb->ports[PORT_SINGLE_PROCESS_LOAD]);
err_single_process_load:
	gscheduler_port_cleanup(&lb->ports[PORT_REMOTE_LOAD]);
err_remote_load:
	gscheduler_port_cleanup(&lb->ports[PORT_LOCAL_LOAD]);
err_local_load:
	kfree(lb);
err_lb:
	return NULL;
}

static void mosix_load_balancer_destroy(struct gscheduler_policy *policy)
{
	struct mosix_load_balancer *lb = to_mosix_load_balancer(policy);
	int i;

	gscheduler_policy_cleanup(policy);
	for (i = 0; i < PORT_MAX; i++)
		gscheduler_port_cleanup(&lb->ports[i]);
	kfree(lb);
}

/* module init/exit */

int mosix_load_balancer_init(void)
{
	int err;

	err = gscheduler_port_type_init(&local_load_port_type, NULL);
	if (err)
		goto err_local_load;
	err = gscheduler_port_type_init(&remote_load_port_type, NULL);
	if (err)
		goto err_remote_load;
	err = gscheduler_port_type_init(&single_process_load_port_type, NULL);
	if (err)
		goto err_single_process_load;
	err = gscheduler_port_type_init(&process_load_port_type, NULL);
	if (err)
		goto err_process_load;

	err = gscheduler_policy_type_register(&mosix_load_balancer);
	if (err)
		goto err_register;

out:
	return err;

err_register:

	gscheduler_port_type_cleanup(&process_load_port_type);
err_process_load:
	gscheduler_port_type_cleanup(&single_process_load_port_type);
err_single_process_load:
	gscheduler_port_type_cleanup(&remote_load_port_type);
err_remote_load:
	gscheduler_port_type_cleanup(&local_load_port_type);
err_local_load:
	goto out;
}

void mosix_load_balancer_exit(void)
{
	gscheduler_policy_type_unregister(&mosix_load_balancer);
	gscheduler_port_type_cleanup(&process_load_port_type);
	gscheduler_port_type_cleanup(&single_process_load_port_type);
	gscheduler_port_type_cleanup(&remote_load_port_type);
	gscheduler_port_type_cleanup(&local_load_port_type);
}

module_init(mosix_load_balancer_init);
module_exit(mosix_load_balancer_exit);
