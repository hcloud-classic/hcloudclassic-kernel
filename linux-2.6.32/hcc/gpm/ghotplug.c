/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <hcc/capabilities.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>
#include <hcc/pid.h>
#include <hcc/ghotplug.h>
#include <hcc/migration.h>

#include "gpm_internal.h"

static int gpm_add(struct ghotplug_context *ctx)
{
	return pidmap_map_add(ctx);
}

/* migrate all processes that we can migrate */
static int gpm_remove(const hcc_nodemask_t *vector)
{
	struct task_struct *tsk;
	hcc_node_t dest_node = hcc_node_id;

	printk("gpm_remove...\n");

	/* Here we assume that all nodes of the cluster are not removed */
	dest_node = hcc_node_next_online_in_ring(dest_node);
	BUG_ON(__hcc_node_isset(dest_node, vector));

	read_lock(&tasklist_lock);
	for_each_process(tsk) {
		if (!tsk->nsproxy->hcc_ns)
			continue;

		if (cap_raised(tsk->hcc_gcaps.effective, GCAP_CAN_MIGRATE)) {
			/* have to migrate this process */
			printk("try to migrate %d %s to %d\n",
			       task_pid_knr(tsk), tsk->comm, dest_node);

			__migrate_linux_threads(tsk, MIGR_LOCAL_PROCESS,
						dest_node);

			/*
			 * Here we assume that all nodes of the cluster are not
			 * removed.
			 */
			dest_node = hcc_node_next_online_in_ring(dest_node);
			BUG_ON(__hcc_node_isset(dest_node, vector));

			continue;
		}

		if (cap_raised(tsk->hcc_gcaps.effective, GCAP_USE_REMOTE_MEMORY)) {
			/* have to kill this process */
			printk("gpm_remove: have to kill %d (%s)\n",
			       task_pid_knr(tsk), tsk->comm);
			continue;
		}
	}
	read_unlock(&tasklist_lock);

	return 0;
}

static int gpm_notification(struct notifier_block *nb, ghotplug_event_t event,
			    void *data)
{
	struct ghotplug_context *ctx;
	struct ghotplug_node_set *node_set;
	int err;

	switch(event){
	case GHOTPLUG_NOTIFY_ADD:
		ctx = data;
		err = gpm_add(ctx);
		break;
	case GHOTPLUG_NOTIFY_REMOVE:
		node_set = data;
		err = gpm_remove(&node_set->v);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int gpm_ghotplug_init(void)
{
	register_ghotplug_notifier(gpm_notification, GHOTPLUG_PRIO_GPM);
	return 0;
}

void gpm_ghotplug_cleanup(void)
{
}
