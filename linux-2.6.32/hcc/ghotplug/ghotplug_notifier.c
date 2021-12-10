/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/slab.h>

#include <hcc/ghotplug.h>
#include <hcc/hcc_nodemask.h>

static RAW_NOTIFIER_HEAD(ghotplug_chain_add);
static RAW_NOTIFIER_HEAD(ghotplug_chain_remove);

static DEFINE_MUTEX(ghotplug_mutex);

int register_ghotplug_notifier(int (*notifier_call)(struct notifier_block *, ghotplug_event_t, void *),
			      int priority)
{
	int err;
	struct notifier_block *nb;

	/* Insert into the addition chain */
	nb = kmalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;
	nb->notifier_call = (int (*)(struct notifier_block *, unsigned long, void *))(notifier_call);
	nb->priority = priority;

	mutex_lock(&ghotplug_mutex);
	err = raw_notifier_chain_register(&ghotplug_chain_add, nb);
	mutex_unlock(&ghotplug_mutex);

	if (err)
		return err;
	
	/* Insert into the removal chain */
	nb = kmalloc(sizeof(*nb), GFP_KERNEL);
	if (!nb)
		return -ENOMEM;
	nb->notifier_call =  (int (*)(struct notifier_block *, unsigned long, void *))(notifier_call);
	nb->priority = GHOTPLUG_PRIO_MAX-priority;
	
	mutex_lock(&ghotplug_mutex);
	err = raw_notifier_chain_register(&ghotplug_chain_remove, nb);
	mutex_unlock(&ghotplug_mutex);

	return err;
}

int ghotplug_add_notify(struct ghotplug_context *ctx, ghotplug_event_t event)
{
	return raw_notifier_call_chain(&ghotplug_chain_add, event, ctx);
}

int ghotplug_remove_notify(struct ghotplug_node_set *nodes_set,
			  ghotplug_event_t event)
{
	return raw_notifier_call_chain(&ghotplug_chain_remove, event,
				       nodes_set);
}

int ghotplug_failure_notify(struct ghotplug_node_set *nodes_set,
			   ghotplug_event_t event)
{
	return 0;
}
