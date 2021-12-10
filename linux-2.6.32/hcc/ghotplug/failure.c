/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#define MODULE_NAME "Hotplug"

#include <linux/reboot.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/irqflags.h>
#include <hcc/ghotplug.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <asm/uaccess.h>

#include <hcc/hcc_services.h>
#include <hcc/hcc_syscalls.h>
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>

#include "ghotplug_internal.h"

hcc_nodemask_t failure_vector;
struct work_struct fail_work;
struct work_struct recovery_work;
struct notifier_block *ghotplug_failure_notifier_list;

static void recovery_worker(struct work_struct *data)
{
	hcc_node_t i;

	for_each_hcc_node_mask(i, failure_vector){
		clear_hcc_node_online(i);
		printk("FAILURE OF %d DECIDED\n", i);
		printk("should ignore messages from this node\n");
	}

	//knetdev_failure(&failure_vector);
	//comm_failure(&failure_vector);

#ifdef CONFIG_HCC_GDM
	//gdm_failure(&failure_vector);
#endif
}

void hcc_failure(hcc_nodemask_t * vector)
{

	if(__hcc_nodes_equal(&failure_vector, vector))
		return;
	
	__hcc_nodes_copy(&failure_vector, vector);

	queue_work(hcc_ha_wq, &recovery_work);
}

static void handle_node_fail(struct grpc_desc *desc, void *data, size_t size)
{
	emergency_sync();
	emergency_remount();

	machine_restart(NULL);

	// should never be reached
	BUG();

}

static int nodes_fail(void __user *arg)
{
	struct __ghotplug_node_set __node_set;
	struct ghotplug_node_set node_set;
	int unused;
	int err;
	
	if (copy_from_user(&node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;

	err = hcc_nodemask_copy_from_user(&node_set.v, &__node_set.v);
	if (err)
		return err;
	
	grpc_async_m(NODE_FAIL, &node_set.v,
		    &unused, sizeof(unused));
	
	return 0;
}

int ghotplug_failure_init(void)
{
	INIT_WORK(&recovery_work, recovery_worker);

	grpc_register_void(NODE_FAIL, handle_node_fail, 0);
	
	register_proc_service(HCC_SYS_GHOTPLUG_FAIL, nodes_fail);

	return 0;
}

void ghotplug_failure_cleanup(void)
{
}
