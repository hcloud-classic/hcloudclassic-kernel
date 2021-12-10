/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#define MODULE_NAME "Hotplug"

#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/reboot.h>
#include <linux/workqueue.h>
#include <linux/device.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>
#include <hcc/hashtable.h>
#include <hcc/ghotplug.h>
#include <hcc/hcc_flags.h>
#include <asm/uaccess.h>
#include <asm/ioctl.h>

#include <tools/workqueue.h>
#include <tools/hcc_syscalls.h>
#include <tools/hcc_services.h>
#include <grpc/grpc.h>

#include "ghotplug_internal.h"

inline
void do_local_node_remove(struct ghotplug_node_set *node_set)
{
	hcc_node_t node;

	SET_HCC_NODE_FLAGS(HCC_FLAGS_STOPPING);
	printk("do_local_node_remove\n");

	printk("...notify local\n");
	ghotplug_remove_notify(node_set, GHOTPLUG_NOTIFY_REMOVE_LOCAL);
	printk("...notify_distant\n");
	ghotplug_remove_notify(node_set, GHOTPLUG_NOTIFY_REMOVE_DISTANT);

	printk("...confirm\n");
	grpc_sync_m(NODE_REMOVE_CONFIRM, &hcc_node_online_map, node_set, sizeof(*node_set));

	CLEAR_HCC_NODE_FLAGS(HCC_FLAGS_RUNNING);

	for_each_online_hcc_node(node)
		if(node != hcc_node_id)
			clear_hcc_node_online(node);

	hooks_stop();
	SET_HCC_NODE_FLAGS(HCC_FLAGS_STOPPED);

#if 0
	printk("...sleep\n");
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(10*HZ);

	printk("...try to reboot\n");
	queue_work(hcc_nb_wq, &fail_work);
#endif
}

inline
void do_other_node_remove(struct ghotplug_node_set *node_set)
{
	printk("do_other_node_remove\n");
	ghotplug_remove_notify(node_set, GHOTPLUG_NOTIFY_REMOVE_ADVERT);
	grpc_async_m(NODE_REMOVE_ACK, &node_set->v, NULL, 0);				
}

static void handle_node_remove(struct grpc_desc *desc, void *data, size_t size)
{
	struct ghotplug_node_set *node_set;

	printk("handle_node_remove\n");
	node_set = data;

	if(!hcc_node_isset(hcc_node_id, node_set->v)){
		do_other_node_remove(node_set);
		return;
	}

	do_local_node_remove(node_set);
}

/* we receive the ack from cluster about our remove operation */
static void handle_node_remove_ack(struct grpc_desc *desc, void *data, size_t size)
{
	printk("Need to take care that node %d ack the remove (if needed)\n", desc->client);
}

/* cluster receive the confirmation about the remove operation */
static int handle_node_remove_confirm(struct grpc_desc *desc, void *data, size_t size)
{
	if(desc->client==hcc_node_id)
		return 0;
	
	ghotplug_remove_notify((void*)&desc->client, GHOTPLUG_NOTIFY_REMOVE_ACK);
	printk("HCC: node %d removed\n", desc->client);
	return 0;
}

inline void __fwd_remove_cb(struct ghotplug_node_set *node_set)
{
	printk("__fwd_remove_cb: begin (%d / %d)\n", node_set->subclusterid, hcc_subsession_id);
	if (node_set->subclusterid == hcc_subsession_id) {

		grpc_async_m(NODE_REMOVE, &hcc_node_online_map, node_set, sizeof(*node_set));
		
	} else {
		hcc_node_t node;

		printk("__fwd_remove_cb: m1\n");
		node = 0;
		while ((universe[node].subid != node_set->subclusterid)
		       && (node < HCC_MAX_NODES))
			node++;
		printk("__fwd_remove_cb: m2 (%d/%d)\n", node, HCC_MAX_NODES);

		if (node == HCC_MAX_NODES) {
			BUG();
			printk
			    ("WARNING: here we have no idea... may be the next one will be more luky!\n");
			node = hcc_node_id + 1;
		}

		printk("send a NODE_FWD_REMOVE to %d\n", node);
		grpc_async(NODE_FWD_REMOVE, node, node_set, sizeof(*node_set));
	}
}

static void handle_node_fwd_remove(struct grpc_desc *desc, void *data, size_t size)
{
	__fwd_remove_cb(data);
}

static int nodes_remove(void __user *arg)
{
	struct __ghotplug_node_set __node_set;
	struct ghotplug_node_set node_set;
	int err;

	if (copy_from_user(&__node_set, arg, sizeof(struct __ghotplug_node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;
	err = hcc_nodemask_copy_from_user(&node_set.v, &__node_set.v);
	if (err)
		return err;

	if (!hcc_nodes_subset(node_set.v, hcc_node_present_map))
		return -ENONET;

	if (!hcc_nodes_subset(node_set.v, hcc_node_online_map))
		return -EPERM;

	/* TODO: Really required? */
	if (hcc_node_isset(hcc_node_id, node_set.v))
		return -EPERM;

	__fwd_remove_cb(&node_set);
	return 0;
}

static void handle_node_poweroff(struct grpc_desc *desc)
{
	emergency_sync();
	emergency_remount();

	kernel_shutdown_prepare(SYSTEM_POWER_OFF);
	if (pm_power_off_prepare)
		pm_power_off_prepare();
	sysdev_shutdown();

	printk(KERN_EMERG "Powering off the node...\n");
	machine_power_off();

	// should never be reached
	BUG();

}

static int nodes_poweroff(void __user *arg)
{
	struct __ghotplug_node_set __node_set;
	struct ghotplug_node_set node_set;
	int unused;
	int err;
	
	if (copy_from_user(&__node_set, arg, sizeof(__node_set)))
		return -EFAULT;

	node_set.subclusterid = __node_set.subclusterid;

	err = hcc_nodemask_copy_from_user(&node_set.v, &__node_set.v);
	if (err)
		return err;

	grpc_async_m(NODE_POWEROFF, &node_set.v,
		    &unused, sizeof(unused));
	
	return 0;
}


int ghotplug_remove_init(void)
{
	grpc_register(NODE_POWEROFF, handle_node_poweroff, 0);
	grpc_register_void(NODE_REMOVE, handle_node_remove, 0);
	grpc_register_void(NODE_REMOVE_ACK, handle_node_remove_ack, 0);
	grpc_register_void(NODE_FWD_REMOVE, handle_node_fwd_remove, 0);
	grpc_register_int(NODE_REMOVE_CONFIRM, handle_node_remove_confirm, 0);
	
	register_proc_service(HCC_SYS_GHOTPLUG_REMOVE, nodes_remove);
	register_proc_service(HCC_SYS_GHOTPLUG_POWEROFF, nodes_poweroff);

	return 0;
}

void ghotplug_remove_cleanup(void)
{
}
