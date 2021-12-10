/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/notifier.h>
#include <linux/kernel.h>
#include <hcc/hcc_nodemask.h>
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include <hcc/ghotplug.h>

#include "grpc_internal.h"

static void grpc_remove(hcc_nodemask_t * vector)
{
	printk("Have to send all the tx_queue before stopping the node\n");
};


/**
 *
 * Notifier related part
 *
 */

#ifdef CONFIG_HCC
static int grpc_notification(struct notifier_block *nb, ghotplug_event_t event,
			    void *data){
	struct ghotplug_node_set *node_set = data;
	
	switch(event){
	case GHOTPLUG_NOTIFY_REMOVE:
		grpc_remove(&node_set->v);
		break;
	default:
		break;
	}
	
	return NOTIFY_OK;
};
#endif

int grpc_ghotplug_init(void){
#ifdef CONFIG_HCC
	register_ghotplug_notifier(grpc_notification, GHOTPLUG_PRIO_GRPC);
#endif
	return 0;
};

void grpc_ghotplug_cleanup(void){
};
