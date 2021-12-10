/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/notifier.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>

#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include <hcc/ghotplug.h>

#include "proc.h"

struct notifier_block;

inline
void procfs_add(hcc_nodemask_t * v){
	hcc_node_t i;

	__for_each_hcc_node_mask(i, v){
		create_proc_node_info(i);
	};

};

inline
void procfs_remove(hcc_nodemask_t * v){
	hcc_node_t i;

	__for_each_hcc_node_mask(i, v){
		remove_proc_node_info(i);
	};

};


/**
 *
 * Notifier related part
 *
 */

static int procfs_notification(struct notifier_block *nb, ghotplug_event_t event,
			    void *data){
	struct ghotplug_context *ctx;
	struct ghotplug_node_set *node_set;

	switch(event){
	case GHOTPLUG_NOTIFY_ADD:
		ctx = data;
		procfs_add(&ctx->node_set.v);
		break;

	case GHOTPLUG_NOTIFY_REMOVE_ADVERT:
		node_set = data;
		procfs_remove(&node_set->v);
		break;
	default:
		break;
	}

	return NOTIFY_OK;
};

int procfs_ghotplug_init(void){
	register_ghotplug_notifier(procfs_notification, GHOTPLUG_PRIO_MEMBERSHIP_ONLINE);
	return 0;
};

void procfs_ghotplug_cleanup(void){
};
