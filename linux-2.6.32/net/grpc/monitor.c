/**
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 *
 */

#include <linux/timer.h>
#include <linux/workqueue.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>

#include <hcc/workqueue.h>
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>

#include "grpc_internal.h"

static struct timer_list grpc_timer;
struct work_struct grpc_work;
struct grpc_service pingpong_service;

static void grpc_pingpong_handler (struct grpc_desc *grpc_desc,
				  void *data,
				  size_t size){
	unsigned long l = *(unsigned long*)data;

	l++;
	
	grpc_pack(grpc_desc, 0, &l, sizeof(l));
};

static void grpc_worker(struct work_struct *data)
{
	static unsigned long l = 0;
	hcc_nodemask_t n;
	int r;

	r = 0;
	l++;
	
	hcc_nodes_clear(n);
	hcc_node_set(0, n);

	r = grpc_async(GRPC_PINGPONG, 0, &l, sizeof(l));
	if(r<0)
		return;
	
}

static void grpc_timer_cb(unsigned long _arg)
{
	return;
	queue_work(hcc_wq, &grpc_work);
	mod_timer(&grpc_timer, jiffies + 2*HZ);
}

int grpc_monitor_init(void){
	grpc_register_void(GRPC_PINGPONG,
			  grpc_pingpong_handler, 0);
	
	init_timer(&grpc_timer);
	grpc_timer.function = grpc_timer_cb;
	grpc_timer.data = 0;
	if(hcc_node_id != 0)
		mod_timer(&grpc_timer, jiffies + 10*HZ);
	INIT_WORK(&grpc_work, grpc_worker);

	return 0;
}

void grpc_monitor_cleanup(void){
}
