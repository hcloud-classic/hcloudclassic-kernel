/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#include <linux/timer.h>
#include <linux/workqueue.h>
#include <hcc/hccnodemask.h>
#include <hcc/hccinit.h>

#include <hcc/workqueue.h>
#include <net/hccgrpc/rpcid.h>
#include <net/hccgrpc/rpc.h>
#include <hcc/sys/types.h>

#include "rpc_internal.h"

int rpc_monitor_init(void){
    rpc_register_void(RPC_PINGPONG,
                      rpc_pingpong_handler, 0);

    return 0;
}

void rpc_monitor_cleanup(void){
}