/*
 *  Copyright (C) 2019 Innogrid
 */

/* writen by cgs 2019 */

#include <linux/kernel.h>
#include <net/hccgrpc/rpc.h>
#include <net/hccgrpc/rpcid.h>

int say_hello(struct rpc_desc *desc, void *_msg, size_t size)
{
    printk(KERN_INFO "HCC: hello");
    return 0;
}

void proc_task_start(void)
{
    printk(KERN_INFO "HCC: proc_task_start");

    rpc_register_int(PROC_HELLO, say_hello, 0);
}