/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#include <linux/kernel.h>
#include <linux/tipc.h>
#include <net/tipc.h>
#include <linux/workqueue.h>

#include <linux/socket.h>
#include <linux/net_namespace.h>

struct workqueue_struct *hcccom_wq;

int comlayer_init(void) {

    unsigned int i;
    struct net *net = NULL;
    struct task_struct *tmp;
    struct nsproxy *np;

    printk(KERN_INFO "HCC: comlayer_init");

    tmp = get_current();

//    task_lock(tmp);
    np = tmp->nsproxy;
    if (np) {
        net = get_net(np->net_ns);
    }
//    task_unlock(tmp);

    for_each_possible_cpu(i) {
        printk(KERN_INFO "HCC: %d", i);
    }

    hcccom_wq = create_workqueue("hcccom");

    lockdep_off();

    tipc_net_start(net, tipc_addr(1, 1, 2));

    lockdep_on();

    return 0;
}