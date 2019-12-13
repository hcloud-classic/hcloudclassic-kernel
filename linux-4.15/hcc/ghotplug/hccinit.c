/*
 *  Copyright (C) 2019 Innogrid
 */

/* writen by cgs 2019 */

#include <linux/kernel.h>
#include <linux/cluster_barrier.h>
#include <hcc/hccinit.h>

#include <linux/workqueue.h>

#ifdef CONFIG_HCCGRPC
#include <net/hccgrpc/rpc.h>
#include <net/hccgrpc/rpcid.h>
#endif

#ifdef CONFIG_HCCGPROC
#include <hcc/gproc.h>
#endif

#ifdef CONFIG_HCCGPROC
#include <hcc/gproc.h>
#endif

/* HCC Cluster Node id */
hcc_node_t hcc_node_id = -1;
EXPORT_SYMBOL(hcc_node_id);

struct workqueue_struct *hcc_wq;
struct workqueue_struct *hcc_nb_wq;

int init_hcc_communication_system(void){

    printk(KERN_INFO "HCC: init_hcc_communication_system");

#ifdef CONFIG_HCCGRPC
    if (init_rpc())
        goto err_rpc;
#endif

    return 0;

#ifdef CONFIG_HCCGRPC
    err_rpc:
    return -1;
#endif
}

#ifdef CONFIG_HCC
int init_hcc_components(void){

    printk(KERN_INFO "HCC: init_hcc_components");
    init_proc();

    return 0;
}
#endif

void __init hcc_init(void){

    struct rpc_desc *desc;
    int id = 1;

    printk(KERN_INFO "HCC: hcc_init");

    hcc_wq = create_workqueue("hcc");
    hcc_nb_wq = create_workqueue("hccNB");
    BUG_ON(hcc_wq == NULL);
    BUG_ON(hcc_nb_wq == NULL);

    if (init_hcc_communication_system())
        return;

    init_cluster_barrier();

#ifdef CONFIG_HCC
    if (init_hcc_components())
        return;

    desc = rpc_begin(PROC_HELLO, HCC_NODE_ID);
    rpc_pack_type (desc, id);
    rpc_end(desc, 0);
#endif

}
