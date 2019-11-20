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

/* Hcc Cluster Node id */
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

//static char *read_from_file(char *_filename, int size)
//{
//    int error;
//    struct file *f;
//    char *b, *filename;
//
//    b = kmalloc(size, GFP_ATOMIC);
//    BUG_ON(b==NULL);
//
//    filename = getname(_filename);
//    if (!IS_ERR(filename)) {
//        f = filp_open(filename, O_RDONLY, 0);
//        if (IS_ERR(f)) {
//            printk("error: %ld\n", PTR_ERR(f));
//            goto err_file;
//        }
//
//        error = kernel_read(f, 0, b, size);
//        //printk("read %d bytes\n", error);
//
//        b[error] = 0;
//        //printk(">>>%s<<<\n", b);
//
//        if (f->f_op && f->f_op->flush) {
//            error = f->f_op->flush(f, NULL);
//            if (error)
//                printk("init_ids: Error while closing file %d\n", error);
//        }
//    }
//    return b;
//
//    err_file:
//    kfree(b);
//    return NULL;
//}

//static void __init init_ids(void)
//{
//    char *hostname, *hcc_nodes;
//
//    if (!ISSET_HCC_INIT_FLAGS(HCC_INITFLAGS_NODEID) || !ISSET_HCC_INIT_FLAGS(HCC_INITFLAGS_SESSIONID)) {}
//    hostname = read_from_file("/etc/hostname", 256);
//
//    printk(KERN_INFO "HCC: init_ids %s", hostname);
//
//    return;
//}

void __init hcc_init(void) {

    struct rpc_desc *desc;
    int id = 1;

    printk(KERN_INFO "HCC: hcc_init");

    hcc_wq = create_workqueue("hcc");
    hcc_nb_wq = create_workqueue("hccNB");
    BUG_ON(hcc_wq == NULL);
    BUG_ON(hcc_nb_wq == NULL);

    if(init_hcc_communication_system())
        return;

    init_cluster_barrier();

#ifdef CONFIG_HCC
    if (init_hcc_components())
        return;

    desc = rpc_begin(PROC_HELLO, HCC_NODE_ID);

    rpc_pack_type (desc, id);
//	rpc_pack(desc, 0, nodes, sizeof(hccmask_t));

    rpc_end(desc, 0);

#endif

}
