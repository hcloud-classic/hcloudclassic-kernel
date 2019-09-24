//
// Created by root on 19. 9. 23.
//

#include <linux/module.h>
#include <linux/cluster_barrier.h>
#include <hcc/hccinit.h>

#ifdef CONFIG_HCCGRPC
#include <net/hccgrpc/rpc.h>
#endif

int init_hcc_communication_system(void){

    printk(KERN_INFO "HCC: init_hcc_communication_system");

#ifdef CONFIG_HCCGRPC
    if (init_rpc())
        goto err_rpc;
#endif

    return 0;

#ifdef CONFIG_HCCGRPC
err_rpc:
#endif
    return -1;
}

#ifdef CONFIG_HCC
int init_hcc_components(void){

    printk(KERN_INFO "HCC: init_hcc_components");

    return 0;
}
#endif

void __init hcc_init(void){

    printk(KERN_INFO "HCC: hcc_init");

    if(init_hcc_communication_system())
        return;

    init_cluster_barrier();

#ifdef CONFIG_HCC
    if (init_hcc_components())
        return;
#endif

}
