//
// Created by root on 19. 9. 24.
//

#include <linux/module.h>
#include <linux/cluster_barrier.h>

void init_cluster_barrier(void){

    printk(KERN_INFO "HCC: init_cluster_barrier");
}