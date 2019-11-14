/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by ish 2019 */

#include <linux/kernel.h>
#include <hcc/hccinit.h>
#include "gproc_internal.h"

int init_proc(void) {

    printk(KERN_INFO "HCC: init_gproc");
    proc_task_start();

    return 0;
}

void cleanup_proc(void){

}