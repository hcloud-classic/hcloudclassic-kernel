/*
 *  hcc/proc/proc.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/kernel.h>

#include "proc_internal.h"

/** Initial function of the module
 *  @author Innogrid HCC
 */
int init_proc(void)
{
	printk("Proc initialisation: start\n");

	proc_task_start();
	proc_hcc_exit_start();

	proc_remote_syscalls_start();
	register_remote_syscalls_hooks();

	printk("Proc initialisation: done\n");

	return 0;
}

void cleanup_proc(void)
{
}
