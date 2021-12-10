/** Initialization of procfs stuffs for ProcFS module.
 *  @file procfs.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include "proc.h"
#ifdef CONFIG_HCC_PROC
#include "proc_pid.h"
#endif
#include "static_node_info_linker.h"
#include "static_cpu_info_linker.h"
#include <hcc/dynamic_node_info_linker.h>
#include "dynamic_cpu_info_linker.h"

int procfs_ghotplug_init(void);
void procfs_ghotplug_cleanup(void);

int init_procfs(void)
{
	static_node_info_init();
	static_cpu_info_init();
	dynamic_node_info_init();
	dynamic_cpu_info_init();

#ifdef CONFIG_HCC_PROC
	proc_pid_init();
#endif

	hcc_procfs_init();

	procfs_ghotplug_init();

	return 0;
}

void cleanup_procfs(void)
{
	procfs_ghotplug_cleanup();
	hcc_procfs_finalize();

#ifdef CONFIG_HCC_PROC
	proc_pid_finalize();
#endif
}
