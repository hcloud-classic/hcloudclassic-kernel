/*
 *  hcc/gpm/gpm.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/hcc_hashtable.h>
#include <hcc/ghost.h>
#include <hcc/ghotplug.h>
#include <hcc/hcc_syms.h>
#include <hcc/debug.h>
#include "gpm_internal.h"

struct task_struct *baby_sitter;

static void init_baby_sitter(void)
{
	baby_sitter = alloc_task_struct();
	if (!baby_sitter)
		OOM;

	memset(baby_sitter, 0, sizeof(*baby_sitter));
	baby_sitter->pid = -1;
	baby_sitter->tgid = baby_sitter->pid;
	baby_sitter->state = TASK_UNINTERRUPTIBLE;
	INIT_LIST_HEAD(&baby_sitter->children);
	baby_sitter->real_parent = baby_sitter;
	baby_sitter->parent = baby_sitter;
	strncpy(baby_sitter->comm, "baby sitter", 15);
}

/* HCCsyms to register for restart_blocks in ghost processes */
extern int compat_hcc_syms_register(void);
extern int hrtimer_hcc_syms_register(void);
extern int posix_cpu_timers_hcc_syms_register(void);
extern int select_hcc_syms_register(void);
extern int futex_hcc_syms_register(void);
extern int compat_hcc_syms_unregister(void);
extern int hrtimer_hcc_syms_unregister(void);
extern int posix_cpu_timers_hcc_syms_unregister(void);
extern int select_hcc_syms_unregister(void);
extern int futex_hcc_syms_unregister(void);

static int restart_block_hcc_syms_register(void)
{
	int retval;

	retval = hcc_syms_register(HCC_SYMS_DO_NO_RESTART_SYSCALL,
			do_no_restart_syscall);
#ifdef CONFIG_COMPAT
	if (!retval)
		retval = compat_hcc_syms_register();
#endif
	if (!retval)
		retval = hrtimer_hcc_syms_register();
	if (!retval)
		retval = posix_cpu_timers_hcc_syms_register();
	if (!retval)
		retval = select_hcc_syms_register();
	if (!retval)
		retval = futex_hcc_syms_register();

	return retval;
}

static int restart_block_hcc_syms_unregister(void)
{
	int retval;

	retval = hcc_syms_unregister(HCC_SYMS_DO_NO_RESTART_SYSCALL);
#ifdef CONFIG_COMPAT
	if (!retval)
		retval = compat_hcc_syms_unregister();
#endif
	if (!retval)
		retval = hrtimer_hcc_syms_unregister();
	if (!retval)
		retval = posix_cpu_timers_hcc_syms_unregister();
	if (!retval)
		retval = select_hcc_syms_unregister();
	if (!retval)
		retval = futex_hcc_syms_unregister();

	return retval;
}

int init_gpm(void)
{
	printk("GPM initialisation: start\n");

	restart_block_hcc_syms_register();

	init_baby_sitter();

	gpm_signal_start();
	gpm_sighand_start();
	gpm_children_start();

	gpm_pidmap_start();
	gpm_pid_start();

	gpm_remote_clone_start();
	register_remote_clone_hooks();

	gpm_migration_start();

	register_checkpoint_hooks();

	gpm_procfs_start();

	application_cr_server_init();

	gpm_ghotplug_init();

	printk("GPM initialisation: done\n");
	return 0;
}

void cleanup_gpm(void)
{
	gpm_ghotplug_cleanup();
	application_cr_server_finalize();
	gpm_procfs_exit();
	gpm_migration_exit();
	gpm_remote_clone_exit();
	gpm_pid_exit();
	gpm_pidmap_exit();
	gpm_children_exit();
	gpm_sighand_exit();
	gpm_signal_exit();
	restart_block_hcc_syms_unregister();
}
