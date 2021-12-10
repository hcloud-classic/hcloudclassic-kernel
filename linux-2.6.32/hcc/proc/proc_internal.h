#ifndef __PROC_INTERNAL_H__
#define __PROC_INTERNAL_H__

#ifdef CONFIG_HCC_PROC

void proc_task_start(void);
void proc_task_exit(void);

void proc_hcc_exit_start(void);
void proc_hcc_exit_exit(void);

void proc_remote_syscalls_start(void);
void register_remote_syscalls_hooks(void);

#endif /* CONFIG_HCC_PROC */

#endif /* __PROC_INTERNAL_H__ */
