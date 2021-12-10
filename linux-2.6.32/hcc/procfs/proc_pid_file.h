/**  /proc/<pid>/<file> information management.
 *  @file proc_pid_file.h
 *
 *  @author Innogrid HCC
 */

#ifndef __PROC_PID_FILE_H__
#define __PROC_PID_FILE_H__

#include <linux/fs.h>

struct proc_distant_pid_info;

/* REG() entries */
extern const struct file_operations hcc_proc_pid_environ_operations;

/* INF() entries */
extern const struct file_operations hcc_proc_info_file_operations;
int hcc_proc_pid_cmdline(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_pid_auxv(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_pid_limits(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_pid_syscall(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_pid_wchan(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_pid_schedstat(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_pid_oom_score(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_tgid_io_accounting(struct proc_distant_pid_info *task,
				char *buffer);
#ifdef CONFIG_HCC_GPM
int hcc_proc_gpm_type_show(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_gpm_source_show(struct proc_distant_pid_info *task, char *buffer);
int hcc_proc_gpm_target_show(struct proc_distant_pid_info *task, char *buffer);
#endif

/* ONE() entries */
extern const struct file_operations hcc_proc_single_file_operations;
int hcc_proc_pid_status(struct file *file, struct proc_distant_pid_info *task,
			char *buffer, size_t count);
int hcc_proc_pid_personality(struct file *file,
			     struct proc_distant_pid_info *task,
			     char *buffer, size_t count);
int hcc_proc_tgid_stat(struct file *file, struct proc_distant_pid_info *task,
		       char *buffer, size_t count);
int hcc_proc_pid_statm(struct file *file, struct proc_distant_pid_info *task,
		       char *buffer, size_t count);
int hcc_proc_pid_stack(struct file *file, struct proc_distant_pid_info *task,
		       char *buffer, size_t count);

void proc_pid_file_init(void);
void proc_pid_file_finalize(void);

#endif /* __PROC_PID_FILE_H__ */
