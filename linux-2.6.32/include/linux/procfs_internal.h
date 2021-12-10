#ifndef __PROCFS_INTERNAL_H__
#define __PROCFS_INTERNAL_H__

/* All definitions below are moved from fs/proc/internal.h */
#ifdef CONFIG_HCC_PROCFS

struct vmalloc_info {
	unsigned long	used;
	unsigned long	largest_chunk;
};

#ifdef CONFIG_MMU
#define VMALLOC_TOTAL (VMALLOC_END - VMALLOC_START)
extern void get_vmalloc_info(struct vmalloc_info *vmi);
#else

#define VMALLOC_TOTAL 0UL
#define get_vmalloc_info(vmi)			\
do {						\
	(vmi)->used = 0;			\
	(vmi)->largest_chunk = 0;		\
} while(0)
#endif

struct seq_file;
int meminfo_proc_show(struct seq_file *m, void *v);
int show_stat(struct seq_file *p, void *v);
int loadavg_proc_show(struct seq_file *m, void *v);
int uptime_proc_show(struct seq_file *m, void *v);

#ifdef CONFIG_HCC_PROC
/* From fs/proc/base.c */
struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};

extern const struct inode_operations proc_def_inode_operations;

int proc_setattr(struct dentry *dentry, struct iattr *attr);
int proc_pid_fill_cache(struct file *filp, void *dirent, filldir_t filldir,
			struct tgid_iter iter);
int do_proc_readlink(struct path *path, char __user *buffer, int buflen);

int proc_pid_cmdline(struct task_struct *task, char * buffer);
int proc_pid_auxv(struct task_struct *task, char *buffer);
int proc_pid_limits(struct task_struct *task, char *buffer);
int proc_pid_syscall(struct task_struct *task, char *buffer);
int proc_pid_wchan(struct task_struct *task, char *buffer);
int proc_pid_schedstat(struct task_struct *task, char *buffer);
int proc_oom_score(struct task_struct *task, char *buffer);

int proc_pid_personality(struct seq_file *m, struct pid_namespace *ns,
			 struct pid *pid, struct task_struct *task);
int proc_pid_stack(struct seq_file *m, struct pid_namespace *ns,
		   struct pid *pid, struct task_struct *task);
int proc_tgid_io_accounting(struct task_struct *task, char *buffer);

/* From fs/proc/internal.h */
extern int proc_tgid_stat(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *task);
extern int proc_pid_status(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *task);
extern int proc_pid_statm(struct seq_file *m, struct pid_namespace *ns,
				struct pid *pid, struct task_struct *task);

#ifdef CONFIG_HCC_GPM
int gpm_type_show(struct task_struct *task, char *buffer);
int gpm_source_show(struct task_struct *task, char *buffer);
int gpm_target_show(struct task_struct *task, char *buffer);
#endif

extern struct dentry *hcc_proc_pid_lookup(struct inode *dir,
					  struct dentry *dentry, pid_t pid);
extern int hcc_proc_pid_readdir(struct file *filp,
				void *dirent, filldir_t filldir,
				loff_t offset);
#endif /* CONFIG_HCC_PROC */

#endif /* CONFIG_HCC_PROCFS */

#endif /* __PROCFS_INTERNAL_H__ */
