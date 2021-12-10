#ifndef _LINUX_PID_NS_H
#define _LINUX_PID_NS_H

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/threads.h>
#include <linux/nsproxy.h>
#include <linux/kref.h>

struct pidmap {
       atomic_t nr_free;
       void *page;
};

#define PIDMAP_ENTRIES         ((PID_MAX_LIMIT + 8*PAGE_SIZE - 1)/PAGE_SIZE/8)

struct bsd_acct_struct;

struct pid_namespace {
	struct kref kref;
	struct pidmap pidmap[PIDMAP_ENTRIES];
	int last_pid;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
#ifdef CONFIG_PROC_FS
	struct vfsmount *proc_mnt;
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT
	struct bsd_acct_struct *bacct;
#endif
#ifdef CONFIG_HCC_PROC
	struct pid_namespace *hcc_ns_root;
	unsigned global:1;
#endif
#ifndef __GENKSYMS__
	gid_t pid_gid;
	int hide_pid;
	unsigned int nr_hashed;
	struct work_struct proc_work;
	int reboot;	/* group exit code if this pidns was rebooted */
	unsigned int proc_inum;
#endif
};

extern struct pid_namespace init_pid_ns;

#define PIDNS_HASH_ADDING (1U << 31)

#ifdef CONFIG_PID_NS
static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	if (ns != &init_pid_ns)
		kref_get(&ns->kref);
	return ns;
}

extern struct pid_namespace *copy_pid_ns(unsigned long flags, struct pid_namespace *ns);
extern void free_pid_ns(struct kref *kref);
extern void zap_pid_ns_processes(struct pid_namespace *pid_ns);
extern int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd);

static inline void put_pid_ns(struct pid_namespace *ns)
{
	if (ns != &init_pid_ns)
		kref_put(&ns->kref, free_pid_ns);
}

#ifdef CONFIG_HCC_PROC
static inline bool is_hcc_pid_ns_root(struct pid_namespace *ns)
{
	return ns == ns->hcc_ns_root;
}

struct pid_namespace *find_get_hcc_pid_ns(void);
#endif

#ifdef CONFIG_HCC_GPM
struct pid_namespace *create_pid_namespace(struct pid_namespace *parent_pid_ns);
#endif

#else /* !CONFIG_PID_NS */
#include <linux/err.h>

static inline struct pid_namespace *get_pid_ns(struct pid_namespace *ns)
{
	return ns;
}

static inline struct pid_namespace *
copy_pid_ns(unsigned long flags, struct pid_namespace *ns)
{
	if (flags & CLONE_NEWPID)
		ns = ERR_PTR(-EINVAL);
	return ns;
}

static inline void put_pid_ns(struct pid_namespace *ns)
{
}

static inline void zap_pid_ns_processes(struct pid_namespace *ns)
{
	BUG();
}

#ifdef CONFIG_HCC_PROC
static inline bool is_hcc_pid_ns_root(struct pid_namespace *ns)
{
	return true;
}

static inline struct pid_namespace *find_get_hcc_pid_ns(void)
{
	return &init_pid_ns;
}
#endif

static inline int reboot_pid_ns(struct pid_namespace *pid_ns, int cmd)
{
	return 0;
}
#endif /* CONFIG_PID_NS */

extern struct pid_namespace *task_active_pid_ns(struct task_struct *tsk);
void pidhash_init(void);
void pidmap_init(void);

#endif /* _LINUX_PID_NS_H */
