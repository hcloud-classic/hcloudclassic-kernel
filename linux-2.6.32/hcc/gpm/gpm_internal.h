#ifndef __GPM_INTERNAL_H__
#define __GPM_INTERNAL_H__

#ifdef CONFIG_HCC_GPM

#include <linux/thread_info.h>
#include <linux/slab.h>
#include <hcc/sys/types.h>
#include <asm/signal.h>

#define HCC_SIG_MIGRATE		SIGRTMIN
#define HCC_SIG_CHECKPOINT	(SIGRTMIN + 1)
#ifdef CONFIG_HCC_FD
#define HCC_SIG_FORK_DELAY_STOP	(SIGRTMIN + 2)
#endif

struct task_struct;

/* Used by migration and restart */
void __hcc_children_share(struct task_struct *task);
void leave_all_relatives(struct task_struct *tsk);
void join_local_relatives(struct task_struct *tsk);

/* Copy-paste from kernel/fork.c + unstatify task_struct_cachep */

#ifndef __HAVE_ARCH_TASK_STRUCT_ALLOCATOR
# define alloc_task_struct()	kmem_cache_alloc(task_struct_cachep, GFP_KERNEL)
# define free_task_struct(tsk)	kmem_cache_free(task_struct_cachep, (tsk))
extern struct kmem_cache *task_struct_cachep;
#endif

#ifndef __HAVE_ARCH_THREAD_INFO_ALLOCATOR
static inline struct thread_info *alloc_thread_info(struct task_struct *tsk)
{
#ifdef CONFIG_DEBUG_STACK_USAGE
	gfp_t mask = GFP_KERNEL | __GFP_ZERO;
#else
	gfp_t mask = GFP_KERNEL;
#endif
	return (struct thread_info *)__get_free_pages(mask, THREAD_SIZE_ORDER);
}

static inline void free_thread_info(struct thread_info *ti)
{
	free_pages((unsigned long)ti, THREAD_SIZE_ORDER);
}
#endif

struct ghotplug_context;

int gpm_ghotplug_init(void);
void gpm_ghotplug_cleanup(void);

int gpm_signal_start(void);
void gpm_signal_exit(void);

int gpm_sighand_start(void);
void gpm_sighand_exit(void);

void gpm_children_start(void);
void gpm_children_exit(void);

void gpm_pidmap_start(void);
void gpm_pidmap_exit(void);
int pidmap_map_add(struct ghotplug_context *ctx);

void gpm_pid_start(void);
void gpm_pid_exit(void);

int gpm_procfs_start(void);
void gpm_procfs_exit(void);

void register_remote_clone_hooks(void);
int gpm_remote_clone_start(void);
void gpm_remote_clone_exit(void);

int gpm_migration_start(void);
void gpm_migration_exit(void);

void register_checkpoint_hooks(void);

void application_cr_server_init(void);
void application_cr_server_finalize(void);

#endif /* CONFIG_HCC_GPM */

#endif /* __GPM_INTERNAL_H__ */
