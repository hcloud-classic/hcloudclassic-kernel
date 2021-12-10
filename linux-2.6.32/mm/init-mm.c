#include <linux/mm_types.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/cpumask.h>

#include <asm/atomic.h>
#include <asm/pgtable.h>

#ifdef CONFIG_HCC_GPM
#define INIT_MM_GPM	.mm_ltasks	= ATOMIC_INIT(1),
#else
#define INIT_MM_GPM
#endif

#ifdef CONFIG_HCC_GMM
#define INIT_MM_MM	.mm_tasks	= ATOMIC_INIT(1),
#else
#define INIT_MM_MM
#endif

struct mm_struct init_mm = {
	.mm_rb		= RB_ROOT,
	.pgd		= swapper_pg_dir,
	INIT_MM_MM
	INIT_MM_GPM
	.mm_users	= ATOMIC_INIT(2),
	.mm_count	= ATOMIC_INIT(1),
	.mmap_sem	= __RWSEM_INITIALIZER(init_mm.mmap_sem),
	.page_table_lock =  __SPIN_LOCK_UNLOCKED(init_mm.page_table_lock),
	.mmlist		= LIST_HEAD_INIT(init_mm.mmlist),
	.cpu_vm_mask	= CPU_MASK_ALL,
};
