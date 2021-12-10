/** Distributed management of the MM structure.
 *  @file mm_struct.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/proc_fs.h>
#include <linux/binfmts.h>
#include <asm/mmu_context.h>
#include <net/grpc/grpc.h>
#include <net/grpc/grpcid.h>
#include <hcc/hcc_init.h>
#include <asm/uaccess.h>
#include <hcc/hcc_services.h>
#include <gdm/gdm.h>
#include <hcc/page_table_tree.h>
#include <hcc/ghotplug.h>
#include "memory_int_linker.h"
#include "memory_io_linker.h"
#include "mm_struct.h"
#include "vma_struct.h"
#include "mm_server.h"

void (*hcc_mm_get) (struct mm_struct *mm) = NULL;
void (*hcc_mm_release) (struct mm_struct *mm, int notify) = NULL;

struct mm_struct *(*hcc_copy_mm)(struct task_struct *tsk,
				struct mm_struct *oldmm,
				unsigned long clone_flags) = NULL;

void (*hcc_fill_pte)(struct mm_struct *mm, unsigned long addr,
		    pte_t *pte) = NULL;
void (*hcc_zap_pte)(struct mm_struct *mm, unsigned long addr,
		   pte_t *pte) = NULL;

int hcc_do_execve(struct task_struct *tsk, struct mm_struct *mm)
{
	if (can_use_hcc_gcap(current, GCAP_USE_REMOTE_MEMORY))
		return init_anon_vma_gdm_set(tsk, mm);

	return 0;
}

int reinit_mm(struct mm_struct *mm)
{
	unique_id_t mm_id;

	/* Backup mm_id which is set to 0 in mm_init... */
	mm_id = mm->mm_id;
	if (!mm_init(mm, NULL))
		return -ENOMEM;

	mm->mm_id = mm_id;
	mm->locked_vm = 0;
	mm->mmap = NULL;
	mm->mmap_cache = NULL;
	mm->map_count = 0;
	cpus_clear (mm->cpu_vm_mask);
	mm->mm_rb = RB_ROOT;
	mm->token_priority = 0;
	mm->last_interval = 0;
	/* Insert the new mm struct in the list of active mm */
	spin_lock (&mmlist_lock);
	list_add (&mm->mmlist, &init_mm.mmlist);
	spin_unlock (&mmlist_lock);
#ifdef CONFIG_PROC_FS
	mm->exe_file = NULL;
	mm->num_exe_file_vmas = 0;
#endif

	return 0;
}

void mm_struct_pin(struct mm_struct *mm)
{
	down_read(&mm->remove_sem);
}

void mm_struct_unpin(struct mm_struct *mm)
{
	up_read(&mm->remove_sem);
}

/* Unique mm_struct id generator root */
unique_id_root_t mm_struct_unique_id_root;

/* mm_struct GDM set */
struct gdm_set *mm_struct_gdm_set = NULL;

void kcb_fill_pte(struct mm_struct *mm, unsigned long addr, pte_t pte);
void kcb_zap_pte(struct mm_struct *mm, unsigned long addr, pte_t pte);



void break_distributed_cow(struct gdm_set *set, struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	unsigned long addr;

	for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
		if (vma->vm_ops != &anon_memory_gdm_vmops)
			continue;

		for (addr = vma->vm_start;
		     addr < vma->vm_end;
		     addr += PAGE_SIZE)
			_gdm_grab_object_no_ft(set, addr / PAGE_SIZE);
	}
}



void break_distributed_cow_put(struct gdm_set *set, struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	unsigned long addr;

	for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
		cond_resched();
		if (vma->vm_ops != &anon_memory_gdm_vmops)
			continue;

		for (addr = vma->vm_start;
		     addr < vma->vm_end;
		     addr += PAGE_SIZE)
			_gdm_put_object(set, addr / PAGE_SIZE);
	}
}



/* Duplicate a MM struct for a distant fork. The resulting MM will be used
 * to store pages locally for a remote process through a memory GDM set.
 */
struct mm_struct *hcc_dup_mm(struct task_struct *tsk, struct mm_struct *src_mm)
{
	struct mm_struct *mm;
	int err = -ENOMEM;

	if (src_mm->anon_vma_gdm_set)
		break_distributed_cow(src_mm->anon_vma_gdm_set, src_mm);

	mm = allocate_mm();
	if (!mm)
		goto fail_nomem;

	memcpy(mm, src_mm, sizeof(*mm));

	err = reinit_mm(mm);
	if (err)
		goto exit_put_mm;

	err = init_new_context(NULL, mm);
	if (err)
		goto fail_nocontext;

	/* The duplicated mm does not yet belong to any real process */
	atomic_set(&mm->mm_ltasks, 0);

	err = __dup_mmap(mm, src_mm, 1);
	if (err)
		goto exit_put_mm;

	mm->hiwater_rss = get_mm_rss(mm);
	mm->hiwater_vm = mm->total_vm;

	if (mm->binfmt && !try_module_get(mm->binfmt->module))
		goto exit_put_mm;

	err = init_anon_vma_gdm_set(tsk, mm);
	if (err)
		goto exit_put_mm;

	if (src_mm->anon_vma_gdm_set)
		break_distributed_cow_put(src_mm->anon_vma_gdm_set, src_mm);

	dup_mm_exe_file(src_mm, mm);
#ifdef CONFIG_PROCFS
	/* reinit_mm() reset it */
	mm->num_exe_file_vmas = src_mm->num_exe_file_vmas;
#endif

	/* MM not used locally -> drop the mm_users count
	 * (was setup to 1 in alloc and inc in
	 * create_mm_struct_object) */
	atomic_dec(&mm->mm_users);

	return mm;

exit_put_mm:
	/* don't put binfmt in mmput, we haven't got module yet */
	mm->binfmt = NULL;
	mmput(mm);

fail_nomem:
	return ERR_PTR(err);

fail_nocontext:
	/*
	 * If init_new_context() failed, we cannot use mmput() to free the mm
	 * because it calls destroy_context()
	 */
	pgd_free(mm, mm->pgd);
	free_mm(mm);
	return ERR_PTR(err);
}



void create_mm_struct_object(struct mm_struct *mm)
{
	struct mm_struct *_mm;

	BUG_ON(atomic_read(&mm->mm_ltasks) > 1);

	atomic_inc(&mm->mm_users); // Get a reference count for the GDM.

	hcc_node_set(hcc_node_id, mm->copyset);

	mm->mm_id = get_unique_id(&mm_struct_unique_id_root);

	_mm = _gdm_grab_object_manual_ft(mm_struct_gdm_set, mm->mm_id);
	BUG_ON(_mm);
	_gdm_set_object(mm_struct_gdm_set, mm->mm_id, mm);

	hcc_put_mm(mm->mm_id);
}



/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/



struct mm_struct *dup_mm(struct task_struct *tsk);

static struct mm_struct *kcb_copy_mm(struct task_struct * tsk,
				     struct mm_struct *oldmm,
				     unsigned long clone_flags)
{
	struct mm_struct *mm = NULL;

	if (oldmm->anon_vma_gdm_set)
		break_distributed_cow(oldmm->anon_vma_gdm_set, oldmm);

	mm = dup_mm(tsk);
	if (!mm)
		goto done_put;

	mm->mm_id = 0;
	mm->anon_vma_gdm_set = NULL;
	mm->anon_vma_gdm_id = 0;
	hcc_nodes_clear (mm->copyset);

	if (clone_flags & CLONE_VFORK)
		goto done_put;

	if (cap_raised(tsk->hcc_gcaps.effective, GCAP_USE_REMOTE_MEMORY) ||
	    oldmm->anon_vma_gdm_set) {
		if (init_anon_vma_gdm_set(tsk, mm) != 0) {
			BUG();
			mmput(mm);
			mm = NULL;
			goto done_put;
		}
	}

done_put:
	if (oldmm->anon_vma_gdm_set)
		break_distributed_cow_put(oldmm->anon_vma_gdm_set, oldmm);

	return mm;
}


int init_anon_vma_gdm_set(struct task_struct *tsk,
			   struct mm_struct *mm)
{
	struct gdm_set *set;

	mm->mm_id = 0;
	hcc_nodes_clear (mm->copyset);

	set = __create_new_gdm_set(gdm_def_ns, 0, &gdm_pt_set_ops, mm,
				    MEMORY_LINKER, hcc_node_id,
				    PAGE_SIZE, NULL, 0, 0);

	if (IS_ERR(set))
		return PTR_ERR(set);

	create_mm_struct_object(mm);

	return 0;
}



void hcc_check_vma_link(struct vm_area_struct *vma)
{
	BUG_ON (!vma->vm_mm->anon_vma_gdm_set);
	check_link_vma_to_anon_memory_gdm_set (vma);
}



void kcb_mm_get(struct mm_struct *mm)
{
	if (!mm)
		return;

	if (!mm->mm_id) {
		atomic_inc (&mm->mm_tasks);
		return;
	}

	hcc_grab_mm(mm->mm_id);
	atomic_inc (&mm->mm_tasks);
	hcc_put_mm(mm->mm_id);
}



void clean_up_mm_struct (struct mm_struct *mm)
{
	struct vm_area_struct *vma, *next, *prev;

	/* Take the semaphore to avoid race condition with mm_remove_object */

	down_write(&mm->mmap_sem);

	prev = NULL;
	vma = mm->mmap;

	while (vma) {
		next = vma->vm_next;

		if (!anon_vma(vma)) {
			detach_vmas_to_be_unmapped(mm, vma, prev, vma->vm_end);
			unmap_region(mm, vma, prev, vma->vm_start,
				     vma->vm_end);
			remove_vma_list(mm, vma);
		}
		else
			prev = vma;

		vma = next;
	}
	up_write(&mm->mmap_sem);
}



static void kcb_mm_release(struct mm_struct *mm, int notify)
{
	if (!mm)
		return;

	BUG_ON(!mm->mm_id);

	if (!notify) {
		/* Not a real exit: clean up VMAs */
		BUG_ON (atomic_read(&mm->mm_ltasks) != 0);
		clean_up_mm_struct(mm);
		mm_struct_unpin(mm);
		return;
	}

	hcc_grab_mm(mm->mm_id);
	atomic_dec (&mm->mm_tasks);

	if (atomic_read(&mm->mm_tasks) == 0) {
		struct gdm_set *set = mm->anon_vma_gdm_set;
		unique_id_t mm_id = mm->mm_id;

		mm->mm_id = 0;

		_gdm_remove_frozen_object(mm_struct_gdm_set, mm_id);
		_destroy_gdm_set(set);
	}
	else
		hcc_put_mm(mm->mm_id);
}


void hcc_do_mmap_region(struct vm_area_struct *vma,
			unsigned long flags,
			unsigned long long vm_flags)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mm_mmap_msg msg;
	hcc_nodemask_t copyset;

	if (!mm->anon_vma_gdm_set)
		return;

	BUG_ON (!mm->mm_id);

	check_link_vma_to_anon_memory_gdm_set (vma);

	if (!(vma->vm_flags & VM_GDM))
		return;

	if (hcc_node_is_unique(hcc_node_id, mm->copyset))
		return;

	msg.mm_id = mm->mm_id;
	msg.start = vma->vm_start;
	msg.len = vma->vm_end - vma->vm_start;
	msg.flags = flags;
	msg.vm_flags = vm_flags;
	msg.pgoff = vma->vm_pgoff;

	hcc_nodes_copy(copyset, mm->copyset);
	hcc_node_clear(hcc_node_id, copyset);

	grpc_sync_m(GRPC_MM_MMAP_REGION, &copyset, &msg, sizeof(msg));
}


void hcc_do_munmap(struct mm_struct *mm,
		   unsigned long start,
		   size_t len)
{
	struct mm_mmap_msg msg;
	hcc_nodemask_t copyset;

	if (!mm->mm_id)
		return;

	if (hcc_node_is_unique(hcc_node_id, mm->copyset))
		return;

	msg.mm_id = mm->mm_id;
	msg.start = start;
	msg.len = len;

	hcc_nodes_copy(copyset, mm->copyset);
	hcc_node_clear(hcc_node_id, copyset);

	grpc_sync_m(GRPC_MM_MUNMAP, &copyset, &msg, sizeof(msg));
}

void hcc_do_mremap(struct mm_struct *mm, unsigned long addr,
		   unsigned long old_len, unsigned long new_len,
		   unsigned long flags, unsigned long new_addr,
		   unsigned long _new_addr, unsigned long lock_limit)
{
	struct mm_mmap_msg msg;
	hcc_nodemask_t copyset;

	if (!mm->mm_id)
		return;

	if (hcc_node_is_unique(hcc_node_id, mm->copyset))
		return;

	msg.mm_id = mm->mm_id;
	msg.addr = addr;
	msg.old_len = old_len;
	msg.new_len = new_len;
	msg.flags = flags;
	msg.new_addr = new_addr;
	msg._new_addr = _new_addr;
	msg.lock_limit = lock_limit;

	hcc_nodes_copy(copyset, mm->copyset);
	hcc_node_clear(hcc_node_id, copyset);

	grpc_sync_m(GRPC_MM_MREMAP, &copyset, &msg, sizeof(msg));
}

void hcc_do_brk(struct mm_struct *mm,
		unsigned long brk,
		unsigned long lock_limit,
		unsigned long data_limit)
{
	struct mm_mmap_msg msg;
	hcc_nodemask_t copyset;

	BUG_ON (!mm->mm_id);

	if (hcc_node_is_unique(hcc_node_id, mm->copyset))
		return;

	msg.mm_id = mm->mm_id;
	msg.brk = brk;
	msg.lock_limit = lock_limit;
	msg.data_limit = data_limit;

	hcc_nodes_copy(copyset, mm->copyset);
	hcc_node_clear(hcc_node_id, copyset);

	grpc_sync_m(GRPC_MM_DO_BRK, &copyset, &msg, sizeof(msg));
}

int hcc_expand_stack(struct vm_area_struct *vma,
		     unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	struct mm_mmap_msg msg;
	hcc_nodemask_t copyset;
	int r;

	BUG_ON (!mm->mm_id);

	if (hcc_node_is_unique(hcc_node_id, mm->copyset))
		return 0;

	msg.mm_id = mm->mm_id;
	msg.start = vma->vm_start;
	msg.flags = address;

	hcc_nodes_copy(copyset, mm->copyset);
	hcc_node_clear(hcc_node_id, copyset);

	r = grpc_sync_m(GRPC_MM_EXPAND_STACK, &copyset, &msg, sizeof(msg));

	return r;
}

void hcc_do_mprotect(struct mm_struct *mm,
		     unsigned long start,
		     size_t len,
		     unsigned long prot,
		     int personality)
{
	struct mm_mmap_msg msg;
	hcc_nodemask_t copyset;

	if (!mm->mm_id)
		return;

	if (hcc_node_is_unique(hcc_node_id, mm->copyset))
		return;

	msg.mm_id = mm->mm_id;
	msg.start = start;
	msg.len = len;
	msg.prot = prot;
	msg.personality = personality;

	hcc_nodes_copy(copyset, mm->copyset);
	hcc_node_clear(hcc_node_id, copyset);

	grpc_sync_m(GRPC_MM_MPROTECT, &copyset, &msg, sizeof(msg));
}


/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/



void mm_struct_init (void)
{
	init_unique_id_root (&mm_struct_unique_id_root);

	mm_struct_gdm_set = create_new_gdm_set(gdm_def_ns,
						 MM_STRUCT_GDM_ID,
						 MM_STRUCT_LINKER,
						 GDM_UNIQUE_ID_DEF_OWNER,
						 sizeof (struct mm_struct),
						 GDM_LOCAL_EXCLUSIVE);

	if (IS_ERR(mm_struct_gdm_set))
		OOM;

	hook_register(&hcc_copy_mm, kcb_copy_mm);
	hook_register(&hcc_mm_get, kcb_mm_get);
	hook_register(&hcc_mm_release, kcb_mm_release);
	hook_register(&hcc_fill_pte, kcb_fill_pte);
	hook_register(&hcc_zap_pte, kcb_zap_pte);
}



void mm_struct_finalize (void)
{
}
