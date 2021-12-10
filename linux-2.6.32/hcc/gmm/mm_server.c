/** HCC MM servers.
 *  @file mm_server.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/kernel.h>
#include <linux/mm.h>

#include <net/grpc/grpc.h>
#include "mm_struct.h"
#include "mm_server.h"
#include "memory_int_linker.h"

/** Handler for remote mmap.
 *  @author Innogrid HCC
 */
int handle_do_mmap_region (struct grpc_desc* desc,
			   void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct vm_area_struct *vma;
	struct mm_struct *mm;

	mm = hcc_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	__mmap_region(mm, NULL, msg->start, msg->len, msg->flags,
		      msg->vm_flags, msg->pgoff, 1);

	vma = find_vma(mm, msg->start);
	BUG_ON(!vma || vma->vm_start != msg->start);

	check_link_vma_to_anon_memory_gdm_set (vma);

	up_write(&mm->mmap_sem);

	hcc_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote mremap.
 *  @author Innogrid HCC
 */
int handle_do_mremap (struct grpc_desc* desc,
		      void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = hcc_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	__do_mremap(mm, msg->addr, msg->old_len, msg->new_len, msg->flags,
		    msg->new_addr, &msg->_new_addr, msg->lock_limit);

	up_write(&mm->mmap_sem);

	hcc_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote munmap.
 *  @author Innogrid HCC
 */
int handle_do_munmap (struct grpc_desc* desc,
		      void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = hcc_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	do_munmap(mm, msg->start, msg->len);

	up_write(&mm->mmap_sem);

	hcc_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote brk.
 *  @author Innogrid HCC
 */
int handle_do_brk (struct grpc_desc* desc,
		   void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = hcc_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	down_write(&mm->mmap_sem);

	__sys_brk(mm, msg->brk, msg->lock_limit, msg->data_limit);

	up_write(&mm->mmap_sem);

	hcc_put_mm(msg->mm_id);

	return 0;
}

/** Handler for remote expand_stack.
 *  @author Innogrid HCC
 */
int handle_expand_stack (struct grpc_desc* desc,
			 void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct vm_area_struct *vma;
	struct mm_struct *mm;
	int r;

	mm = hcc_get_mm(msg->mm_id);

	if (!mm)
		return -EINVAL;

	down_write(&mm->mmap_sem);

	vma = find_vma(mm, msg->start);

	r = __expand_stack(vma, msg->flags);

	up_write(&mm->mmap_sem);

	hcc_put_mm(msg->mm_id);

	return r;
}

/** Handler for remote mprotect.
 *  @author Innogrid HCC
 */
int handle_do_mprotect (struct grpc_desc* desc,
			void *msgIn, size_t size)
{
	struct mm_mmap_msg *msg = msgIn;
	struct mm_struct *mm;

	mm = hcc_get_mm(msg->mm_id);

	if (!mm)
		return 0;

	do_mprotect (mm, msg->start, msg->len, msg->prot, msg->personality);

	hcc_put_mm(msg->mm_id);

	return 0;
}

/* MM handler Initialisation */

void mm_server_init (void)
{
	grpc_register_int(GRPC_MM_MMAP_REGION, handle_do_mmap_region, 0);
	grpc_register_int(GRPC_MM_MREMAP, handle_do_mremap, 0);
	grpc_register_int(GRPC_MM_MUNMAP, handle_do_munmap, 0);
	grpc_register_int(GRPC_MM_DO_BRK, handle_do_brk, 0);
	grpc_register_int(GRPC_MM_EXPAND_STACK, handle_expand_stack, 0);
	grpc_register_int(GRPC_MM_MPROTECT, handle_do_mprotect, 0);
}



/* MM server Finalization */

void mm_server_finalize (void)
{
}
