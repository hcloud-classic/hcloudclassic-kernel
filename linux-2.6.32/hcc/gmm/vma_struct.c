/** Distributed management of the VMA structure.
 *  @file vma_struct.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/mm.h>
#include <linux/rmap.h>

void partial_init_vma(struct mm_struct *mm, struct vm_area_struct *vma)
{
	vma->vm_mm = mm;
	vma->vm_next = NULL;
	INIT_LIST_HEAD(&vma->anon_vma_chain);
	vma->vm_truncate_count = 0;
	memset (&vma->shared, 0, sizeof (vma->shared));
	memset (&vma->vm_rb, 0, sizeof (vma->vm_rb));
	vma->vm_private_data = NULL;
}

int alloc_fake_vma(struct mm_struct *mm,
		   unsigned long start,
		   unsigned long end)
{
	struct vm_area_struct *vma;
	int r = 0;

	vma = kmem_cache_zalloc(vm_area_cachep, GFP_ATOMIC);
	if (!vma)
		return -ENOMEM;

	partial_init_vma (mm, vma);
	vma->vm_start = start;
	vma->vm_end = end;
	vma->vm_flags = VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE |
		VM_MAYEXEC;

	r = insert_vm_struct(mm, vma);
	if (unlikely(r))
		goto err;

	vma->anon_vma = NULL;

	return 0;
err:
	kmem_cache_free(vm_area_cachep, vma);
	return r;
}
