/** GDM Memory interface Linker.
 *  @file memory_int_linker.h
 *
 *  Link gdm sets and linux memory system.
 *  @author Innogrid HCC
 */

#ifndef __MEMORY_INT_LINKER__
#define __MEMORY_INT_LINKER__

#include <linux/mm.h>

#include <gdm/gdm.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct vm_operations_struct anon_memory_gdm_vmops;
extern struct vm_operations_struct null_vm_ops;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Link a VMA to an anon gdm set.
 *  @author Innogrid HCC
 *
 *  @param vma     vma structure to link to the anon GDM set.
 *
 *  The gdm set must have been allocated and initialized. The
 *  VM_CONTAINER flag is added to the vm_cflags field of the vma. The
 *  gdm set id is stored in the vm_ctnr field and vm operations are
 *  set to the operations used by gdm sets, depending on the
 *  gdm set type.
 */
int check_link_vma_to_anon_memory_gdm_set (struct vm_area_struct *vma);

static inline void restore_initial_vm_ops (struct vm_area_struct *vma)
{
	if (vma->initial_vm_ops == NULL)
		return;

	if (vma->initial_vm_ops == &null_vm_ops)
		vma->vm_ops = NULL;
	else
		vma->vm_ops = vma->initial_vm_ops;
}



/* Return the page table entry associated to a virtual address */
static inline pte_t *get_pte_no_lock (struct mm_struct *mm, unsigned long addr)
{
	pgd_t * pgd = pgd_offset(mm, addr);
	pud_t * pud = pud_alloc(mm, pgd, addr);
	pmd_t * pmd;

	if (!pud)
		return NULL;

	pmd = pmd_alloc(mm, pud, addr);
	if (!pmd)
		return NULL;

	return pte_alloc_map(mm, NULL, pmd, addr);
}

#endif /* __MEMORY_INT_LINKER__ */
