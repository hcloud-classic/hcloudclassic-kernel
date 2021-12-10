/** GDM object tree based on page tables.
 *  @file page_table_tree.h
 *
 *  @author Innogrid HCC
 */

#ifndef __PAGE_TABLE_TREE__
#define __PAGE_TABLE_TREE__

#include <gdm/gdm_types.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/


extern struct gdm_set_ops gdm_pt_set_ops;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

static inline unsigned long mk_swap_pte_page(pte_t *ptep)
{
	return (pte_val(*ptep) | 1);
}

static inline unsigned long swap_pte_page(struct page *page)
{
	return ((unsigned long) page) & 1 ;
}

struct gdm_obj *get_obj_entry_from_pte(struct mm_struct *mm,
					unsigned long addr, pte_t *ptep,
					struct gdm_obj *new_obj);

static inline swp_entry_t get_swap_entry_from_page(struct page *page)
{
	pte_t pte;

	pte = __pte(((unsigned long) page) & ~1UL);
	return pte_to_swp_entry(pte);
}

static inline void wait_lock_page (struct page *page)
{
	while (TestSetPageLocked(page))
		cpu_relax();
}

/* Used to ensure atomicity of operations on gdm_count and obj_entry fields */
static inline void wait_lock_gdm_page (struct page *page)
{
       while (TestSetPageLockedGDM(page))
		cpu_relax();
}

static inline void unlock_gdm_page (struct page *page)
{
	ClearPageLockedGDM(page);
}

int gdm_pt_invalidate (struct gdm_set *set, objid_t objid,
			struct gdm_obj *obj_entry, struct page *page);

int gdm_pt_swap_in (struct mm_struct *mm, unsigned long addr, pte_t *orig_pte);

#endif // __PAGE_TABLE_TREE__
