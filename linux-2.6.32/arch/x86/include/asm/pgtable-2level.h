#ifndef _ASM_X86_PGTABLE_2LEVEL_H
#define _ASM_X86_PGTABLE_2LEVEL_H

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %08lx.\n", __FILE__, __LINE__, (e).pte_low)
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %08lx.\n", __FILE__, __LINE__, pgd_val(e))

/*
 * Certain architectures need to do special things when PTEs
 * within a page table are directly modified.  Thus, the following
 * hook is made available.
 */
static inline void native_set_pte(pte_t *ptep , pte_t pte)
{
	mm_track_pte(ptep);
	*ptep = pte;
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	mm_track_pmd(pmdp);
	*pmdp = pmd;
}

static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	native_set_pte(ptep, pte);
}

static inline void native_pmd_clear(pmd_t *pmdp)
{
	native_set_pmd(pmdp, __pmd(0));
}

static inline void native_pte_clear(struct mm_struct *mm,
				    unsigned long addr, pte_t *xp)
{
	mm_track_pte(xp);
	*xp = native_make_pte(0);
}

#ifdef CONFIG_SMP
static inline pte_t native_ptep_get_and_clear(pte_t *xp)
{
	mm_track_pte(xp);
	return __pte(xchg(&xp->pte_low, 0));
}
#else
#define native_ptep_get_and_clear(xp) native_local_ptep_get_and_clear(xp)
#endif

/*
 * Bits _PAGE_BIT_PRESENT, _PAGE_BIT_FILE and _PAGE_BIT_PROTNONE are taken,
 * split up the 29 bits of offset into this range:
 */
#ifdef CONFIG_HCC_GMM
/* Bit _PAGE_OBJ_ENTRY is taken too */
#define PTE_FILE_MAX_BITS	28

#define pte_to_pgoff(pte) ((pte_val((pte)) & ~0xf) >> 4)	\

#define pgoff_to_pte(off) ((pte_t) { .pte = ((off) << 4) |	\
				            _PAGE_FILE })
#else
#define PTE_FILE_MAX_BITS	29
#define PTE_FILE_SHIFT1		(_PAGE_BIT_PRESENT + 1)
#if _PAGE_BIT_FILE < _PAGE_BIT_PROTNONE
#define PTE_FILE_SHIFT2		(_PAGE_BIT_FILE + 1)
#define PTE_FILE_SHIFT3		(_PAGE_BIT_PROTNONE + 1)
#else
#define PTE_FILE_SHIFT2		(_PAGE_BIT_PROTNONE + 1)
#define PTE_FILE_SHIFT3		(_PAGE_BIT_FILE + 1)
#endif
#define PTE_FILE_BITS1		(PTE_FILE_SHIFT2 - PTE_FILE_SHIFT1 - 1)
#define PTE_FILE_BITS2		(PTE_FILE_SHIFT3 - PTE_FILE_SHIFT2 - 1)

#define pte_to_pgoff(pte)						\
	((((pte).pte_low >> PTE_FILE_SHIFT1)				\
	  & ((1U << PTE_FILE_BITS1) - 1))				\
	 + ((((pte).pte_low >> PTE_FILE_SHIFT2)				\
	     & ((1U << PTE_FILE_BITS2) - 1)) << PTE_FILE_BITS1)		\
	 + (((pte).pte_low >> PTE_FILE_SHIFT3)				\
	    << (PTE_FILE_BITS1 + PTE_FILE_BITS2)))

#define pgoff_to_pte(off)						\
	((pte_t) { .pte_low =						\
	 (((off) & ((1U << PTE_FILE_BITS1) - 1)) << PTE_FILE_SHIFT1)	\
	 + ((((off) >> PTE_FILE_BITS1) & ((1U << PTE_FILE_BITS2) - 1))	\
	    << PTE_FILE_SHIFT2)						\
	 + (((off) >> (PTE_FILE_BITS1 + PTE_FILE_BITS2))		\
	    << PTE_FILE_SHIFT3)						\
	 + _PAGE_FILE })
#endif /* ! CONFIG_HCC_GMM */


/* Encode and de-code a swap entry */
#ifdef CONFIG_HCC_GMM
#define SWP_TYPE_BITS		5
#define SWP_OFFSET_SHIFT	9
#else
#if _PAGE_BIT_FILE < _PAGE_BIT_PROTNONE
#define SWP_TYPE_BITS (_PAGE_BIT_FILE - _PAGE_BIT_PRESENT - 1)
#define SWP_OFFSET_SHIFT (_PAGE_BIT_PROTNONE + 1)
#else
#define SWP_TYPE_BITS (_PAGE_BIT_PROTNONE - _PAGE_BIT_PRESENT - 1)
#define SWP_OFFSET_SHIFT (_PAGE_BIT_FILE + 1)
#endif
#endif /* ! CONFIG_HCC_GMM */


#define MAX_SWAPFILES_CHECK() BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > SWP_TYPE_BITS)
#ifdef CONFIG_HCC_GMM
#define __swp_type(x)			(((x).val >> (_PAGE_BIT_FILE + 1)) \
					 & ((1U << SWP_TYPE_BITS) - 1))
#else
#define __swp_type(x)			(((x).val >> (_PAGE_BIT_PRESENT + 1)) \
					 & ((1U << SWP_TYPE_BITS) - 1))
#endif
#define __swp_offset(x)			((x).val >> SWP_OFFSET_SHIFT)
#ifdef CONFIG_HCC_GMM
#define __swp_entry(type, offset)	((swp_entry_t) { \
					 ((type) << (_PAGE_BIT_FILE + 1)) \
					 | ((offset) << SWP_OFFSET_SHIFT) })
#else
#define __swp_entry(type, offset)	((swp_entry_t) { \
					 ((type) << (_PAGE_BIT_PRESENT + 1)) \
					 | ((offset) << SWP_OFFSET_SHIFT) })
#endif
#define __pte_to_swp_entry(pte)		((swp_entry_t) { (pte).pte_low })
#define __swp_entry_to_pte(x)		((pte_t) { .pte = (x).val })

#ifdef CONFIG_HCC_GMM
#include <asm/pgtable-invert.h>
#else /* CONFIG_HCC_GMM */
/* No inverted PFNs on 2 level page tables */

static inline u64 protnone_mask(u64 val)
{
	return 0;
}

static inline u64 flip_protnone_guard(u64 oldval, u64 val, u64 mask)
{
	return val;
}

static inline bool __pte_needs_invert(u64 val)
{
	return false;
}
#endif /* CONFIG_HCC_GMM */

#endif /* _ASM_X86_PGTABLE_2LEVEL_H */
