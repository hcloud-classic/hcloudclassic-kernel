#ifndef _ASM_X86_PGTABLE_64_H
#define _ASM_X86_PGTABLE_64_H

#include <linux/const.h>
#include <linux/kaiser.h>
#include <asm/pgtable_64_types.h>

#ifndef __ASSEMBLY__

/*
 * This file contains the functions and defines necessary to modify and use
 * the x86-64 page table tree.
 */
#include <asm/processor.h>
#include <linux/bitops.h>
#include <linux/threads.h>
#include <asm/mm_track.h>

extern pud_t level3_kernel_pgt[512];
extern pud_t level3_ident_pgt[512];
extern pmd_t level2_kernel_pgt[512];
extern pmd_t level2_fixmap_pgt[512];
extern pmd_t level2_ident_pgt[512];
extern pgd_t init_level4_pgt[];

#define swapper_pg_dir init_level4_pgt

extern void paging_init(void);

#define pte_ERROR(e)					\
	printk("%s:%d: bad pte %p(%016lx).\n",		\
	       __FILE__, __LINE__, &(e), pte_val(e))
#define pmd_ERROR(e)					\
	printk("%s:%d: bad pmd %p(%016lx).\n",		\
	       __FILE__, __LINE__, &(e), pmd_val(e))
#define pud_ERROR(e)					\
	printk("%s:%d: bad pud %p(%016lx).\n",		\
	       __FILE__, __LINE__, &(e), pud_val(e))
#define pgd_ERROR(e)					\
	printk("%s:%d: bad pgd %p(%016lx).\n",		\
	       __FILE__, __LINE__, &(e), pgd_val(e))

struct mm_struct;

void set_pte_vaddr_pud(pud_t *pud_page, unsigned long vaddr, pte_t new_pte);


static inline void native_pte_clear(struct mm_struct *mm, unsigned long addr,
				    pte_t *ptep)
{
	mm_track_pte(ptep);
	*ptep = native_make_pte(0);
}

static inline void native_set_pte(pte_t *ptep, pte_t pte)
{
	mm_track_pte(ptep);
	*ptep = pte;
}

static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	native_set_pte(ptep, pte);
}

static inline pte_t native_ptep_get_and_clear(pte_t *xp)
{
#ifdef CONFIG_SMP
	mm_track_pte(xp);
	return native_make_pte(xchg(&xp->pte, 0));
#else
	/* native_local_ptep_get_and_clear,
	   but duplicated because of cyclic dependency */
	pte_t ret;
	mm_track_pte(xp);
	ret = *xp;
	native_pte_clear(NULL, 0, xp);
	return ret;
#endif
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	mm_track_pmd(pmdp);
	*pmdp = pmd;
}

static inline void native_pmd_clear(pmd_t *pmd)
{
	native_set_pmd(pmd, native_make_pmd(0));
}

static inline pmd_t native_pmdp_get_and_clear(pmd_t *xp)
{
#ifdef CONFIG_SMP
	return native_make_pmd(xchg(&xp->pmd, 0));
#else
	/* native_local_pmdp_get_and_clear,
	   but duplicated because of cyclic dependency */
	pmd_t ret = *xp;
	native_pmd_clear(xp);
	return ret;
#endif
}

static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
	mm_track_pud(pudp);
	*pudp = pud;
}

static inline void native_pud_clear(pud_t *pud)
{
	native_set_pud(pud, native_make_pud(0));
}

static inline void kaiser_poison_pgd(pgd_t *pgd)
{
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		pgd->pgd |= _PAGE_NX;
}

static inline void kaiser_unpoison_pgd(pgd_t *pgd)
{
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		pgd->pgd &= ~_PAGE_NX;
}

static inline void kaiser_poison_pgd_atomic(pgd_t *pgd)
{
	BUILD_BUG_ON(_PAGE_NX == 0);
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		set_bit(_PAGE_BIT_NX, &pgd->pgd);
}

static inline void kaiser_unpoison_pgd_atomic(pgd_t *pgd)
{
	if (pgd->pgd & _PAGE_PRESENT && __supported_pte_mask & _PAGE_NX)
		clear_bit(_PAGE_BIT_NX, &pgd->pgd);
}

static inline void native_set_pgd(pgd_t *pgdp, pgd_t pgd)
{
	mm_track_pgd(pgdp);
	*pgdp = pti_set_user_pgd(pgdp, pgd);
}

static inline void native_pgd_clear(pgd_t *pgd)
{
	native_set_pgd(pgd, native_make_pgd(0));
}

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 */

/*
 * Level 4 access.
 */
static inline int pgd_large(pgd_t pgd) { return 0; }
#define mk_kernel_pgd(address) __pgd((address) | _KERNPG_TABLE)

/* PUD - Level3 access */

/* PMD  - Level 2 access */
#ifdef CONFIG_HCC_GMM
#define pte_to_pgoff(pte) ((pte_val((pte)) & PHYSICAL_PAGE_MASK) >> PAGE_SHIFT)
#define pgoff_to_pte(off) ((pte_t) { .pte = ((off) << PAGE_SHIFT) |	\
					    _PAGE_FILE })
#define PTE_FILE_MAX_BITS __PHYSICAL_MASK_SHIFT
#else /*CONFIG_HCC_GMM */
#define pte_to_pgoff(pte) ((pte_val((pte)) & PHYSICAL_PAGE_MASK) >> PAGE_SHIFT)
#define pgoff_to_pte(off) ((pte_t) { .pte =				\
				((~off & (PHYSICAL_PAGE_MASK>>PAGE_SHIFT)) \
				 << PAGE_SHIFT) | _PAGE_FILE })
#ifdef PTE_FILE_MAX_BITS
#error "must be undefined to activate pte_file_max_bits()"
#endif
static inline int pte_file_max_bits(void)
{
	/*
	 * Set the highest allowed nonlinear pgoff to 1 bit less than
	 * x86_phys_bits to guarantee the inversion of the highest bit
	 * in the pgoff_to_pte conversion. The lowest x86_phys_bits is
	 * 36 so x86 implementations with 36 bits will find themselves
	 * unable to keep using remap_file_pages() with file offsets
	 * above 128TiB (calculated as 1<<(36-1+PAGE_SHIFT)). More
	 * recent CPUs will retain much higher max file offset limits.
	 */
	return min(__PHYSICAL_MASK_SHIFT, boot_cpu_data.x86_phys_bits - 1);
}
#endif /* CONFIG_HCC_GMM */

/* PTE - Level 1 access. */

/* x86-64 always has all page tables mapped. */
#define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
#define pte_offset_map_nested(dir, address) pte_offset_kernel((dir), (address))
#define pte_unmap(pte) /* NOP */
#define pte_unmap_nested(pte) /* NOP */

#define update_mmu_cache(vma, address, pte) do { } while (0)

/* Encode and de-code a swap entry */
#define SWP_TYPE_BITS 5
#ifdef CONFIG_HCC_GMM
#define SWP_OFFSET_SHIFT	9
#else
#define SWP_OFFSET_SHIFT (_PAGE_BIT_PROTNONE + 1)
#endif /* !CONFIG_HCC_GMM */

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
#define __pte_to_swp_entry(pte)		((swp_entry_t) { pte_val((pte)) })
#define __swp_entry_to_pte(x)		((pte_t) { .pte = (x).val })

extern int kern_addr_valid(unsigned long addr);
extern void cleanup_highmap(void);

#define HAVE_ARCH_UNMAPPED_AREA
#define HAVE_ARCH_UNMAPPED_AREA_TOPDOWN

#define pgtable_cache_init()   do { } while (0)
#define check_pgt_cache()      do { } while (0)

#define PAGE_AGP    PAGE_KERNEL_NOCACHE
#define HAVE_PAGE_AGP 1

/* fs/proc/kcore.c */
#define	kc_vaddr_to_offset(v) ((v) & __VIRTUAL_MASK)
#define	kc_offset_to_vaddr(o) ((o) | ~__VIRTUAL_MASK)

#define __HAVE_ARCH_PTE_SAME

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline int pmd_trans_splitting(pmd_t pmd)
{
	return pmd_val(pmd) & _PAGE_SPLITTING;
}

static inline int pmd_trans_huge(pmd_t pmd)
{
	return pmd_val(pmd) & _PAGE_PSE;
}

static inline int has_transparent_hugepage(void)
{
	return cpu_has_pse;
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#define mk_pmd(page, pgprot)   pfn_pmd(page_to_pfn(page), (pgprot))

#define  __HAVE_ARCH_PMDP_SET_ACCESS_FLAGS
extern int pmdp_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pmd_t *pmdp,
				 pmd_t entry, int dirty);

#define __HAVE_ARCH_PMDP_TEST_AND_CLEAR_YOUNG
extern int pmdp_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pmd_t *pmdp);

#define __HAVE_ARCH_PMDP_CLEAR_YOUNG_FLUSH
extern int pmdp_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pmd_t *pmdp);


#define __HAVE_ARCH_PMDP_SPLITTING_FLUSH
extern void pmdp_splitting_flush(struct vm_area_struct *vma,
				 unsigned long addr, pmd_t *pmdp);

#define __HAVE_ARCH_PMD_WRITE
static inline int pmd_write(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_RW;
}

#define __HAVE_ARCH_PMDP_GET_AND_CLEAR
static inline pmd_t pmdp_get_and_clear(struct mm_struct *mm, unsigned long addr,
				       pmd_t *pmdp)
{
	pmd_t pmd = native_pmdp_get_and_clear(pmdp);
	pmd_update(mm, addr, pmdp);
	return pmd;
}

#define __HAVE_ARCH_PMDP_SET_WRPROTECT
static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	clear_bit(_PAGE_BIT_RW, (unsigned long *)&pmdp->pmd);
	pmd_update(mm, addr, pmdp);
}

static inline int pmd_young(pmd_t pmd)
{
	return pmd_flags(pmd) & _PAGE_ACCESSED;
}

static inline pmd_t pmd_set_flags(pmd_t pmd, pmdval_t set)
{
	pmdval_t v = native_pmd_val(pmd);

	return native_make_pmd(v | set);
}

static inline pmd_t pmd_clear_flags(pmd_t pmd, pmdval_t clear)
{
	pmdval_t v = native_pmd_val(pmd);

	return native_make_pmd(v & ~clear);
}

static inline pmd_t pmd_mkold(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_ACCESSED);
}

static inline pmd_t pmd_wrprotect(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_RW);
}

static inline pmd_t pmd_mkdirty(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_DIRTY);
}

static inline pmd_t pmd_mkhuge(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_PSE);
}

static inline pmd_t pmd_mkyoung(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_ACCESSED);
}

static inline pmd_t pmd_mkwrite(pmd_t pmd)
{
	return pmd_set_flags(pmd, _PAGE_RW);
}

static inline pmd_t pmd_mknotpresent(pmd_t pmd)
{
	return pmd_clear_flags(pmd, _PAGE_PRESENT);
}

#include <asm/pgtable-invert.h>

#endif /* !__ASSEMBLY__ */

#endif /* _ASM_X86_PGTABLE_64_H */
