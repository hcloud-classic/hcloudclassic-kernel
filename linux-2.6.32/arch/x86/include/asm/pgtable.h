#ifndef _ASM_X86_PGTABLE_H
#define _ASM_X86_PGTABLE_H

#include <asm/page.h>
#include <asm/e820.h>

#include <asm/pgtable_types.h>

/*
 * Macro to mark a page protection value as UC-
 */
#define pgprot_noncached(prot)					\
	((boot_cpu_data.x86 > 3)				\
	 ? (__pgprot(pgprot_val(prot) | _PAGE_CACHE_UC_MINUS))	\
	 : (prot))

#ifndef __ASSEMBLY__

#include <asm/x86_init.h>

/*
 * ZERO_PAGE is a global shared page that is always zero: used
 * for zero-mapped memory areas etc..
 */
extern unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)];
#define ZERO_PAGE(vaddr) (virt_to_page(empty_zero_page))

extern spinlock_t pgd_lock;
extern struct list_head pgd_list;

extern struct mm_struct *pgd_page_get_mm(struct page *page);

#ifdef CONFIG_PARAVIRT
#include <asm/paravirt.h>
#else  /* !CONFIG_PARAVIRT */
#define set_pte(ptep, pte)		native_set_pte(ptep, pte)
#define set_pte_at(mm, addr, ptep, pte)	native_set_pte_at(mm, addr, ptep, pte)
#define set_pmd_at(mm, addr, pmdp, pmd)	native_set_pmd_at(mm, addr, pmdp, pmd)

#define set_pte_atomic(ptep, pte)					\
	native_set_pte_atomic(ptep, pte)

#define set_pmd(pmdp, pmd)		native_set_pmd(pmdp, pmd)

#ifndef __PAGETABLE_PUD_FOLDED
#define set_pgd(pgdp, pgd)		native_set_pgd(pgdp, pgd)
#define pgd_clear(pgd)			native_pgd_clear(pgd)
#endif

#ifndef set_pud
# define set_pud(pudp, pud)		native_set_pud(pudp, pud)
#endif

#ifndef __PAGETABLE_PMD_FOLDED
#define pud_clear(pud)			native_pud_clear(pud)
#endif

#define pte_clear(mm, addr, ptep)	native_pte_clear(mm, addr, ptep)
#define pmd_clear(pmd)			native_pmd_clear(pmd)

#define pte_update(mm, addr, ptep)              do { } while (0)
#define pte_update_defer(mm, addr, ptep)        do { } while (0)
#define pmd_update(mm, addr, ptep)              do { } while (0)
#define pmd_update_defer(mm, addr, ptep)        do { } while (0)

#define pgd_val(x)	native_pgd_val(x)
#define __pgd(x)	native_make_pgd(x)

#ifndef __PAGETABLE_PUD_FOLDED
#define pud_val(x)	native_pud_val(x)
#define __pud(x)	native_make_pud(x)
#endif

#ifndef __PAGETABLE_PMD_FOLDED
#define pmd_val(x)	native_pmd_val(x)
#define __pmd(x)	native_make_pmd(x)
#endif

#define pte_val(x)	native_pte_val(x)
#define __pte(x)	native_make_pte(x)

#define arch_end_context_switch(prev)	do {} while(0)

#endif	/* CONFIG_PARAVIRT */

/*
 * The following only work if pte_present() is true.
 * Undefined behaviour if not..
 */
static inline int pte_dirty(pte_t pte)
{
	return pte_flags(pte) & (_PAGE_DIRTY | _PAGE_SOFTDIRTY);
}

static inline int pte_young(pte_t pte)
{
	return pte_flags(pte) & _PAGE_ACCESSED;
}

static inline int pte_write(pte_t pte)
{
	return pte_flags(pte) & _PAGE_RW;
}

static inline int pte_file(pte_t pte)
{
	return pte_flags(pte) & _PAGE_FILE;
}

static inline int pte_huge(pte_t pte)
{
	return pte_flags(pte) & _PAGE_PSE;
}

static inline int pte_global(pte_t pte)
{
	return pte_flags(pte) & _PAGE_GLOBAL;
}

static inline int pte_exec(pte_t pte)
{
	return !(pte_flags(pte) & _PAGE_NX);
}

static inline int pte_special(pte_t pte)
{
	return pte_flags(pte) & _PAGE_SPECIAL;
}

/* Entries that were set to PROT_NONE are inverted */

static inline u64 protnone_mask(u64 val);

static inline unsigned long pte_pfn(pte_t pte)
{
	phys_addr_t pfn = pte_val(pte);
	pfn ^= protnone_mask(pfn);
	return (pfn & PTE_PFN_MASK) >> PAGE_SHIFT;
}

static inline unsigned long pmd_pfn(pmd_t pmd)
{
	phys_addr_t pfn = pmd_val(pmd);
	pfn ^= protnone_mask(pfn);
#ifdef CONFIG_HCC_GMM
	return (pfn & PTE_PFN_MASK) >> PAGE_SHIFT;
#else
	return (pfn & pmd_pfn_mask(pmd)) >> PAGE_SHIFT;
#endif
}

#ifdef CONFIG_HCC_GMM
static inline unsigned long pud_pfn(pud_t pud)
{
	return (pud_val(pud) & PTE_PFN_MASK) >> PAGE_SHIFT;
}
#else
static inline unsigned long pud_pfn(pud_t pud)
{
	return (pud_val(pud) & pud_pfn_mask(pud)) >> PAGE_SHIFT;
}
#endif

static inline unsigned long pgd_pfn(pgd_t pgd)
{
	return (pgd_val(pgd) & PTE_PFN_MASK) >> PAGE_SHIFT;
}

#define pte_page(pte)	pfn_to_page(pte_pfn(pte))

static inline int pmd_large(pmd_t pte)
{
#ifdef CONFIG_HCC_GMM
	return (pmd_flags(pte) & (_PAGE_PSE | _PAGE_PRESENT)) ==
		(_PAGE_PSE | _PAGE_PRESENT);
#else
	return pmd_flags(pte) & _PAGE_PSE;
#endif
}

static inline pte_t pte_set_flags(pte_t pte, pteval_t set)
{
	pteval_t v = native_pte_val(pte);

	return native_make_pte(v | set);
}

static inline pte_t pte_clear_flags(pte_t pte, pteval_t clear)
{
	pteval_t v = native_pte_val(pte);

	return native_make_pte(v & ~clear);
}

static inline pte_t pte_mkclean(pte_t pte)
{
	return pte_clear_flags(pte, (_PAGE_DIRTY | _PAGE_SOFTDIRTY));
}

static inline pte_t pte_mkold(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_ACCESSED);
}

static inline pte_t pte_wrprotect(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_RW);
}

static inline pte_t pte_mkexec(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_NX);
}

static inline pte_t pte_mkdirty(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_DIRTY);
}

static inline pte_t pte_mkyoung(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_ACCESSED);
}

static inline pte_t pte_mkwrite(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_RW);
}

static inline pte_t pte_mkhuge(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_PSE);
}

static inline pte_t pte_clrhuge(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_PSE);
}

static inline pte_t pte_mkglobal(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_GLOBAL);
}

static inline pte_t pte_clrglobal(pte_t pte)
{
	return pte_clear_flags(pte, _PAGE_GLOBAL);
}

static inline pte_t pte_mkspecial(pte_t pte)
{
	return pte_set_flags(pte, _PAGE_SPECIAL);
}

/*
 * Mask out unsupported bits in a present pgprot.  Non-present pgprots
 * can use those bits for other purposes, so leave them be.
 */
static inline pgprotval_t massage_pgprot(pgprot_t pgprot)
{
	pgprotval_t protval = pgprot_val(pgprot);

	if (protval & _PAGE_PRESENT)
		protval &= __supported_pte_mask;

	return protval;
}

static inline pte_t pfn_pte(unsigned long page_nr, pgprot_t pgprot)
{
	phys_addr_t pfn = (phys_addr_t)page_nr << PAGE_SHIFT;
	pfn ^= protnone_mask(pgprot_val(pgprot));
#ifndef CONFIG_HCC_GMM
	pfn &= PTE_PFN_MASK;
#endif
	return __pte(pfn | massage_pgprot(pgprot));
}

static inline pmd_t pfn_pmd(unsigned long page_nr, pgprot_t pgprot)
{
	phys_addr_t pfn = (phys_addr_t)page_nr << PAGE_SHIFT;
	pfn ^= protnone_mask(pgprot_val(pgprot));
#ifndef CONFIG_HCC_GMM
	pfn &= PHYSICAL_PMD_PAGE_MASK;
#endif
	return __pmd(pfn | massage_pgprot(pgprot));
}

static inline u64 flip_protnone_guard(u64 oldval, u64 val, u64 mask);

static inline pte_t pte_modify(pte_t pte, pgprot_t newprot)
{
	pteval_t val = pte_val(pte), oldval = val;

	/*
	 * Chop off the NX bit (if present), and add the NX portion of
	 * the newprot (if present):
	 */
	val &= _PAGE_CHG_MASK;
	val |= massage_pgprot(newprot) & ~_PAGE_CHG_MASK;

	val = flip_protnone_guard(oldval, val, PTE_PFN_MASK);
	return __pte(val);
}

static inline pmd_t pmd_modify(pmd_t pmd, pgprot_t newprot)
{
	pmdval_t val = pmd_val(pmd), oldval = val;

	val &= _HPAGE_CHG_MASK;
	val |= massage_pgprot(newprot) & ~_HPAGE_CHG_MASK;

	val = flip_protnone_guard(oldval, val, PHYSICAL_PMD_PAGE_MASK);
	return __pmd(val);
}

/* mprotect needs to preserve PAT bits when updating vm_page_prot */
#define pgprot_modify pgprot_modify
static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
{
	pgprotval_t preservebits = pgprot_val(oldprot) & _PAGE_CHG_MASK;
	pgprotval_t addbits = pgprot_val(newprot);
	return __pgprot(preservebits | addbits);
}

#define pte_pgprot(x) __pgprot(pte_flags(x) & PTE_FLAGS_MASK)

#define canon_pgprot(p) __pgprot(massage_pgprot(p))

static inline int is_new_memtype_allowed(u64 paddr, unsigned long size,
					 unsigned long flags,
					 unsigned long new_flags)
{
	/*
	 * PAT type is always WB for untracked ranges, so no need to check.
	 */
	if (x86_platform.is_untracked_pat_range(paddr, paddr + size))
		return 1;

	/*
	 * Certain new memtypes are not allowed with certain
	 * requested memtype:
	 * - request is uncached, return cannot be write-back
	 * - request is write-combine, return cannot be write-back
	 */
	if ((flags == _PAGE_CACHE_UC_MINUS &&
	     new_flags == _PAGE_CACHE_WB) ||
	    (flags == _PAGE_CACHE_WC &&
	     new_flags == _PAGE_CACHE_WB)) {
		return 0;
	}

	return 1;
}

pmd_t *populate_extra_pmd(unsigned long vaddr);
pte_t *populate_extra_pte(unsigned long vaddr);

#ifdef CONFIG_PAGE_TABLE_ISOLATION
/*
 * All top-level KAISER page tables are order-1 pages (8k-aligned
 * and 8k in size).  The kernel one is at the beginning 4k and
 * the user (shadow) one is in the last 4k.  To switch between
 * them, you just need to flip the 12th bit in their addresses.
 */
#define KAISER_PGTABLE_SWITCH_BIT	PAGE_SHIFT

/*
 * This generates better code than the inline assembly in
 * __set_bit().
 */
static inline void *ptr_set_bit(void *ptr, int bit)
{
	unsigned long __ptr = (unsigned long)ptr;

	__ptr |= (1<<bit);
	return (void *)__ptr;
}
static inline void *ptr_clear_bit(void *ptr, int bit)
{
	unsigned long __ptr = (unsigned long)ptr;

	__ptr &= ~(1<<bit);
	return (void *)__ptr;
}

static inline pgd_t *kernel_to_shadow_pgdp(pgd_t *pgdp)
{
	return ptr_set_bit(pgdp, KAISER_PGTABLE_SWITCH_BIT);
}
static inline pgd_t *shadow_to_kernel_pgdp(pgd_t *pgdp)
{
	return ptr_clear_bit(pgdp, KAISER_PGTABLE_SWITCH_BIT);
}

pgd_t __pti_set_user_pgd(pgd_t *pgdp, pgd_t pgd);

/*
 * Take a PGD location (pgdp) and a pgd value that needs
 * to be set there.  Populates the shadow and returns
 * the resulting PGD that must be set in the kernel copy
 * of the page tables.
 */
static inline pgd_t pti_set_user_pgd(pgd_t *pgdp, pgd_t pgd)
{
	if (!boot_cpu_has(X86_FEATURE_PTI_SUPPORT))
		return pgd;
	return __pti_set_user_pgd(pgdp, pgd);
}
#else
static inline pgd_t pti_set_user_pgd(pgd_t *pgdp, pgd_t pgd)
{
	return pgd;
}
#endif /* CONFIG_PAGE_TABLE_ISOLATION */
#endif	/* __ASSEMBLY__ */

#ifndef __ASSEMBLY__
#include <linux/mm_types.h>

#ifdef CONFIG_X86_32
# include "pgtable_32.h"
#else
# include "pgtable_64.h"
#endif

/*
 * Page table pages are page-aligned.  The lower half of the top
 * level is used for userspace and the top half for the kernel.
 *
 * Returns true for parts of the PGD that map userspace and
 * false for the parts that map the kernel.
 */
static inline bool pgdp_maps_userspace(void *__ptr)
{
	unsigned long ptr = (unsigned long)__ptr;

	return (((ptr & ~PAGE_MASK) / sizeof(pgd_t)) < PGD_KERNEL_START);
}

/*
 * Does this PGD allow access from userspace?
 */
static inline bool pgd_userspace_access(pgd_t pgd)
{
	return pgd.pgd & _PAGE_USER;
}

static inline int pte_none(pte_t pte)
{
	return !pte.pte;
}

#define __HAVE_ARCH_PTE_SAME
static inline int pte_same(pte_t a, pte_t b)
{
	return a.pte == b.pte;
}

static inline int pte_present(pte_t a)
{
	return pte_flags(a) & (_PAGE_PRESENT | _PAGE_PROTNONE);
}

static inline int pte_hidden(pte_t pte)
{
	return pte_flags(pte) & _PAGE_HIDDEN;
}

static inline int pmd_present(pmd_t pmd)
{
#ifdef CONFIG_HCC_GMM
	return pmd_flags(pmd) & _PAGE_PRESENT;
#else
	/*
	 * Checking for _PAGE_PSE is needed too because
	 * split_huge_page will temporarily clear the present bit (but
	 * the _PAGE_PSE flag will remain set at all times while the
	 * _PAGE_PRESENT bit is clear).
	 */
	return pmd_flags(pmd) & (_PAGE_PRESENT | _PAGE_PROTNONE | _PAGE_PSE);
#endif
}

static inline int pmd_none(pmd_t pmd)
{
	/* Only check low word on 32-bit platforms, since it might be
	   out of sync with upper half. */
	return (unsigned long)native_pmd_val(pmd) == 0;
}

#ifdef CONFIG_HCC_GMM
static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & PTE_PFN_MASK);
}
#else
static inline unsigned long pmd_page_vaddr(pmd_t pmd)
{
	return (unsigned long)__va(pmd_val(pmd) & pmd_pfn_mask(pmd));
}
#endif

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pmd_page(pmd)	pfn_to_page(pmd_pfn(pmd))

/*
 * the pmd page can be thought of an array like this: pmd_t[PTRS_PER_PMD]
 *
 * this macro returns the index of the entry in the pmd page which would
 * control the given virtual address
 */
static inline unsigned long pmd_index(unsigned long address)
{
	return (address >> PMD_SHIFT) & (PTRS_PER_PMD - 1);
}

/*
 * Conversion functions: convert a page and protection to a page entry,
 * and a page entry and page directory to the page they refer to.
 *
 * (Currently stuck as a macro because of indirect forward reference
 * to linux/mm.h:page_to_nid())
 */
#define mk_pte(page, pgprot)   pfn_pte(page_to_pfn(page), (pgprot))

/*
 * the pte page can be thought of an array like this: pte_t[PTRS_PER_PTE]
 *
 * this function returns the index of the entry in the pte page which would
 * control the given virtual address
 */
static inline unsigned long pte_index(unsigned long address)
{
	return (address >> PAGE_SHIFT) & (PTRS_PER_PTE - 1);
}

static inline pte_t *pte_offset_kernel(pmd_t *pmd, unsigned long address)
{
	return (pte_t *)pmd_page_vaddr(*pmd) + pte_index(address);
}

static inline int pmd_bad(pmd_t pmd)
{
	return (pmd_flags(pmd) & ~_PAGE_USER) != _KERNPG_TABLE;
}

static inline unsigned long pages_to_mb(unsigned long npg)
{
	return npg >> (20 - PAGE_SHIFT);
}

#define io_remap_pfn_range(vma, vaddr, pfn, size, prot)	\
	remap_pfn_range(vma, vaddr, pfn, size, prot)

#if PAGETABLE_LEVELS > 2
static inline int pud_none(pud_t pud)
{
	return native_pud_val(pud) == 0;
}

static inline int pud_present(pud_t pud)
{
	return pud_flags(pud) & _PAGE_PRESENT;
}

#ifdef CONFIG_HCC_GMM
static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va(pud_val(pud) & PTE_PFN_MASK);
}
#else
static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return (unsigned long)__va(pud_val(pud) & pud_pfn_mask(pud));
}
#endif

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pud_page(pud)	pfn_to_page(pud_pfn(pud))

/* Find an entry in the second-level page table.. */
static inline pmd_t *pmd_offset(pud_t *pud, unsigned long address)
{
	return (pmd_t *)pud_page_vaddr(*pud) + pmd_index(address);
}

static inline int pud_large(pud_t pud)
{
	return (pud_val(pud) & (_PAGE_PSE | _PAGE_PRESENT)) ==
		(_PAGE_PSE | _PAGE_PRESENT);
}

static inline int pud_bad(pud_t pud)
{
	return (pud_flags(pud) & ~(_KERNPG_TABLE | _PAGE_USER)) != 0;
}
#else
static inline int pud_large(pud_t pud)
{
	return 0;
}
#endif	/* PAGETABLE_LEVELS > 2 */

#if PAGETABLE_LEVELS > 3
static inline int pgd_present(pgd_t pgd)
{
	return pgd_flags(pgd) & _PAGE_PRESENT;
}

static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return (unsigned long)__va((unsigned long)pgd_val(pgd) & PTE_PFN_MASK);
}

/*
 * Currently stuck as a macro due to indirect forward reference to
 * linux/mmzone.h's __section_mem_map_addr() definition:
 */
#define pgd_page(pgd)	pfn_to_page(pgd_pfn(pgd))

/* to find an entry in a page-table-directory. */
static inline unsigned long pud_index(unsigned long address)
{
	return (address >> PUD_SHIFT) & (PTRS_PER_PUD - 1);
}

static inline pud_t *pud_offset(pgd_t *pgd, unsigned long address)
{
	return (pud_t *)pgd_page_vaddr(*pgd) + pud_index(address);
}

static inline int pgd_bad(pgd_t pgd)
{
	unsigned long ignore_flags = _PAGE_USER;

	if (IS_ENABLED(CONFIG_PAGE_TABLE_ISOLATION))
		ignore_flags |= _PAGE_NX;

	return (pgd_flags(pgd) & ~ignore_flags) != _KERNPG_TABLE;
}

static inline int pgd_none(pgd_t pgd)
{
	return !native_pgd_val(pgd);
}
#endif	/* PAGETABLE_LEVELS > 3 */

#endif	/* __ASSEMBLY__ */

/*
 * the pgd page can be thought of an array like this: pgd_t[PTRS_PER_PGD]
 *
 * this macro returns the index of the entry in the pgd page which would
 * control the given virtual address
 */
#define pgd_index(address) (((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))

/*
 * pgd_offset() returns a (pgd_t *)
 * pgd_index() is used get the offset into the pgd page's array of pgd_t's;
 */
#define pgd_offset(mm, address) ((mm)->pgd + pgd_index((address)))
/*
 * a shortcut which implies the use of the kernel's pgd, instead
 * of a process's
 */
#define pgd_offset_k(address) pgd_offset(&init_mm, (address))



#define KERNEL_PGD_BOUNDARY	pgd_index(PAGE_OFFSET)
#define KERNEL_PGD_PTRS		(PTRS_PER_PGD - KERNEL_PGD_BOUNDARY)

#ifndef __ASSEMBLY__

extern int direct_gbpages;
extern pgprotval_t kernel_page_global __read_mostly;

/* local pte updates need not use xchg for locking */
static inline pte_t native_local_ptep_get_and_clear(pte_t *ptep)
{
	pte_t res = *ptep;

	/* Pure native function needs no input for mm, addr */
	native_pte_clear(NULL, 0, ptep);
	return res;
}

static inline void native_set_pte_at(struct mm_struct *mm, unsigned long addr,
				     pte_t *ptep , pte_t pte)
{
	native_set_pte(ptep, pte);
}

static inline void native_set_pmd_at(struct mm_struct *mm, unsigned long addr,
				     pmd_t *pmdp , pmd_t pmd)
{
	native_set_pmd(pmdp, pmd);
}

#ifndef CONFIG_PARAVIRT
/*
 * Rules for using pte_update - it must be called after any PTE update which
 * has not been done using the set_pte / clear_pte interfaces.  It is used by
 * shadow mode hypervisors to resynchronize the shadow page tables.  Kernel PTE
 * updates should either be sets, clears, or set_pte_atomic for P->P
 * transitions, which means this hook should only be called for user PTEs.
 * This hook implies a P->P protection or access change has taken place, which
 * requires a subsequent TLB flush.  The notification can optionally be delayed
 * until the TLB flush event by using the pte_update_defer form of the
 * interface, but care must be taken to assure that the flush happens while
 * still holding the same page table lock so that the shadow and primary pages
 * do not become out of sync on SMP.
 */
#define pte_update(mm, addr, ptep)		do { } while (0)
#define pte_update_defer(mm, addr, ptep)	do { } while (0)
#endif

/*
 * We only update the dirty/accessed state if we set
 * the dirty bit by hand in the kernel, since the hardware
 * will do the accessed bit for us, and we don't want to
 * race with other CPU's that might be updating the dirty
 * bit at the same time.
 */
struct vm_area_struct;

#define  __HAVE_ARCH_PTEP_SET_ACCESS_FLAGS
extern int ptep_set_access_flags(struct vm_area_struct *vma,
				 unsigned long address, pte_t *ptep,
				 pte_t entry, int dirty);

#define __HAVE_ARCH_PTEP_TEST_AND_CLEAR_YOUNG
extern int ptep_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pte_t *ptep);

#define __HAVE_ARCH_PTEP_CLEAR_YOUNG_FLUSH
extern int ptep_clear_flush_young(struct vm_area_struct *vma,
				  unsigned long address, pte_t *ptep);

#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
static inline pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
				       pte_t *ptep)
{
	pte_t pte = native_ptep_get_and_clear(ptep);
	pte_update(mm, addr, ptep);
	return pte;
}

#define __HAVE_ARCH_PTEP_GET_AND_CLEAR_FULL
static inline pte_t ptep_get_and_clear_full(struct mm_struct *mm,
					    unsigned long addr, pte_t *ptep,
					    int full)
{
	pte_t pte;
	if (full) {
		/*
		 * Full address destruction in progress; paravirt does not
		 * care about updates and native needs no locking
		 */
		pte = native_local_ptep_get_and_clear(ptep);
	} else {
		pte = ptep_get_and_clear(mm, addr, ptep);
	}
	return pte;
}

#define __HAVE_ARCH_PTEP_SET_WRPROTECT
static inline void ptep_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pte_t *ptep)
{
	clear_bit(_PAGE_BIT_RW, (unsigned long *)&ptep->pte);
	pte_update(mm, addr, ptep);
}

static inline void __clone_pgd_range(pgd_t *dst, pgd_t *src, int count)
{
       memcpy(dst, src, count * sizeof(pgd_t));
}

/*
 * clone_pgd_range(pgd_t *dst, pgd_t *src, int count);
 *
 *  dst - pointer to pgd range anwhere on a pgd page
 *  src - ""
 *  count - the number of pgds to copy.
 *
 * dst and src can be on the same page, but the range must not overlap,
 * and must not cross a page boundary.
 */
static inline void clone_pgd_range(pgd_t *dst, pgd_t *src, int count)
{
	__clone_pgd_range(dst, src, count);
#ifdef CONFIG_PAGE_TABLE_ISOLATION
	/* Clone the shadow pgd part as well */
	if (!static_cpu_has(X86_FEATURE_PTI_SUPPORT))
		return;
	__clone_pgd_range(kernel_to_shadow_pgdp(dst),
			  kernel_to_shadow_pgdp(src), count);
#endif
}

#ifdef CONFIG_HCC_GMM
struct gdm_obj;
static inline void set_pte_obj_entry(pte_t *ptep, struct gdm_obj *obj)
{
	pte_t pte = __pte((unsigned long)obj);
	pte = pte_set_flags(pte, _PAGE_OBJ_ENTRY);
	set_pte(ptep, pte);
}

static inline void set_swap_pte_obj_entry(pte_t *ptep, struct gdm_obj *obj)
{
	pte_t pte = __pte((unsigned long)obj);
	pte = pte_set_flags(pte, _PAGE_OBJ_ENTRY | _PAGE_FILE);
	set_pte(ptep, pte);
}

static inline struct gdm_obj *get_pte_obj_entry(pte_t *ptep)
{
	return (struct gdm_obj *)(pte_val(*ptep) & (~(_PAGE_OBJ_ENTRY |
						       _PAGE_FILE)));
}

static inline int pte_obj_entry(pte_t *ptep)
{
	return ((pte_val(*ptep) & _PAGE_OBJ_ENTRY) && (!pte_present(*ptep)));
}

static inline int swap_pte_obj_entry(pte_t *ptep)
{
	return ((pte_val(*ptep) & _PAGE_OBJ_ENTRY) &&
		(pte_val(*ptep) & _PAGE_FILE) &&
		(!pte_present(*ptep)));
}

#endif /* HCC_GMM */

#define __HAVE_ARCH_PFN_MODIFY_ALLOWED 1
extern bool pfn_modify_allowed(unsigned long pfn, pgprot_t prot);

static inline bool arch_has_pfn_modify_check(void)
{
#ifdef CONFIG_HCC_GPM
	return false;
#else
	return boot_cpu_has_bug(X86_BUG_L1TF);
#endif
}

#include <asm-generic/pgtable.h>
#endif	/* __ASSEMBLY__ */

#endif /* _ASM_X86_PGTABLE_H */
