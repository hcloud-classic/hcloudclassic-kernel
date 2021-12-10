#include <linux/initrd.h>
#include <linux/ioport.h>
#include <linux/swap.h>

#include <asm/cacheflush.h>
#include <asm/e820.h>
#include <asm/init.h>
#include <asm/page.h>
#include <asm/page_types.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/system.h>
#include <asm/tlbflush.h>
#include <asm/tlb.h>
#include <asm/proto.h>
#include <asm/cpufeature.h>
#include <asm/mmu_context.h>

DEFINE_PER_CPU(struct mmu_gather, mmu_gathers);

unsigned long __initdata e820_table_start;
unsigned long __meminitdata e820_table_end;
unsigned long __meminitdata e820_table_top;

int after_bootmem;

int direct_gbpages
#ifdef CONFIG_DIRECT_GBPAGES
				= 1
#endif
;

struct map_range {
	unsigned long start;
	unsigned long end;
	unsigned page_size_mask;
};

/*
 * First calculate space needed for kernel direct mapping page tables to cover
 * mr[0].start to mr[nr_range - 1].end, while accounting for possible 2M and 1GB
 * pages. Then find enough contiguous space for those page tables.
 */
static void __init find_early_table_space(struct map_range *mr, int nr_range)
{
	int i;
	unsigned long puds = 0, pmds = 0, ptes = 0, tables;
	unsigned long start = 0;

	for (i = 0; i < nr_range; i++) {
		unsigned long range, extra;

		range = mr[i].end - mr[i].start;
		puds += (range + PUD_SIZE - 1) >> PUD_SHIFT;

		if (mr[i].page_size_mask & (1 << PG_LEVEL_1G)) {
			extra = range - ((range >> PUD_SHIFT) << PUD_SHIFT);
			pmds += (extra + PMD_SIZE - 1) >> PMD_SHIFT;
		} else {
			pmds += (range + PMD_SIZE - 1) >> PMD_SHIFT;
		}

		if (mr[i].page_size_mask & (1 << PG_LEVEL_2M)) {
			extra = range - ((range >> PMD_SHIFT) << PMD_SHIFT);
#ifdef CONFIG_X86_32
			extra += PMD_SIZE;
#endif
			ptes += (extra + PAGE_SIZE - 1) >> PAGE_SHIFT;
		} else {
			ptes += (range + PAGE_SIZE - 1) >> PAGE_SHIFT;
		}
	}
 
	tables = roundup(puds * sizeof(pud_t), PAGE_SIZE);
	tables += roundup(pmds * sizeof(pmd_t), PAGE_SIZE);
	tables += roundup(ptes * sizeof(pte_t), PAGE_SIZE);

#ifdef CONFIG_X86_32
	/* for fixmap */
	tables += roundup(__end_of_fixed_addresses * sizeof(pte_t), PAGE_SIZE);
#endif

	/*
	 * RED-PEN putting page tables only on node 0 could
	 * cause a hotspot and fill up ZONE_DMA. The page tables
	 * need roughly 0.5KB per GB.
	 */
#ifdef CONFIG_X86_32
	start = 0x7000;
#else
	start = 0x8000;
#endif
	e820_table_start = find_e820_area(start, max_pfn_mapped<<PAGE_SHIFT,
					tables, PAGE_SIZE);
	if (e820_table_start == -1UL)
		panic("Cannot find space for the kernel page tables");

	e820_table_start >>= PAGE_SHIFT;
	e820_table_end = e820_table_start;
	e820_table_top = e820_table_start + (tables >> PAGE_SHIFT);

	printk(KERN_DEBUG "kernel direct mapping tables up to %lx @ %lx-%lx\n",
		mr[nr_range - 1].end, e820_table_start << PAGE_SHIFT,
		e820_table_top << PAGE_SHIFT);
}

static void setup_pcid(void)
{
#ifdef CONFIG_X86_64
	if (boot_cpu_has(X86_FEATURE_PCID)) {
		if (boot_cpu_has(X86_FEATURE_PGE)) {
			/*
			 * This can't be cr4_set_bits_and_update_boot() --
			 * the trampoline code can't handle CR4.PCIDE and
			 * it wouldn't do any good anyway.  Despite the name,
			 * cr4_set_bits_and_update_boot() doesn't actually
			 * cause the bits in question to remain set all the
			 * way through the secondary boot asm.
			 *
			 * Instead, we brute-force it and set CR4.PCIDE
			 * manually in start_secondary().
			 */
			set_in_cr4(X86_CR4_PCIDE);
			/*
			 * INVPCID's single-context modes (2/3) only work
			 * if we set X86_CR4_PCIDE, *and* we INVPCID
			 * support.  It's unusable on systems that have
			 * X86_CR4_PCIDE clear, or that have no INVPCID
			 * support at all.
			 */
			if (boot_cpu_has(X86_FEATURE_INVPCID))
				setup_force_cpu_cap(X86_FEATURE_INVPCID_SINGLE);
		} else {
			/*
			 * flush_tlb_all(), as currently implemented, won't
			 * work if PCID is on but PGE is not.  Since that
			 * combination doesn't exist on real hardware, there's
			 * no reason to try to fully support it, but it's
			 * polite to avoid corrupting data if we're on
			 * an improperly configured VM.
			 */
			setup_clear_cpu_cap(X86_FEATURE_PCID);
		}
	}
#endif
}

#ifdef CONFIG_X86_32
#define NR_RANGE_MR 3
#else /* CONFIG_X86_64 */
#define NR_RANGE_MR 5
#endif

static int __meminit save_mr(struct map_range *mr, int nr_range,
			     unsigned long start_pfn, unsigned long end_pfn,
			     unsigned long page_size_mask)
{
	if (start_pfn < end_pfn) {
		if (nr_range >= NR_RANGE_MR)
			panic("run out of range for init_memory_mapping\n");
		mr[nr_range].start = start_pfn<<PAGE_SHIFT;
		mr[nr_range].end   = end_pfn<<PAGE_SHIFT;
		mr[nr_range].page_size_mask = page_size_mask;
		nr_range++;
	}

	return nr_range;
}

/*
 * Setup the direct mapping of the physical memory at PAGE_OFFSET.
 * This runs before bootmem is initialized and gets pages directly from
 * the physical memory. To access them they are temporarily mapped.
 */
unsigned long __init_refok init_memory_mapping(unsigned long start,
					       unsigned long end)
{
	unsigned long page_size_mask = 0;
	unsigned long start_pfn, end_pfn;
	unsigned long ret = 0;
	unsigned long pos;

	struct map_range mr[NR_RANGE_MR];
	int nr_range, i;
	int use_pse, use_gbpages;

	printk(KERN_INFO "init_memory_mapping: %016lx-%016lx\n", start, end);
	setup_pcid();

#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KMEMCHECK)
	/*
	 * For CONFIG_DEBUG_PAGEALLOC, identity mapping will use small pages.
	 * This will simplify cpa(), which otherwise needs to support splitting
	 * large pages into small in interrupt context, etc.
	 */
	use_pse = use_gbpages = 0;
#else
	use_pse = cpu_has_pse;
	use_gbpages = direct_gbpages;
#endif

	set_nx();
	if (nx_enabled)
		printk(KERN_INFO "NX (Execute Disable) protection: active\n");
#ifdef CONFIG_X86_32
	else
	if (exec_shield)
		printk(KERN_INFO "Using x86 segment limits to approximate "
			"NX protection\n");
#endif

	/* Enable PSE if available */
	if (cpu_has_pse)
		set_in_cr4(X86_CR4_PSE);

	/* Enable PGE if available */
	if (cpu_has_pge) {
		set_in_cr4(X86_CR4_PGE);
		__supported_pte_mask |= _PAGE_GLOBAL;
	}

	if (use_gbpages)
		page_size_mask |= 1 << PG_LEVEL_1G;
	if (use_pse)
		page_size_mask |= 1 << PG_LEVEL_2M;

	memset(mr, 0, sizeof(mr));
	nr_range = 0;

	/* head if not big page alignment ? */
	start_pfn = start >> PAGE_SHIFT;
	pos = start_pfn << PAGE_SHIFT;
#ifdef CONFIG_X86_32
	/*
	 * Don't use a large page for the first 2/4MB of memory
	 * because there are often fixed size MTRRs in there
	 * and overlapping MTRRs into large pages can cause
	 * slowdowns.
	 */
	if (pos == 0)
		end_pfn = 1<<(PMD_SHIFT - PAGE_SHIFT);
	else
		end_pfn = ((pos + (PMD_SIZE - 1))>>PMD_SHIFT)
				 << (PMD_SHIFT - PAGE_SHIFT);
#else /* CONFIG_X86_64 */
	end_pfn = ((pos + (PMD_SIZE - 1)) >> PMD_SHIFT)
			<< (PMD_SHIFT - PAGE_SHIFT);
#endif
	if (end_pfn > (end >> PAGE_SHIFT))
		end_pfn = end >> PAGE_SHIFT;
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);
		pos = end_pfn << PAGE_SHIFT;
	}

	/* big page (2M) range */
	start_pfn = ((pos + (PMD_SIZE - 1))>>PMD_SHIFT)
			 << (PMD_SHIFT - PAGE_SHIFT);
#ifdef CONFIG_X86_32
	end_pfn = (end>>PMD_SHIFT) << (PMD_SHIFT - PAGE_SHIFT);
#else /* CONFIG_X86_64 */
	end_pfn = ((pos + (PUD_SIZE - 1))>>PUD_SHIFT)
			 << (PUD_SHIFT - PAGE_SHIFT);
	if (end_pfn > ((end>>PMD_SHIFT)<<(PMD_SHIFT - PAGE_SHIFT)))
		end_pfn = ((end>>PMD_SHIFT)<<(PMD_SHIFT - PAGE_SHIFT));
#endif

	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pos = end_pfn << PAGE_SHIFT;
	}

#ifdef CONFIG_X86_64
	/* big page (1G) range */
	start_pfn = ((pos + (PUD_SIZE - 1))>>PUD_SHIFT)
			 << (PUD_SHIFT - PAGE_SHIFT);
	end_pfn = (end >> PUD_SHIFT) << (PUD_SHIFT - PAGE_SHIFT);
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask &
				 ((1<<PG_LEVEL_2M)|(1<<PG_LEVEL_1G)));
		pos = end_pfn << PAGE_SHIFT;
	}

	/* tail is not big page (1G) alignment */
	start_pfn = ((pos + (PMD_SIZE - 1))>>PMD_SHIFT)
			 << (PMD_SHIFT - PAGE_SHIFT);
	end_pfn = (end >> PMD_SHIFT) << (PMD_SHIFT - PAGE_SHIFT);
	if (start_pfn < end_pfn) {
		nr_range = save_mr(mr, nr_range, start_pfn, end_pfn,
				page_size_mask & (1<<PG_LEVEL_2M));
		pos = end_pfn << PAGE_SHIFT;
	}
#endif

	/* tail is not big page (2M) alignment */
	start_pfn = pos>>PAGE_SHIFT;
	end_pfn = end>>PAGE_SHIFT;
	nr_range = save_mr(mr, nr_range, start_pfn, end_pfn, 0);

	/* try to merge same page size and continuous */
	for (i = 0; nr_range > 1 && i < nr_range - 1; i++) {
		unsigned long old_start;
		if (mr[i].end != mr[i+1].start ||
		    mr[i].page_size_mask != mr[i+1].page_size_mask)
			continue;
		/* move it */
		old_start = mr[i].start;
		memmove(&mr[i], &mr[i+1],
			(nr_range - 1 - i) * sizeof(struct map_range));
		mr[i--].start = old_start;
		nr_range--;
	}

	for (i = 0; i < nr_range; i++)
		printk(KERN_DEBUG " %010lx - %010lx page %s\n",
				mr[i].start, mr[i].end,
			(mr[i].page_size_mask & (1<<PG_LEVEL_1G))?"1G":(
			 (mr[i].page_size_mask & (1<<PG_LEVEL_2M))?"2M":"4k"));

	/*
	 * Find space for the kernel direct mapping tables.
	 *
	 * Later we should allocate these tables in the local node of the
	 * memory mapped. Unfortunately this is done currently before the
	 * nodes are discovered.
	 */
	if (!after_bootmem)
		find_early_table_space(mr, nr_range);

#ifdef CONFIG_X86_32
	for (i = 0; i < nr_range; i++)
		kernel_physical_mapping_init(mr[i].start, mr[i].end,
					     mr[i].page_size_mask);
	ret = end;
#else /* CONFIG_X86_64 */
	for (i = 0; i < nr_range; i++)
		ret = kernel_physical_mapping_init(mr[i].start, mr[i].end,
						   mr[i].page_size_mask);
#endif

#ifdef CONFIG_X86_32
	early_ioremap_page_table_range_init();

	load_cr3(swapper_pg_dir);
#endif

#ifdef CONFIG_X86_64
	if (!after_bootmem && !start) {
		pud_t *pud;
		pmd_t *pmd;

		mmu_cr4_features = read_cr4();

		/*
		 * _brk_end cannot change anymore, but it and _end may be
		 * located on different 2M pages. cleanup_highmap(), however,
		 * can only consider _end when it runs, so destroy any
		 * mappings beyond _brk_end here.
		 */
		pud = pud_offset(pgd_offset_k(_brk_end), _brk_end);
		pmd = pmd_offset(pud, _brk_end - 1);
		while (++pmd <= pmd_offset(pud, (unsigned long)_end - 1))
			pmd_clear(pmd);
	}
#endif
	__flush_tlb_all();

	if (!after_bootmem && e820_table_end > e820_table_start)
		reserve_early(e820_table_start << PAGE_SHIFT,
				 e820_table_end << PAGE_SHIFT, "PGTABLE");

	if (!after_bootmem)
		early_memtest(start, end);

	return ret >> PAGE_SHIFT;
}


/*
 * devmem_is_allowed() checks to see if /dev/mem access to a certain address
 * is valid. The argument is a physical page number.
 *
 * On x86, access has to be given to the first megabyte of RAM because that
 * area traditionally contains BIOS code and data regions used by X, dosemu,
 * and similar apps. Since they map the entire memory range, the whole range
 * must be allowed (for mapping), but any areas that would otherwise be
 * disallowed are flagged as being "zero filled" instead of rejected.
 * Access has to be given to non-kernel-ram areas as well, these contain the
 * PCI mmio resources as well as potential bios/acpi data regions.
 */
int devmem_is_allowed(unsigned long pagenr)
{
	if (page_is_ram(pagenr)) {
		/*
		 * For disallowed memory regions in the low 1MB range,
		 * request that the page be shown as all zeros.
		 */
		if (pagenr < 256)
			return 2;

		return 0;
	}

	/*
	 * This must follow RAM test, since System RAM is considered a
	 * restricted resource under CONFIG_STRICT_IOMEM.
	 */
	if (iomem_is_exclusive(pagenr << PAGE_SHIFT)) {
		/* Low 1MB bypasses iomem restrictions. */
		if (pagenr < 256)
			return 1;

		return 0;
	}

	return 1;
}

void free_init_pages(char *what, unsigned long begin, unsigned long end)
{
	unsigned long addr = begin;

	if (addr >= end)
		return;

	/*
	 * If debugging page accesses then do not free this memory but
	 * mark them not present - any buggy init-section access will
	 * create a kernel page fault:
	 */
#ifdef CONFIG_DEBUG_PAGEALLOC
	printk(KERN_INFO "debug: unmapping init memory %08lx..%08lx\n",
		begin, PAGE_ALIGN(end));
	set_memory_np(begin, (end - begin) >> PAGE_SHIFT);
#else
	/*
	 * We just marked the kernel text read only above, now that
	 * we are going to free part of that, we need to make that
	 * writeable first.
	 */
	set_memory_rw(begin, (end - begin) >> PAGE_SHIFT);

	printk(KERN_INFO "Freeing %s: %luk freed\n", what, (end - begin) >> 10);

	for (; addr < end; addr += PAGE_SIZE) {
		ClearPageReserved(virt_to_page(addr));
		init_page_count(virt_to_page(addr));
		memset((void *)(addr & ~(PAGE_SIZE-1)),
			POISON_FREE_INITMEM, PAGE_SIZE);
		free_page(addr);
		totalram_pages++;
	}
#endif
}

void free_initmem(void)
{
	free_init_pages("unused kernel memory",
			(unsigned long)(&__init_begin),
			(unsigned long)(&__init_end));
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{
	free_init_pages("initrd memory", start, end);
}
#endif

unsigned long max_swapfile_size(void)
{
	unsigned long pages;

	pages = generic_max_swapfile_size();

#ifndef CONFIG_HCC_GPM
	if (boot_cpu_has_bug(X86_BUG_L1TF)) {
		/* Limit the swap file size to MAX_PA/2 for L1TF workaround */
		unsigned long long l1tf_limit = l1tf_pfn_limit() + 1;
		/*
		 * We encode swap offsets also with 3 bits below those for pfn
		 * which makes the usable limit higher.
		 */
#ifdef CONFIG_X86_64
		l1tf_limit <<= PAGE_SHIFT - SWP_OFFSET_SHIFT;
#endif
		pages = min_t(unsigned long long, l1tf_limit, pages);
	}
#endif
	return pages;
}
