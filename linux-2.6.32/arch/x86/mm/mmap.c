/*
 * Flexible mmap layout support
 *
 * Based on code by Ingo Molnar and Andi Kleen, copyrighted
 * as follows:
 *
 * Copyright 2003-2009 Red Hat Inc.
 * All Rights Reserved.
 * Copyright 2005 Andi Kleen, SUSE Labs.
 * Copyright 2007 Jiri Kosina, SUSE Labs.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/personality.h>
#include <linux/mm.h>
#include <linux/random.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <asm/elf.h>

struct __read_mostly va_alignment va_align = {
	.flags = -1,
};

static unsigned long stack_maxrandom_size(void)
{
	unsigned long max = 0;
	if ((current->flags & PF_RANDOMIZE) &&
		!(current->personality & ADDR_NO_RANDOMIZE)) {
		max = ((-1UL) & STACK_RND_MASK) << PAGE_SHIFT;
	}

	return max;
}


/*
 * Top of mmap area (just below the process stack).
 *
 * Leave an at least ~128 MB hole with possible stack randomization.
 */
#define MIN_GAP (128*1024*1024UL + stack_maxrandom_size())
#define MAX_GAP (TASK_SIZE/6*5)

static int mmap_is_legacy(void)
{
	if (current->personality & ADDR_COMPAT_LAYOUT)
		return 1;

	if (current->signal->rlim[RLIMIT_STACK].rlim_cur == RLIM_INFINITY)
		return 1;

	return sysctl_legacy_va_layout;
}

unsigned long arch_mmap_rnd(void)
{
	unsigned long rnd;

	/*
	 *  8 bits of randomness in 32bit mmaps, 20 address space bits
	 * 28 bits of randomness in 64bit mmaps, 40 address space bits
	 */
	if (mmap_is_ia32())
		rnd = (unsigned long)get_random_int() % (1<<8);
	else
		rnd = (unsigned long)get_random_int() % (1<<28);

	return rnd << PAGE_SHIFT;
}

static unsigned long mmap_base(unsigned long rnd)
{
	unsigned long gap = current->signal->rlim[RLIMIT_STACK].rlim_cur;

	if (gap < MIN_GAP)
		gap = MIN_GAP;
	else if (gap > MAX_GAP)
		gap = MAX_GAP;

	return PAGE_ALIGN(TASK_SIZE - gap - rnd);
}

#define SHLIB_BASE             0x00110000

/*
 * Bottom-up (legacy) layout on X86_32 did not support randomization, X86_64
 * does, but not when emulating X86_32
 */
static unsigned long mmap_legacy_base(unsigned long rnd)
{
	if (mmap_is_ia32())
		return TASK_UNMAPPED_BASE;
	else
		return TASK_UNMAPPED_BASE + rnd;
}

/*
 * This function, called very early during the creation of a new
 * process VM image, sets up which VM layout function to use:
 */
void arch_pick_mmap_layout(struct mm_struct *mm)
{
	unsigned long random_factor = 0UL;

	mm->get_unmapped_exec_area = NULL;

	if (current->flags & PF_RANDOMIZE)
		random_factor = arch_mmap_rnd();

	if (!(2 & exec_shield) && mmap_is_legacy()) {
		mm->mmap_base = mmap_legacy_base(random_factor);
		mm->get_unmapped_area = arch_get_unmapped_area;
		mm->unmap_area = arch_unmap_area;
	} else {
		mm->mmap_base = mmap_base(random_factor);
		mm->get_unmapped_area = arch_get_unmapped_area_topdown;
		if (!(current->personality & READ_IMPLIES_EXEC)
		    && mmap_is_ia32()) {
			mm->get_unmapped_exec_area = arch_get_unmapped_exec_area;
			mm->shlib_base = SHLIB_BASE + arch_mmap_rnd();
		}
		mm->unmap_area = arch_unmap_area_topdown;
	}
}

/*
 * Only allow root to set high MMIO mappings to PROT_NONE.
 * This prevents an unpriv. user to set them to PROT_NONE and invert
 * them, then pointing to valid memory for L1TF speculation.
 *
 * Note: for locked down kernels may want to disable the root override.
 */
bool pfn_modify_allowed(unsigned long pfn, pgprot_t prot)
{
#ifdef CONFIG_HCC_GPM
	return true;
#else
	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return true;
	if (!__pte_needs_invert(pgprot_val(prot)))
		return true;
	/* If it's real memory always allow */
	if (pfn_valid(pfn))
		return true;
	if (pfn > l1tf_pfn_limit() && !capable(CAP_SYS_ADMIN))
		return false;
	return true;
#endif
}
