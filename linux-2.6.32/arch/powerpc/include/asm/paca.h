/*
 * This control block defines the PACA which defines the processor
 * specific data for each logical processor on the system.
 * There are some pointers defined that are utilized by PLIC.
 *
 * C 2001 PPC 64 Team, IBM Corp
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */
#ifndef _ASM_POWERPC_PACA_H
#define _ASM_POWERPC_PACA_H
#ifdef __KERNEL__

#include <asm/types.h>
#include <asm/lppaca.h>
#include <asm/mmu.h>
#include <asm/page.h>
#include <asm/exception-64e.h>

register struct paca_struct *local_paca asm("r13");

#if defined(CONFIG_DEBUG_PREEMPT) && defined(CONFIG_SMP)
extern unsigned int debug_smp_processor_id(void); /* from linux/smp.h */
/*
 * Add standard checks that preemption cannot occur when using get_paca():
 * otherwise the paca_struct it points to may be the wrong one just after.
 */
#define get_paca()	((void) debug_smp_processor_id(), local_paca)
#else
#define get_paca()	local_paca
#endif

#define get_lppaca()	(get_paca()->lppaca_ptr)
#define get_slb_shadow()	(get_paca()->slb_shadow_ptr)

struct task_struct;

/*
 * This is pointed to by paca->aux_ptr, for the purpose of extending the
 * paca structure without kABI breakage.
 */
#ifdef CONFIG_PPC_BOOK3S_64
struct paca_aux_struct {
	/*
	 * rfi fallback flush must be in its own cacheline to prevent
	 * other paca data leaking into the L1d
	 */
	u64 exrfi[13] __aligned(0x80);
	void *rfi_flush_fallback_area;
	u64 l1d_flush_size;
};
#endif

/*
 * Defines the layout of the paca.
 *
 * This structure is not directly accessed by firmware or the service
 * processor.
 */
struct paca_struct {
#ifdef CONFIG_PPC_BOOK3S
	/*
	 * Because hw_cpu_id, unlike other paca fields, is accessed
	 * routinely from other CPUs (from the IRQ code), we stick to
	 * read-only (after boot) fields in the first cacheline to
	 * avoid cacheline bouncing.
	 */

	struct lppaca *lppaca_ptr;	/* Pointer to LpPaca for PLIC */
#endif /* CONFIG_PPC_BOOK3S */
	/*
	 * MAGIC: the spinlock functions in arch/powerpc/lib/locks.c 
	 * load lock_token and paca_index with a single lwz
	 * instruction.  They must travel together and be properly
	 * aligned.
	 */
	u16 lock_token;			/* Constant 0x8000, used in locks */
	u16 paca_index;			/* Logical processor number */

	u64 kernel_toc;			/* Kernel TOC address */
	u64 kernelbase;			/* Base address of kernel */
	u64 kernel_msr;			/* MSR while running in kernel */
#ifdef CONFIG_PPC_STD_MMU_64
	u64 stab_real;			/* Absolute address of segment table */
	u64 stab_addr;			/* Virtual address of segment table */
#endif /* CONFIG_PPC_STD_MMU_64 */
	void *emergency_sp;		/* pointer to emergency stack */
	u64 data_offset;		/* per cpu data offset */
	s16 hw_cpu_id;			/* Physical processor number */
	u8 cpu_start;			/* At startup, processor spins until */
					/* this becomes non-zero. */
#ifdef CONFIG_PPC_STD_MMU_64
	struct slb_shadow *slb_shadow_ptr;
	struct dtl_entry *dispatch_log;
	struct dtl_entry *dispatch_log_end;

	/*
	 * Because of alignement of exgen there is a hole here, we use that hole
	 * for the aux_ptr and so don't change the size of the paca or the
	 * location of any members.
	 */
#ifdef CONFIG_PPC_BOOK3S_64
#ifndef __GENKSYMS__
	struct paca_aux_struct *aux_ptr;
#endif
#endif
	/*
	 * Now, starting in cacheline 2, the exception save areas
	 */
	/* used for most interrupts/exceptions */
	u64 exgen[10] __attribute__((aligned(0x80)));
	u64 exmc[10];		/* used for machine checks */
	u64 exslb[10];		/* used for SLB/segment table misses
 				 * on the linear mapping */
	/* SLB related definitions */
	u16 vmalloc_sllp;
	u16 slb_cache_ptr;
	u16 slb_cache[SLB_CACHE_ENTRIES];
#endif /* CONFIG_PPC_STD_MMU_64 */

#ifdef CONFIG_PPC_BOOK3E
	pgd_t *pgd;			/* Current PGD */
	pgd_t *kernel_pgd;		/* Kernel PGD */
	u64 exgen[8] __attribute__((aligned(0x80)));
	u64 extlb[EX_TLB_SIZE*3] __attribute__((aligned(0x80)));
	u64 exmc[8];		/* used for machine checks */
	u64 excrit[8];		/* used for crit interrupts */
	u64 exdbg[8];		/* used for debug interrupts */

	/* Kernel stack pointers for use by special exceptions */
	void *mc_kstack;
	void *crit_kstack;
	void *dbg_kstack;
#endif /* CONFIG_PPC_BOOK3E */

	mm_context_t context;

	/*
	 * then miscellaneous read-write fields
	 */
	struct task_struct *__current;	/* Pointer to current */
	u64 kstack;			/* Saved Kernel stack addr */
	u64 stab_rr;			/* stab/slb round-robin counter */
	u64 saved_r1;			/* r1 save for RTAS calls */
	u64 saved_msr;			/* MSR saved here by enter_rtas */
	u16 trap_save;			/* Used when bad stack is encountered */
	u8 soft_enabled;		/* irq soft-enable flag */
	u8 hard_enabled;		/* set if irqs are enabled in MSR */
	u8 io_sync;			/* writel() needs spin_unlock sync */
#ifndef __GENKSYMS__
	u8 irq_work_pending;		/* IRQ_WORK interrupt while soft-disable */
#else
	u8 perf_event_pending;		/* PM interrupt while soft-disabled */
#endif

	/* Stuff for accurate time accounting */
	u64 user_time;			/* accumulated usermode TB ticks */
	u64 system_time;		/* accumulated system TB ticks */
	u64 user_time_scaled;		/* accumulated usermode SPURR ticks */
	u64 starttime;			/* TB value snapshot */
	u64 starttime_user;		/* TB value on exit to usermode */
	u64 startspurr;			/* SPURR value snapshot */
	u64 utime_sspurr;		/* ->user_time when ->startspurr set */
	u64 stolen_time;		/* TB ticks taken by hypervisor */
	u64 dtl_ridx;			/* read index in dispatch log */
	struct dtl_entry *dtl_curr;	/* pointer corresponding to dtl_ridx */
};

extern struct paca_struct paca[];
extern void initialise_pacas(void);

#endif /* __KERNEL__ */
#endif /* _ASM_POWERPC_PACA_H */
