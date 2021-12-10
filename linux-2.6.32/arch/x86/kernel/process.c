#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/prctl.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/pm.h>
#include <linux/clockchips.h>
#include <linux/random.h>
#include <linux/user-return-notifier.h>
#include <linux/dmi.h>
#include <linux/utsname.h>
#include <trace/events/power.h>
#include <asm/cpu.h>
#include <asm/system.h>
#include <asm/apic.h>
#include <asm/syscalls.h>
#include <asm/idle.h>
#include <asm/uaccess.h>
#include <asm/i387.h>
#include <asm/spec_ctrl.h>
#include <asm/fpu-internal.h>
#include <asm/debugreg.h>

unsigned long idle_halt;
EXPORT_SYMBOL(idle_halt);
unsigned long idle_nomwait;
EXPORT_SYMBOL(idle_nomwait);

struct kmem_cache *task_xstate_cachep;
EXPORT_SYMBOL_GPL(task_xstate_cachep);

int arch_dup_task_struct(struct task_struct *dst, struct task_struct *src)
{
	int ret;

	*dst = *src;
	if (fpu_allocated((struct fpu *)&src->thread.xstate)) {
		memset(&dst->thread.xstate, 0, sizeof(dst->thread.xstate));
		ret = fpu_alloc((struct fpu *)&dst->thread.xstate);
		if (ret)
			return ret;
		fpu_copy(dst, src);
	}
	return 0;
}

void free_thread_xstate(struct task_struct *tsk)
{
	fpu_free((struct fpu *)&tsk->thread.xstate);
}

void free_thread_info(struct thread_info *ti)
{
	free_thread_xstate(ti->task);
	free_pages((unsigned long)ti, get_order(THREAD_SIZE));
}

void arch_task_cache_init(void)
{
        task_xstate_cachep =
        	kmem_cache_create("task_xstate", xstate_size,
				  __alignof__(union thread_xstate),
				  SLAB_PANIC | SLAB_NOTRACK, NULL);
}

/*
 * Free current thread data structures etc..
 */
void exit_thread(void)
{
	struct task_struct *me = current;
	struct thread_struct *t = &me->thread;
	unsigned long *bp = t->io_bitmap_ptr;

	if (bp) {
		struct tss_struct *tss = &per_cpu(init_tss, get_cpu());

		t->io_bitmap_ptr = NULL;
		clear_thread_flag(TIF_IO_BITMAP);
		/*
		 * Careful, clear this in the TSS too:
		 */
		memset(tss->io_bitmap, 0xff, t->io_bitmap_max);
		t->io_bitmap_max = 0;
		put_cpu();
		kfree(bp);
	}

	drop_fpu(me);
}

void show_regs_common(void)
{
	const char *vendor, *product, *board;

	vendor = dmi_get_system_info(DMI_SYS_VENDOR);
	if (!vendor)
		vendor = "";
	product = dmi_get_system_info(DMI_PRODUCT_NAME);
	if (!product)
		product = "";

	/* Board Name is optional */
	board = dmi_get_system_info(DMI_BOARD_NAME);

	printk(KERN_CONT "\n");
	printk(KERN_DEFAULT "Pid: %d, comm: %.20s %s %s %.*s",
		current->pid, current->comm, print_tainted(),
		init_utsname()->release,
		(int)strcspn(init_utsname()->version, " "),
		init_utsname()->version);
	printk(KERN_CONT " %s %s", vendor, product);
	if (board)
		printk(KERN_CONT "/%s", board);
	printk(KERN_CONT "\n");
}

void flush_thread(void)
{
	struct task_struct *tsk = current;

	clear_tsk_thread_flag(tsk, TIF_DEBUG);

	tsk->thread.debugreg0 = 0;
	tsk->thread.debugreg1 = 0;
	tsk->thread.debugreg2 = 0;
	tsk->thread.debugreg3 = 0;
	tsk->thread.debugreg6 = 0;
	tsk->thread.debugreg7 = 0;
	memset(tsk->thread.tls_array, 0, sizeof(tsk->thread.tls_array));

	if (!use_eager_fpu()) {
		/* FPU state will be reallocated lazily at the first use. */
		drop_fpu(tsk);
		free_thread_xstate(tsk);
	} else {
		restore_init_xstate();
	}
}

static void hard_disable_TSC(void)
{
	write_cr4(read_cr4() | X86_CR4_TSD);
}

void disable_TSC(void)
{
	preempt_disable();
	if (!test_and_set_thread_flag(TIF_NOTSC))
		/*
		 * Must flip the CPU state synchronously with
		 * TIF_NOTSC in the current running context.
		 */
		hard_disable_TSC();
	preempt_enable();
}

static void hard_enable_TSC(void)
{
	write_cr4(read_cr4() & ~X86_CR4_TSD);
}

static void enable_TSC(void)
{
	preempt_disable();
	if (test_and_clear_thread_flag(TIF_NOTSC))
		/*
		 * Must flip the CPU state synchronously with
		 * TIF_NOTSC in the current running context.
		 */
		hard_enable_TSC();
	preempt_enable();
}

int get_tsc_mode(unsigned long adr)
{
	unsigned int val;

	if (test_thread_flag(TIF_NOTSC))
		val = PR_TSC_SIGSEGV;
	else
		val = PR_TSC_ENABLE;

	return put_user(val, (unsigned int __user *)adr);
}

int set_tsc_mode(unsigned int val)
{
	if (val == PR_TSC_SIGSEGV)
		disable_TSC();
	else if (val == PR_TSC_ENABLE)
		enable_TSC();
	else
		return -EINVAL;

	return 0;
}

#ifdef CONFIG_SMP

struct ssb_state {
	struct ssb_state	*shared_state;
	raw_spinlock_t		lock;
	unsigned int		disable_state;
	unsigned long		local_state;
};

#define LSTATE_SSB	0

static DEFINE_PER_CPU(struct ssb_state, ssb_state);

void speculative_store_bypass_ht_init(void)
{
	unsigned int this_cpu = smp_processor_id();
	unsigned int cpu;
	struct ssb_state *st = &per_cpu(ssb_state, this_cpu);

	st->local_state = 0;

	/*
	 * Shared state setup happens once on the first bringup
	 * of the CPU. It's not destroyed on CPU hotunplug.
	 */
	if (st->shared_state)
		return;

	st->lock = (raw_spinlock_t)__RAW_SPIN_LOCK_UNLOCKED;

	/*
	 * Go over HT siblings and check whether one of them has set up the
	 * shared state pointer already.
	 */
	for_each_cpu(cpu, topology_thread_cpumask(this_cpu)) {
		if (cpu == this_cpu)
			continue;

		if (!per_cpu(ssb_state, cpu).shared_state)
			continue;

		/* Link it to the state of the sibling: */
		st->shared_state = per_cpu(ssb_state, cpu).shared_state;
		return;
	}

	/*
	 * First HT sibling to come up on the core.  Link shared state of
	 * the first HT sibling to itself. The siblings on the same core
	 * which come up later will see the shared state pointer and link
	 * themself to the state of this CPU.
	 */
	st->shared_state = st;
}

/*
 * Logic is: First HT sibling enables SSBD for both siblings in the core
 * and last sibling to disable it, disables it for the whole core. This how
 * MSR_SPEC_CTRL works in "hardware":
 *
 *  CORE_SPEC_CTRL = THREAD0_SPEC_CTRL | THREAD1_SPEC_CTRL
 */
static __always_inline void amd_set_core_ssb_state(unsigned long tifn)
{
	struct ssb_state *st = &per_cpu(ssb_state, smp_processor_id());
	u64 msr = x86_amd_ls_cfg_base;

	if (!static_cpu_has(X86_FEATURE_ZEN)) {
		msr |= ssbd_tif_to_amd_ls_cfg(tifn);
		wrmsrl(MSR_AMD64_LS_CFG, msr);
		return;
	}

	if (tifn & _TIF_SSBD) {
		/*
		 * Since this can race with prctl(), block reentry on the
		 * same CPU.
		 */
		if (__test_and_set_bit(LSTATE_SSB, &st->local_state))
			return;

		msr |= x86_amd_ls_cfg_ssbd_mask;

		__raw_spin_lock(&st->shared_state->lock);
		/* First sibling enables SSBD: */
		if (!st->shared_state->disable_state)
			wrmsrl(MSR_AMD64_LS_CFG, msr);
		st->shared_state->disable_state++;
		__raw_spin_unlock(&st->shared_state->lock);
	} else {
		if (!__test_and_clear_bit(LSTATE_SSB, &st->local_state))
			return;

		__raw_spin_lock(&st->shared_state->lock);
		st->shared_state->disable_state--;
		if (!st->shared_state->disable_state)
			wrmsrl(MSR_AMD64_LS_CFG, msr);
		__raw_spin_unlock(&st->shared_state->lock);
	}
}
#else
static __always_inline void amd_set_core_ssb_state(unsigned long tifn)
{
	u64 msr = x86_amd_ls_cfg_base | ssbd_tif_to_amd_ls_cfg(tifn);

	wrmsrl(MSR_AMD64_LS_CFG, msr);
}
#endif

static __always_inline void amd_set_ssb_virt_state(unsigned long tifn)
{
	/*
	 * SSBD has the same definition in SPEC_CTRL and VIRT_SPEC_CTRL,
	 * so ssbd_tif_to_spec_ctrl() just works.
	 */
	wrmsrl(MSR_AMD64_VIRT_SPEC_CTRL, ssbd_tif_to_spec_ctrl(tifn));
}

static __always_inline void intel_set_ssb_state(unsigned long tifn)
{
	spec_ctrl_set_ssbd(ssbd_tif_to_spec_ctrl(tifn));
	wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl_pcp_read64());
}

static __always_inline void __speculative_store_bypass_update(unsigned long tifn)
{
	if (!ssb_is_user_settable(READ_ONCE(ssb_mode)))
		return;	/* Don't do anything if not user settable */

	if (static_cpu_has(X86_FEATURE_VIRT_SSBD))
		amd_set_ssb_virt_state(tifn);
	else if (static_cpu_has(X86_FEATURE_LS_CFG_SSBD))
		amd_set_core_ssb_state(tifn);
	else
		intel_set_ssb_state(tifn);
}

void speculative_store_bypass_update(unsigned long tif)
{
	preempt_disable();
	__speculative_store_bypass_update(tif);
	preempt_enable();
}
EXPORT_SYMBOL_GPL(speculative_store_bypass_update);

void __switch_to_xtra(struct task_struct *prev_p, struct task_struct *next_p,
		      struct tss_struct *tss)
{
	struct thread_struct *prev, *next;

	prev = &prev_p->thread;
	next = &next_p->thread;

	if (test_tsk_thread_flag(next_p, TIF_DEBUG)) {
		set_debugreg(next->debugreg0, 0);
		set_debugreg(next->debugreg1, 1);
		set_debugreg(next->debugreg2, 2);
		set_debugreg(next->debugreg3, 3);
		/* no 4 and 5 */
		set_debugreg(next->debugreg6, 6);
		set_debugreg(next->debugreg7, 7);
	}

	if (test_tsk_thread_flag(prev_p, TIF_BLOCKSTEP) ^
	    test_tsk_thread_flag(next_p, TIF_BLOCKSTEP)) {
		unsigned long debugctl = get_debugctlmsr();

		debugctl &= ~DEBUGCTLMSR_BTF;
		if (test_tsk_thread_flag(next_p, TIF_BLOCKSTEP))
			debugctl |= DEBUGCTLMSR_BTF;

		update_debugctlmsr(debugctl);
	}

	if (test_tsk_thread_flag(prev_p, TIF_NOTSC) ^
	    test_tsk_thread_flag(next_p, TIF_NOTSC)) {
		/* prev and next are different */
		if (test_tsk_thread_flag(next_p, TIF_NOTSC))
			hard_disable_TSC();
		else
			hard_enable_TSC();
	}

	if (test_tsk_thread_flag(next_p, TIF_IO_BITMAP)) {
		/*
		 * Copy the relevant range of the IO bitmap.
		 * Normally this is 128 bytes or less:
		 */
		memcpy(tss->io_bitmap, next->io_bitmap_ptr,
		       max(prev->io_bitmap_max, next->io_bitmap_max));
	} else if (test_tsk_thread_flag(prev_p, TIF_IO_BITMAP)) {
		/*
		 * Clear any possible leftover bits:
		 */
		memset(tss->io_bitmap, 0xff, prev->io_bitmap_max);
	}
	propagate_user_return_notify(prev_p, next_p);

	if (test_tsk_thread_flag(prev_p, TIF_SSBD) ^
	    test_tsk_thread_flag(next_p, TIF_SSBD))
		__speculative_store_bypass_update(task_thread_info(next_p)->flags);
}

int sys_fork(struct pt_regs *regs)
{
	return do_fork(SIGCHLD, regs->sp, regs, 0, NULL, NULL);
}

/*
 * This is trivial, and on the face of it looks like it
 * could equally well be done in user mode.
 *
 * Not so, for quite unobvious reasons - register pressure.
 * In user mode vfork() cannot have a stack frame, and if
 * done by calling the "clone()" system call directly, you
 * do not have enough call-clobbered registers to hold all
 * the information you need.
 */
int sys_vfork(struct pt_regs *regs)
{
#ifdef CONFIG_HCC_GPM
	int retval;
#ifdef CONFIG_HCC_GCAP
	if (can_use_hcc_gcap(current, GCAP_DISTANT_FORK))
	{
#endif
		retval = hcc_do_fork(CLONE_VFORK | SIGCHLD,
					 regs->sp, regs, 0,
					 NULL, NULL, 0);
		if (retval > 0)
			return retval;
	}
#endif /* CONFIG_HCC_GPM */
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->sp, regs, 0,
		       NULL, NULL);
}


/*
 * Idle related variables and functions
 */
unsigned long boot_option_idle_override = 0;
EXPORT_SYMBOL(boot_option_idle_override);

/*
 * Powermanagement idle function, if any..
 */
void (*pm_idle)(void);
EXPORT_SYMBOL(pm_idle);

#ifdef CONFIG_X86_32
/*
 * This halt magic was a workaround for ancient floppy DMA
 * wreckage. It should be safe to remove.
 */
static int hlt_counter;
void disable_hlt(void)
{
	hlt_counter++;
}
EXPORT_SYMBOL(disable_hlt);

void enable_hlt(void)
{
	hlt_counter--;
}
EXPORT_SYMBOL(enable_hlt);

static inline int hlt_use_halt(void)
{
	return (!hlt_counter && boot_cpu_data.hlt_works_ok);
}
#else
static inline int hlt_use_halt(void)
{
	return 1;
}
#endif

/*
 * We use this if we don't have any better
 * idle routine..
 */
void default_idle(void)
{
	spec_ctrl_ibrs_off();
	if (hlt_use_halt()) {
		trace_power_start(POWER_CSTATE, 1, smp_processor_id());
		current_thread_info()->status &= ~TS_POLLING;
		/*
		 * TS_POLLING-cleared state must be visible before we
		 * test NEED_RESCHED:
		 */
		smp_mb();

		if (!need_resched())
			safe_halt();	/* enables interrupts racelessly */
		else
			local_irq_enable();
		current_thread_info()->status |= TS_POLLING;
	} else {
		local_irq_enable();
		/* loop is done by the caller */
		cpu_relax();
	}
	spec_ctrl_ibrs_on();
}
#ifdef CONFIG_APM_MODULE
EXPORT_SYMBOL(default_idle);
#endif

void stop_this_cpu(void *dummy)
{
	local_irq_disable();
	/*
	 * Remove this CPU:
	 */
	set_cpu_online(smp_processor_id(), false);
	disable_local_APIC();

	for (;;) {
		if (hlt_works(smp_processor_id()))
			halt();
	}
}

static void do_nothing(void *unused)
{
}

/*
 * cpu_idle_wait - Used to ensure that all the CPUs discard old value of
 * pm_idle and update to new pm_idle value. Required while changing pm_idle
 * handler on SMP systems.
 *
 * Caller must have changed pm_idle to the new value before the call. Old
 * pm_idle value will not be used by any CPU after the return of this function.
 */
void cpu_idle_wait(void)
{
	smp_mb();
	/* kick all the CPUs so that they exit out of pm_idle */
	smp_call_function(do_nothing, NULL, 1);
}
EXPORT_SYMBOL_GPL(cpu_idle_wait);

/*
 * This uses new MONITOR/MWAIT instructions on P4 processors with PNI,
 * which can obviate IPI to trigger checking of need_resched.
 * We execute MONITOR against need_resched and enter optimized wait state
 * through MWAIT. Whenever someone changes need_resched, we would be woken
 * up from MWAIT (without an IPI).
 *
 * New with Core Duo processors, MWAIT can take some hints based on CPU
 * capability.
 */
void mwait_idle_with_hints(unsigned long ax, unsigned long cx)
{
	trace_power_start(POWER_CSTATE, (ax>>4)+1, smp_processor_id());
	if (!need_resched()) {
		if (cpu_has(&current_cpu_data, X86_FEATURE_CLFLUSH_MONITOR))
			clflush((void *)&current_thread_info()->flags);

		/*
		 * IRQs must be disabled here and nmi uses the
		 * save_paranoid model which always enables ibrs on
		 * exception entry before any indirect jump can run.
		 */
		spec_ctrl_ibrs_off();
		__monitor((void *)&current_thread_info()->flags, 0, 0);
		smp_mb();
		if (!need_resched())
			__mwait(ax, cx);
		spec_ctrl_ibrs_on();
	}
}

/* Default MONITOR/MWAIT with no hints, used for default C1 state */
static void mwait_idle(void)
{
	if (!need_resched()) {
		trace_power_start(POWER_CSTATE, 1, smp_processor_id());
		if (cpu_has(&current_cpu_data, X86_FEATURE_CLFLUSH_MONITOR))
			clflush((void *)&current_thread_info()->flags);

		spec_ctrl_ibrs_off();
		__monitor((void *)&current_thread_info()->flags, 0, 0);
		smp_mb();
		if (!need_resched())
			__sti_mwait(0, 0);
		else
			local_irq_enable();
		spec_ctrl_ibrs_on();
	} else
		local_irq_enable();
}

/*
 * On SMP it's slightly faster (but much more power-consuming!)
 * to poll the ->work.need_resched flag instead of waiting for the
 * cross-CPU IPI to arrive. Use this option with caution.
 */
static void poll_idle(void)
{
	trace_power_start(POWER_CSTATE, 0, smp_processor_id());
	local_irq_enable();
	spec_ctrl_ibrs_off();
	while (!need_resched())
		cpu_relax();
	spec_ctrl_ibrs_on();
	trace_power_end(0);
}

/*
 * mwait selection logic:
 *
 * It depends on the CPU. For AMD CPUs that support MWAIT this is
 * wrong. Family 0x10 and 0x11 CPUs will enter C1 on HLT. Powersavings
 * then depend on a clock divisor and current Pstate of the core. If
 * all cores of a processor are in halt state (C1) the processor can
 * enter the C1E (C1 enhanced) state. If mwait is used this will never
 * happen.
 *
 * idle=mwait overrides this decision and forces the usage of mwait.
 */
static int force_mwait;

#define MWAIT_INFO			0x05
#define MWAIT_ECX_EXTENDED_INFO		0x01
#define MWAIT_EDX_C1			0xf0

int mwait_usable(const struct cpuinfo_x86 *c)
{
	u32 eax, ebx, ecx, edx;

	if (force_mwait)
		return 1;

	if (c->cpuid_level < MWAIT_INFO)
		return 0;

	cpuid(MWAIT_INFO, &eax, &ebx, &ecx, &edx);
	/* Check, whether EDX has extended info about MWAIT */
	if (!(ecx & MWAIT_ECX_EXTENDED_INFO))
		return 1;

	/*
	 * edx enumeratios MONITOR/MWAIT extensions. Check, whether
	 * C1  supports MWAIT
	 */
	return (edx & MWAIT_EDX_C1);
}

/*
 * Check for AMD CPUs, where APIC timer interrupt does not wake up CPU from C1e.
 * For more information see
 * - Erratum #400 for NPT family 0xf and family 0x10 CPUs
 * - Erratum #365 for family 0x11 (not affected because C1e not in use)
 */
static int __cpuinit check_c1e_idle(const struct cpuinfo_x86 *c)
{
	u64 val;
	if (c->x86_vendor != X86_VENDOR_AMD)
		goto no_c1e_idle;

	/* Family 0x0f models < rev F do not have C1E */
	if (c->x86 == 0x0F && c->x86_model >= 0x40)
		return 1;

	if (c->x86 == 0x10) {
		/*
		 * check OSVW bit for CPUs that are not affected
		 * by erratum #400
		 */
		if (cpu_has(c, X86_FEATURE_OSVW)) {
			rdmsrl(MSR_AMD64_OSVW_ID_LENGTH, val);
			if (val >= 2) {
				rdmsrl(MSR_AMD64_OSVW_STATUS, val);
				if (!(val & BIT(1)))
					goto no_c1e_idle;
			}
		}
		return 1;
	}

no_c1e_idle:
	return 0;
}

static cpumask_var_t c1e_mask;
static int c1e_detected;

void c1e_remove_cpu(int cpu)
{
	if (c1e_mask != NULL)
		cpumask_clear_cpu(cpu, c1e_mask);
}

/*
 * C1E aware idle routine. We check for C1E active in the interrupt
 * pending message MSR. If we detect C1E, then we handle it the same
 * way as C3 power states (local apic timer and TSC stop)
 */
static void c1e_idle(void)
{
	if (need_resched())
		return;

	if (!c1e_detected) {
		u32 lo, hi;

		rdmsr(MSR_K8_INT_PENDING_MSG, lo, hi);
		if (lo & K8_INTP_C1E_ACTIVE_MASK) {
			c1e_detected = 1;
			if (!boot_cpu_has(X86_FEATURE_NONSTOP_TSC))
				mark_tsc_unstable("TSC halt in AMD C1E");
			printk(KERN_INFO "System has AMD C1E enabled\n");
			set_cpu_cap(&boot_cpu_data, X86_FEATURE_AMDC1E);
		}
	}

	if (c1e_detected) {
		int cpu = smp_processor_id();

		if (!cpumask_test_cpu(cpu, c1e_mask)) {
			cpumask_set_cpu(cpu, c1e_mask);
			/*
			 * Force broadcast so ACPI can not interfere.
			 */
			clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_FORCE,
					   &cpu);
			printk(KERN_INFO "Switch to broadcast mode on CPU%d\n",
			       cpu);
		}
		clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_ENTER, &cpu);

		default_idle();

		/*
		 * The switch back from broadcast mode needs to be
		 * called with interrupts disabled.
		 */
		 local_irq_disable();
		 clockevents_notify(CLOCK_EVT_NOTIFY_BROADCAST_EXIT, &cpu);
		 local_irq_enable();
	} else
		default_idle();
}

void __cpuinit select_idle_routine(const struct cpuinfo_x86 *c)
{
#ifdef CONFIG_SMP
	if (pm_idle == poll_idle && smp_num_siblings > 1) {
		printk(KERN_WARNING "WARNING: polling idle and HT enabled,"
			" performance may degrade.\n");
	}
#endif
	if (pm_idle)
		return;

	if (cpu_has(c, X86_FEATURE_MWAIT) && mwait_usable(c)) {
		/*
		 * One CPU supports mwait => All CPUs supports mwait
		 */
		printk(KERN_INFO "using mwait in idle threads.\n");
		pm_idle = mwait_idle;
	} else if (check_c1e_idle(c)) {
		printk(KERN_INFO "using C1E aware idle routine\n");
		pm_idle = c1e_idle;
	} else
		pm_idle = default_idle;
}

void __init init_c1e_mask(void)
{
	/* If we're using c1e_idle, we need to allocate c1e_mask. */
	if (pm_idle == c1e_idle)
		zalloc_cpumask_var(&c1e_mask, GFP_KERNEL);
}

static int __init idle_setup(char *str)
{
	if (!str)
		return -EINVAL;

	if (!strcmp(str, "poll")) {
		printk("using polling idle threads.\n");
		pm_idle = poll_idle;
	} else if (!strcmp(str, "mwait"))
		force_mwait = 1;
	else if (!strcmp(str, "halt")) {
		/*
		 * When the boot option of idle=halt is added, halt is
		 * forced to be used for CPU idle. In such case CPU C2/C3
		 * won't be used again.
		 * To continue to load the CPU idle driver, don't touch
		 * the boot_option_idle_override.
		 */
		pm_idle = default_idle;
		idle_halt = 1;
		return 0;
	} else if (!strcmp(str, "nomwait")) {
		/*
		 * If the boot option of "idle=nomwait" is added,
		 * it means that mwait will be disabled for CPU C2/C3
		 * states. In such case it won't touch the variable
		 * of boot_option_idle_override.
		 */
		idle_nomwait = 1;
		return 0;
	} else
		return -1;

	boot_option_idle_override = 1;
	return 0;
}
early_param("idle", idle_setup);

unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_int() % 8192;
	return sp & ~0xf;
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
	unsigned long range_end = mm->brk + 0x02000000;
	return randomize_range(mm->brk, range_end, 0) ? : mm->brk;
}

