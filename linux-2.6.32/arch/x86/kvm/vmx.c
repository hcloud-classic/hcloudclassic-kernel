/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This module enables machines with Intel VT-x extensions to run virtual
 * machines without emulation or binary translation.
 *
 * Copyright (C) 2006 Qumranet, Inc.
 *
 * Authors:
 *   Avi Kivity   <avi@qumranet.com>
 *   Yaniv Kamay  <yaniv@qumranet.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "irq.h"
#include "mmu.h"

#include <linux/kvm_host.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/ftrace_event.h>
#include <linux/tboot.h>
#include "kvm_cache_regs.h"
#include "x86.h"

#include <asm/io.h>
#include <asm/desc.h>
#include <asm/vmx.h>
#include <asm/virtext.h>
#include <asm/mce.h>
#include <asm/i387.h>
#include <asm/xcr.h>
#include <asm/perf_event.h>
#include <asm/kexec.h>
#include <asm/nospec-branch.h>

#include "trace.h"

#define __ex(x) __kvm_handle_fault_on_reboot(x)

MODULE_AUTHOR("Qumranet");
MODULE_LICENSE("GPL");

static int __read_mostly bypass_guest_pf = 1;
module_param(bypass_guest_pf, bool, S_IRUGO);

static int __read_mostly enable_vpid = 1;
module_param_named(vpid, enable_vpid, bool, 0444);

static int __read_mostly flexpriority_enabled = 1;
module_param_named(flexpriority, flexpriority_enabled, bool, S_IRUGO);

static int __read_mostly enable_ept = 1;
module_param_named(ept, enable_ept, bool, S_IRUGO);

static int __read_mostly enable_unrestricted_guest = 1;
module_param_named(unrestricted_guest,
			enable_unrestricted_guest, bool, S_IRUGO);

static bool __read_mostly enable_ept_ad_bits = 1;
module_param_named(eptad, enable_ept_ad_bits, bool, S_IRUGO);

static int __read_mostly emulate_invalid_guest_state = 0;
module_param(emulate_invalid_guest_state, bool, S_IRUGO);

static int __read_mostly yield_on_hlt = 1;
module_param(yield_on_hlt, bool, S_IRUGO);

static int __read_mostly vmm_exclusive = 1;
module_param(vmm_exclusive, bool, S_IRUGO);

/*
 * These 2 parameters are used to config the controls for Pause-Loop Exiting:
 * ple_gap:    upper bound on the amount of time between two successive
 *             executions of PAUSE in a loop. Also indicate if ple enabled.
 *             According to test, this time is usually smaller than 128 cycles.
 * ple_window: upper bound on the amount of time a guest is allowed to execute
 *             in a PAUSE loop. Tests indicate that most spinlocks are held for
 *             less than 2^12 cycles
 * Time is measured based on a counter that runs at the same rate as the TSC,
 * refer SDM volume 3b section 21.6.13 & 22.1.3.
 */
#define KVM_VMX_DEFAULT_PLE_GAP           128
#define KVM_VMX_DEFAULT_PLE_WINDOW        4096
#define KVM_VMX_DEFAULT_PLE_WINDOW_GROW   2
#define KVM_VMX_DEFAULT_PLE_WINDOW_SHRINK 0
#define KVM_VMX_DEFAULT_PLE_WINDOW_MAX    \
		INT_MAX / KVM_VMX_DEFAULT_PLE_WINDOW_GROW
static int ple_gap = KVM_VMX_DEFAULT_PLE_GAP;
module_param(ple_gap, int, S_IRUGO);

static int ple_window = KVM_VMX_DEFAULT_PLE_WINDOW;
module_param(ple_window, int, S_IRUGO);

/* Default doubles per-vcpu window every exit. */
static int ple_window_grow = KVM_VMX_DEFAULT_PLE_WINDOW_GROW;
module_param(ple_window_grow, int, S_IRUGO);

/* Default resets per-vcpu window every exit to ple_window. */
static int ple_window_shrink = KVM_VMX_DEFAULT_PLE_WINDOW_SHRINK;
module_param(ple_window_shrink, int, S_IRUGO);

/* Default is to compute the maximum so we can never overflow. */
static int ple_window_actual_max = KVM_VMX_DEFAULT_PLE_WINDOW_MAX;
static int ple_window_max        = KVM_VMX_DEFAULT_PLE_WINDOW_MAX;
module_param(ple_window_max, int, S_IRUGO);

#define NR_AUTOLOAD_MSRS 8

struct vmcs {
	u32 revision_id;
	u32 abort;
	char data[0];
};

struct shared_msr_entry {
	unsigned index;
	u64 data;
	u64 mask;
};

struct vmx_msrs {
	unsigned int		nr;
	struct vmx_msr_entry	val[NR_AUTOLOAD_MSRS];
};

struct vcpu_vmx {
	struct kvm_vcpu       vcpu;
	struct list_head      local_vcpus_link;
	unsigned long         host_rsp;
	int                   launched;
	u8                    fail;
	u32                   idt_vectoring_info;
	struct shared_msr_entry *guest_msrs;
	int                   nmsrs;
	int                   save_nmsrs;
	int                   msr_offset_efer;
	unsigned long	      host_idt_base;
#ifdef CONFIG_X86_64
	u64 		      msr_host_kernel_gs_base;
	u64 		      msr_guest_kernel_gs_base;
#endif
	u64		      spec_ctrl;

	u64		      arch_capabilities;

	struct vmcs          *vmcs;
	struct msr_autoload {
		struct vmx_msrs guest;
		struct vmx_msrs host;
	} msr_autoload;
	struct {
		int           loaded;
		u16           fs_sel, gs_sel, ldt_sel;
		int           gs_ldt_reload_needed;
		int           fs_reload_needed;
		unsigned long vmcs_host_cr4;	/* May not match real cr4 */
	} host_state;
	struct {
		int vm86_active;
		ulong save_rflags;
		struct kvm_save_segment {
			u16 selector;
			unsigned long base;
			u32 limit;
			u32 ar;
		} tr, es, ds, fs, gs;
		struct {
			bool pending;
			u8 vector;
			unsigned rip;
		} irq;
	} rmode;
	int vpid;
	bool emulation_required;
	enum emulation_result invalid_state_emulation_result;

	/* Support for vnmi-less CPUs */
	int soft_vnmi_blocked;
	ktime_t entry_time;
	s64 vnmi_blocked_time;
	u32 exit_reason;

	/* Dynamic PLE window. */
	int ple_window;
	bool ple_window_dirty;
};

static inline struct vcpu_vmx *to_vmx(struct kvm_vcpu *vcpu)
{
	return container_of(vcpu, struct vcpu_vmx, vcpu);
}

static u64 construct_eptp(unsigned long root_hpa);
static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr);
static void kvm_cpu_vmxon(u64 addr);
static void kvm_cpu_vmxoff(void);
static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);
static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg);

static DEFINE_PER_CPU(struct vmcs *, vmxarea);
static DEFINE_PER_CPU(struct vmcs *, current_vmcs);
static DEFINE_PER_CPU(struct list_head, vcpus_on_cpu);
static DEFINE_PER_CPU(struct desc_ptr, host_gdt);

static unsigned long *vmx_io_bitmap_a;
static unsigned long *vmx_io_bitmap_b;
static unsigned long *vmx_msr_bitmap_legacy;
static unsigned long *vmx_msr_bitmap_longmode;

static bool cpu_has_load_perf_global_ctrl;

static DECLARE_BITMAP(vmx_vpid_bitmap, VMX_NR_VPIDS);
static DEFINE_SPINLOCK(vmx_vpid_lock);
static DEFINE_MUTEX(vmx_l1d_flush_mutex);

static struct vmcs_config {
	int size;
	int order;
	u32 revision_id;
	u32 pin_based_exec_ctrl;
	u32 cpu_based_exec_ctrl;
	u32 cpu_based_2nd_exec_ctrl;
	u32 vmexit_ctrl;
	u32 vmentry_ctrl;
} vmcs_config;

static struct vmx_capability {
	u32 ept;
	u32 vpid;
} vmx_capability;

#define VMX_SEGMENT_FIELD(seg)					\
	[VCPU_SREG_##seg] = {                                   \
		.selector = GUEST_##seg##_SELECTOR,		\
		.base = GUEST_##seg##_BASE,		   	\
		.limit = GUEST_##seg##_LIMIT,		   	\
		.ar_bytes = GUEST_##seg##_AR_BYTES,	   	\
	}

static struct kvm_vmx_segment_field {
	unsigned selector;
	unsigned base;
	unsigned limit;
	unsigned ar_bytes;
} kvm_vmx_segment_fields[] = {
	VMX_SEGMENT_FIELD(CS),
	VMX_SEGMENT_FIELD(DS),
	VMX_SEGMENT_FIELD(ES),
	VMX_SEGMENT_FIELD(FS),
	VMX_SEGMENT_FIELD(GS),
	VMX_SEGMENT_FIELD(SS),
	VMX_SEGMENT_FIELD(TR),
	VMX_SEGMENT_FIELD(LDTR),
};

static u64 host_efer;

static void ept_save_pdptrs(struct kvm_vcpu *vcpu);

#define RMODE_GUEST_OWNED_EFLAGS_BITS (~(X86_EFLAGS_IOPL | X86_EFLAGS_VM))

/* Storage for pre module init parameter parsing */
static enum vmx_l1d_flush_state __read_mostly vmentry_l1d_flush_param = VMENTER_L1D_FLUSH_AUTO;

static const struct {
	const char *option;
	bool for_parse;
} vmentry_l1d_param[] = {
	[VMENTER_L1D_FLUSH_AUTO]	 = {"auto", true},
	[VMENTER_L1D_FLUSH_NEVER]	 = {"never", true},
	[VMENTER_L1D_FLUSH_COND]	 = {"cond", true},
	[VMENTER_L1D_FLUSH_ALWAYS]	 = {"always", true},
	[VMENTER_L1D_FLUSH_EPT_DISABLED] = {"EPT disabled", false},
	[VMENTER_L1D_FLUSH_NOT_REQUIRED] = {"not required", false},
};

#define L1D_CACHE_ORDER 4
static void *vmx_l1d_flush_pages;

static int vmx_setup_l1d_flush(enum vmx_l1d_flush_state l1tf)
{
	struct page *page;
	unsigned int i;

	if (!boot_cpu_has_bug(X86_BUG_L1TF)) {
		l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_NOT_REQUIRED;
		return 0;
	}

	if (!enable_ept) {
		l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_EPT_DISABLED;
		return 0;
	}

       if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES)) {
	       u64 msr;

	       rdmsrl(MSR_IA32_ARCH_CAPABILITIES, msr);
	       if (msr & ARCH_CAP_SKIP_VMENTRY_L1DFLUSH) {
		       l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_NOT_REQUIRED;
		       return 0;
	       }
       }

	/* If set to auto use the default l1tf mitigation method */
	if (l1tf == VMENTER_L1D_FLUSH_AUTO) {
		switch (l1tf_mitigation) {
		case L1TF_MITIGATION_OFF:
			l1tf = VMENTER_L1D_FLUSH_NEVER;
			break;
		case L1TF_MITIGATION_FLUSH_NOWARN:
		case L1TF_MITIGATION_FLUSH:
		case L1TF_MITIGATION_FLUSH_NOSMT:
			l1tf = VMENTER_L1D_FLUSH_COND;
			break;
		case L1TF_MITIGATION_FULL:
		case L1TF_MITIGATION_FULL_FORCE:
			l1tf = VMENTER_L1D_FLUSH_ALWAYS;
			break;
		}
	} else if (l1tf_mitigation == L1TF_MITIGATION_FULL_FORCE) {
		l1tf = VMENTER_L1D_FLUSH_ALWAYS;
	}

	if (l1tf != VMENTER_L1D_FLUSH_NEVER && !vmx_l1d_flush_pages &&
	    !boot_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		page = alloc_pages(GFP_KERNEL, L1D_CACHE_ORDER);
		if (!page)
			return -ENOMEM;
		vmx_l1d_flush_pages = page_address(page);

		/*
		 * Initialize each page with a different pattern in
		 * order to protect against KSM in the nested
		 * virtualization case.
		 */
		for (i = 0; i < 1u << L1D_CACHE_ORDER; ++i) {
			memset(vmx_l1d_flush_pages + i * PAGE_SIZE, i + 1,
			       PAGE_SIZE);
		}
	}

	l1tf_vmx_mitigation = l1tf;
	return 0;
}

static int vmentry_l1d_flush_parse(const char *s)
{
	unsigned int i;

	if (s) {
		for (i = 0; i < ARRAY_SIZE(vmentry_l1d_param); i++) {
			if (vmentry_l1d_param[i].for_parse &&
			    sysfs_streq(s, vmentry_l1d_param[i].option))
				return i;
		}
	}
	return -EINVAL;
}

static int vmentry_l1d_flush_set(const char *s, struct kernel_param *kp)
{
	int l1tf, ret;

	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return 0;

	l1tf = vmentry_l1d_flush_parse(s);
	if (l1tf < 0)
		return l1tf;

	/*
	 * Has vmx_init() run already? If not then this is the pre init
	 * parameter parsing. In that case just store the value and let
	 * vmx_init() do the proper setup after enable_ept has been
	 * established.
	 */
	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_AUTO) {
		vmentry_l1d_flush_param = l1tf;
		return 0;
	}

	mutex_lock(&vmx_l1d_flush_mutex);
	ret = vmx_setup_l1d_flush(l1tf);
	mutex_unlock(&vmx_l1d_flush_mutex);
	return ret;
}

static int vmentry_l1d_flush_get(char *s, struct kernel_param *kp)
{
	return sprintf(s, "%s", vmentry_l1d_param[l1tf_vmx_mitigation].option);
}

module_param_call(vmentry_l1d_flush, vmentry_l1d_flush_set,
		  vmentry_l1d_flush_get, NULL, 0644);

/*
 * Keep MSR_K6_STAR at the end, as setup_msrs() will try to optimize it
 * away by decrementing the array size.
 */
static const u32 vmx_msr_index[] = {
#ifdef CONFIG_X86_64
	MSR_SYSCALL_MASK, MSR_LSTAR, MSR_CSTAR,
#endif
	MSR_EFER, MSR_K6_STAR,
};
#define NR_VMX_MSR ARRAY_SIZE(vmx_msr_index)

static inline int is_page_fault(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | PF_VECTOR | INTR_INFO_VALID_MASK);
}

static inline int is_no_device(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | NM_VECTOR | INTR_INFO_VALID_MASK);
}

static inline int is_invalid_opcode(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | UD_VECTOR | INTR_INFO_VALID_MASK);
}

static inline int is_external_interrupt(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VALID_MASK))
		== (INTR_TYPE_EXT_INTR | INTR_INFO_VALID_MASK);
}

static inline int is_machine_check(u32 intr_info)
{
	return (intr_info & (INTR_INFO_INTR_TYPE_MASK | INTR_INFO_VECTOR_MASK |
			     INTR_INFO_VALID_MASK)) ==
		(INTR_TYPE_HARD_EXCEPTION | MC_VECTOR | INTR_INFO_VALID_MASK);
}

static inline int cpu_has_vmx_msr_bitmap(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_USE_MSR_BITMAPS;
}

static inline int cpu_has_vmx_tpr_shadow(void)
{
	return vmcs_config.cpu_based_exec_ctrl & CPU_BASED_TPR_SHADOW;
}

static inline int vm_need_tpr_shadow(struct kvm *kvm)
{
	return (cpu_has_vmx_tpr_shadow()) && (irqchip_in_kernel(kvm));
}

static inline int cpu_has_secondary_exec_ctrls(void)
{
	return vmcs_config.cpu_based_exec_ctrl &
		CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
}

static inline bool cpu_has_vmx_virtualize_apic_accesses(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
}

static inline bool cpu_has_vmx_flexpriority(void)
{
	return cpu_has_vmx_tpr_shadow() &&
		cpu_has_vmx_virtualize_apic_accesses();
}

static inline bool cpu_has_vmx_ept_execute_only(void)
{
	return !!(vmx_capability.ept & VMX_EPT_EXECUTE_ONLY_BIT);
}

static inline bool cpu_has_vmx_eptp_uncacheable(void)
{
	return !!(vmx_capability.ept & VMX_EPTP_UC_BIT);
}

static inline bool cpu_has_vmx_eptp_writeback(void)
{
	return !!(vmx_capability.ept & VMX_EPTP_WB_BIT);
}

static inline bool cpu_has_vmx_ept_2m_page(void)
{
	return !!(vmx_capability.ept & VMX_EPT_2MB_PAGE_BIT);
}

static inline bool cpu_has_vmx_ept_ad_bits(void)
{
	return vmx_capability.ept & VMX_EPT_AD_BIT;
}

static inline bool cpu_has_vmx_ept_1g_page(void)
{
	return !!(vmx_capability.ept & VMX_EPT_1GB_PAGE_BIT);
}

static inline int cpu_has_vmx_invept_individual_addr(void)
{
	return !!(vmx_capability.ept & VMX_EPT_EXTENT_INDIVIDUAL_BIT);
}

static inline int cpu_has_vmx_invept_context(void)
{
	return !!(vmx_capability.ept & VMX_EPT_EXTENT_CONTEXT_BIT);
}

static inline int cpu_has_vmx_invept_global(void)
{
	return !!(vmx_capability.ept & VMX_EPT_EXTENT_GLOBAL_BIT);
}

static inline int cpu_has_vmx_ept(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_EPT;
}

static inline int cpu_has_vmx_unrestricted_guest(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_UNRESTRICTED_GUEST;
}

static inline int cpu_has_vmx_ple(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_PAUSE_LOOP_EXITING;
}

static inline int vm_need_virtualize_apic_accesses(struct kvm *kvm)
{
	return flexpriority_enabled &&
		(cpu_has_vmx_virtualize_apic_accesses()) &&
		(irqchip_in_kernel(kvm));
}

static inline int cpu_has_vmx_vpid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_VPID;
}

static inline bool cpu_has_vmx_invpcid(void)
{
	return vmcs_config.cpu_based_2nd_exec_ctrl &
		SECONDARY_EXEC_ENABLE_INVPCID;
}

static bool vmx_invpcid_supported(void)
{
	return cpu_has_vmx_invpcid() && enable_ept;
}

static inline int cpu_has_virtual_nmis(void)
{
	return vmcs_config.pin_based_exec_ctrl & PIN_BASED_VIRTUAL_NMIS;
}

static inline bool report_flexpriority(void)
{
	return flexpriority_enabled;
}

static int __find_msr_index(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	for (i = 0; i < vmx->nmsrs; ++i)
		if (vmx_msr_index[vmx->guest_msrs[i].index] == msr)
			return i;
	return -1;
}

static inline void __invvpid(int ext, u16 vpid, gva_t gva)
{
    struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
    } operand = { vpid, 0, gva };

    asm volatile (__ex(ASM_VMX_INVVPID)
		  /* CF==1 or ZF==1 --> rc = -1 */
		  "; ja 1f ; ud2 ; 1:"
		  : : "a"(&operand), "c"(ext) : "cc", "memory");
}

static inline void __invept(int ext, u64 eptp, gpa_t gpa)
{
	struct {
		u64 eptp, gpa;
	} operand = {eptp, gpa};

	asm volatile (__ex(ASM_VMX_INVEPT)
			/* CF==1 or ZF==1 --> rc = -1 */
			"; ja 1f ; ud2 ; 1:\n"
			: : "a" (&operand), "c" (ext) : "cc", "memory");
}

static struct shared_msr_entry *find_msr_entry(struct vcpu_vmx *vmx, u32 msr)
{
	int i;

	i = __find_msr_index(vmx, msr);
	if (i >= 0)
		return &vmx->guest_msrs[i];
	return NULL;
}

static void vmcs_clear(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMCLEAR_RAX) "; setna %0"
		      : "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
		      : "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmclear fail: %p/%llx\n",
		       vmcs, phys_addr);
}

static void vmcs_load(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(vmcs);
	u8 error;

	asm volatile (__ex(ASM_VMX_VMPTRLD_RAX) "; setna %0"
			: "=g"(error) : "a"(&phys_addr), "m"(phys_addr)
			: "cc", "memory");
	if (error)
		printk(KERN_ERR "kvm: vmptrld %p/%llx fail\n",
		       vmcs, phys_addr);
}

#ifdef CONFIG_KEXEC
/*
 * This bitmap is used to indicate whether the vmclear
 * operation is enabled on all cpus. All disabled by
 * default.
 */
static cpumask_t crash_vmclear_enabled_bitmap = CPU_MASK_NONE;

static inline void crash_enable_local_vmclear(int cpu)
{
	cpumask_set_cpu(cpu, &crash_vmclear_enabled_bitmap);
}

static inline void crash_disable_local_vmclear(int cpu)
{
	cpumask_clear_cpu(cpu, &crash_vmclear_enabled_bitmap);
}

static inline int crash_local_vmclear_enabled(int cpu)
{
	return cpumask_test_cpu(cpu, &crash_vmclear_enabled_bitmap);
}

static void crash_vmclear_local_loaded_vmcss(void)
{
	int cpu = raw_smp_processor_id();
	struct vcpu_vmx *vmx;

	if (!crash_local_vmclear_enabled(cpu))
		return;

	list_for_each_entry(vmx, &per_cpu(vcpus_on_cpu, cpu),
			    local_vcpus_link)
		vmcs_clear(vmx->vmcs);
}
#else
static inline void crash_enable_local_vmclear(int cpu) { }
static inline void crash_disable_local_vmclear(int cpu) { }
#endif /* CONFIG_KEXEC */

static void __vcpu_clear(void *arg)
{
	struct vcpu_vmx *vmx = arg;
	int cpu = raw_smp_processor_id();

	if (vmx->vcpu.cpu == cpu)
		vmcs_clear(vmx->vmcs);
	if (per_cpu(current_vmcs, cpu) == vmx->vmcs)
		per_cpu(current_vmcs, cpu) = NULL;
	crash_disable_local_vmclear(cpu);
	list_del(&vmx->local_vcpus_link);
	vmx->vcpu.cpu = -1;
	vmx->launched = 0;
	crash_enable_local_vmclear(cpu);
}

static void vcpu_clear(struct vcpu_vmx *vmx)
{
	if (vmx->vcpu.cpu == -1)
		return;
	smp_call_function_single(vmx->vcpu.cpu, __vcpu_clear, vmx, 1);
}

static inline void vpid_sync_vcpu_all(struct vcpu_vmx *vmx)
{
	if (vmx->vpid == 0)
		return;

	__invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vmx->vpid, 0);
}

static inline void ept_sync_global(void)
{
	if (cpu_has_vmx_invept_global())
		__invept(VMX_EPT_EXTENT_GLOBAL, 0, 0);
}

static inline void ept_sync_context(u64 eptp)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_context())
			__invept(VMX_EPT_EXTENT_CONTEXT, eptp, 0);
		else
			ept_sync_global();
	}
}

static inline void ept_sync_individual_addr(u64 eptp, gpa_t gpa)
{
	if (enable_ept) {
		if (cpu_has_vmx_invept_individual_addr())
			__invept(VMX_EPT_EXTENT_INDIVIDUAL_ADDR,
					eptp, gpa);
		else
			ept_sync_context(eptp);
	}
}

static unsigned long vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (__ex(ASM_VMX_VMREAD_RDX_RAX)
		      : "=a"(value) : "d"(field) : "cc");
	return value;
}

static u16 vmcs_read16(unsigned long field)
{
	return vmcs_readl(field);
}

static u32 vmcs_read32(unsigned long field)
{
	return vmcs_readl(field);
}

static u64 vmcs_read64(unsigned long field)
{
#ifdef CONFIG_X86_64
	return vmcs_readl(field);
#else
	return vmcs_readl(field) | ((u64)vmcs_readl(field+1) << 32);
#endif
}

static noinline void vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "vmwrite error: reg %lx value %lx (err %d)\n",
	       field, value, vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

static void vmcs_writel(unsigned long field, unsigned long value)
{
	u8 error;

	asm volatile (__ex(ASM_VMX_VMWRITE_RAX_RDX) "; setna %0"
		       : "=q"(error) : "a"(value), "d"(field) : "cc");
	if (unlikely(error))
		vmwrite_error(field, value);
}

static void vmcs_write16(unsigned long field, u16 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write32(unsigned long field, u32 value)
{
	vmcs_writel(field, value);
}

static void vmcs_write64(unsigned long field, u64 value)
{
	vmcs_writel(field, value);
#ifndef CONFIG_X86_64
	asm volatile ("");
	vmcs_writel(field+1, value >> 32);
#endif
}

static void vmcs_clear_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) & ~mask);
}

static void vmcs_set_bits(unsigned long field, u32 mask)
{
	vmcs_writel(field, vmcs_readl(field) | mask);
}

static void update_exception_bitmap(struct kvm_vcpu *vcpu)
{
	u32 eb;

	eb = (1u << PF_VECTOR) | (1u << UD_VECTOR) | (1u << MC_VECTOR)
		| (1u << NM_VECTOR) | (1u << AC_VECTOR);
	/*
	 * Unconditionally intercept #DB so we can maintain dr6 without
	 * reading it every exit.
	 */
	eb |= 1u << DB_VECTOR;
	if (vcpu->guest_debug & KVM_GUESTDBG_ENABLE) {
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			eb |= 1u << BP_VECTOR;
	}
	if (to_vmx(vcpu)->rmode.vm86_active)
		eb = ~0;
	if (enable_ept)
		eb &= ~(1u << PF_VECTOR); /* bypass_guest_pf = 0 */
	if (vcpu->fpu_active)
		eb &= ~(1u << NM_VECTOR);
	vmcs_write32(EXCEPTION_BITMAP, eb);
}

static void clear_atomic_switch_msr_special(unsigned long entry,
		unsigned long exit)
{
	vmcs_clear_bits(VM_ENTRY_CONTROLS, entry);
	vmcs_clear_bits(VM_EXIT_CONTROLS, exit);
}

static int find_msr(struct vmx_msrs *m, unsigned int msr)
{
	unsigned int i;

	for (i = 0; i < m->nr; ++i) {
		if (m->val[i].index == msr)
			return i;
	}
	return -ENOENT;
}

static void clear_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr)
{
	int i;
	struct msr_autoload *m = &vmx->msr_autoload;

	switch (msr) {
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (cpu_has_load_perf_global_ctrl) {
			clear_atomic_switch_msr_special(
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);
			return;
		}
		break;
	}
	i = find_msr(&m->guest, msr);
	if (i < 0)
		goto skip_guest;
	--m->guest.nr;
	m->guest.val[i] = m->guest.val[m->guest.nr];
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->guest.nr);

skip_guest:
	i = find_msr(&m->host, msr);
	if (i < 0)
		return;

	--m->host.nr;
	m->host.val[i] = m->host.val[m->host.nr];
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->host.nr);
}

static void add_atomic_switch_msr_special(unsigned long entry,
		unsigned long exit, unsigned long guest_val_vmcs,
		unsigned long host_val_vmcs, u64 guest_val, u64 host_val)
{
	vmcs_write64(guest_val_vmcs, guest_val);
	vmcs_write64(host_val_vmcs, host_val);
	vmcs_set_bits(VM_ENTRY_CONTROLS, entry);
	vmcs_set_bits(VM_EXIT_CONTROLS, exit);
}

static void add_atomic_switch_msr(struct vcpu_vmx *vmx, unsigned msr,
				  u64 guest_val, u64 host_val, bool entry_only)
{
	int i, j = 0;
	struct msr_autoload *m = &vmx->msr_autoload;

	switch (msr) {
	case MSR_CORE_PERF_GLOBAL_CTRL:
		if (cpu_has_load_perf_global_ctrl) {
			add_atomic_switch_msr_special(
					VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL,
					VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL,
					GUEST_IA32_PERF_GLOBAL_CTRL,
					HOST_IA32_PERF_GLOBAL_CTRL,
					guest_val, host_val);
			return;
		}
		break;
	}

	i = find_msr(&m->guest, msr);
	if (!entry_only)
		j = find_msr(&m->host, msr);

	if (i == NR_AUTOLOAD_MSRS || j == NR_AUTOLOAD_MSRS) {
		printk_once(KERN_WARNING "Not enough mst switch entries. "
				"Can't add msr %x\n", msr);
		return;
	}
	if (i < 0) {
		i = m->guest.nr++;
		vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, m->guest.nr);
	}
	m->guest.val[i].index = msr;
	m->guest.val[i].value = guest_val;

	if (entry_only)
		return;

	if (j < 0) {
		j = m->host.nr++;
		vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, m->host.nr);
	}

	m->guest.val[i].index = msr;
	m->guest.val[i].value = guest_val;
	m->host.val[j].index = msr;
	m->host.val[j].value = host_val;
}

static void reload_tss(void)
{
	/*
	 * VT restores TR but not its size.  Useless.
	 */
	struct descriptor_table gdt;
	struct desc_struct *descs;

	kvm_get_gdt(&gdt);
	descs = (void *)gdt.base;
	descs[GDT_ENTRY_TSS].type = 9; /* available TSS */
	load_TR_desc();
}

static bool update_transition_efer(struct vcpu_vmx *vmx)
{
	int efer_offset = vmx->msr_offset_efer;
	u64 guest_efer;
	u64 ignore_bits;

	if (efer_offset < 0)
		return false;
	guest_efer = vmx->vcpu.arch.shadow_efer;

	/*
	 * NX is emulated; LMA and LME handled by hardware; SCE meaninless
	 * outside long mode
	 */
	ignore_bits = EFER_NX | EFER_SCE;
#ifdef CONFIG_X86_64
	ignore_bits |= EFER_LMA | EFER_LME;
	/* SCE is meaningful only in long mode on Intel */
	if (guest_efer & EFER_LMA)
		ignore_bits &= ~(u64)EFER_SCE;
#endif
	guest_efer &= ~ignore_bits;
	guest_efer |= host_efer & ignore_bits;
	vmx->guest_msrs[efer_offset].data = guest_efer;
	vmx->guest_msrs[efer_offset].mask = ~ignore_bits;
	return true;
}

static void vmx_save_host_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int i;

	if (vmx->host_state.loaded)
		return;

	vmx->host_state.loaded = 1;
	/*
	 * Set host fs and gs selectors.  Unfortunately, 22.2.3 does not
	 * allow segment selectors with cpl > 0 or ti == 1.
	 */
	vmx->host_state.ldt_sel = kvm_read_ldt();
	vmx->host_state.gs_ldt_reload_needed = vmx->host_state.ldt_sel;
	savesegment(fs, vmx->host_state.fs_sel);
	if (!(vmx->host_state.fs_sel & 7)) {
		vmcs_write16(HOST_FS_SELECTOR, vmx->host_state.fs_sel);
		vmx->host_state.fs_reload_needed = 0;
	} else {
		vmcs_write16(HOST_FS_SELECTOR, 0);
		vmx->host_state.fs_reload_needed = 1;
	}
	savesegment(gs, vmx->host_state.gs_sel);
	if (!(vmx->host_state.gs_sel & 7))
		vmcs_write16(HOST_GS_SELECTOR, vmx->host_state.gs_sel);
	else {
		vmcs_write16(HOST_GS_SELECTOR, 0);
		vmx->host_state.gs_ldt_reload_needed = 1;
	}

#ifdef CONFIG_X86_64
	vmcs_writel(HOST_FS_BASE, read_msr(MSR_FS_BASE));
	vmcs_writel(HOST_GS_BASE, read_msr(MSR_GS_BASE));
#else
	vmcs_writel(HOST_FS_BASE, segment_base(vmx->host_state.fs_sel));
	vmcs_writel(HOST_GS_BASE, segment_base(vmx->host_state.gs_sel));
#endif

#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
	}
#endif
	for (i = 0; i < vmx->save_nmsrs; ++i)
		kvm_set_shared_msr(vmx->guest_msrs[i].index,
				   vmx->guest_msrs[i].data,
				   vmx->guest_msrs[i].mask);
}

static void __vmx_load_host_state(struct vcpu_vmx *vmx)
{
	if (!vmx->host_state.loaded)
		return;

	++vmx->vcpu.stat.host_state_reload;
	vmx->host_state.loaded = 0;
	if (vmx->host_state.fs_reload_needed)
		loadsegment(fs, vmx->host_state.fs_sel);
	if (vmx->host_state.gs_ldt_reload_needed) {
		kvm_load_ldt(vmx->host_state.ldt_sel);
#ifdef CONFIG_X86_64
		load_gs_index(vmx->host_state.gs_sel);
		wrmsrl(MSR_KERNEL_GS_BASE, current->thread.gs);
#else
		loadsegment(gs, vmx->host_state.gs_sel);
#endif
	}
	reload_tss();
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		rdmsrl(MSR_KERNEL_GS_BASE, vmx->msr_guest_kernel_gs_base);
		wrmsrl(MSR_KERNEL_GS_BASE, vmx->msr_host_kernel_gs_base);
	}
#endif
	load_gdt(&__get_cpu_var(host_gdt));
}

static void vmx_load_host_state(struct vcpu_vmx *vmx)
{
	preempt_disable();
	__vmx_load_host_state(vmx);
	preempt_enable();
}

/*
 * Switches to specified vcpu, until a matching vcpu_put(), but assumes
 * vcpu mutex is already taken.
 */
static void vmx_vcpu_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));

	if (!vmm_exclusive)
		kvm_cpu_vmxon(phys_addr);
	else if (vcpu->cpu != cpu)
		vcpu_clear(vmx);

	if (per_cpu(current_vmcs, cpu) != vmx->vmcs) {
		per_cpu(current_vmcs, cpu) = vmx->vmcs;
		vmcs_load(vmx->vmcs);
		spec_ctrl_ibpb();
	}

	if (vcpu->cpu != cpu) {
		struct descriptor_table dt;
		unsigned long sysenter_esp;

		set_bit(KVM_REQ_TLB_FLUSH, &vcpu->requests);
		local_irq_disable();
		crash_disable_local_vmclear(cpu);
		list_add(&vmx->local_vcpus_link,
			 &per_cpu(vcpus_on_cpu, cpu));
		crash_enable_local_vmclear(cpu);
		local_irq_enable();

		/*
		 * Linux uses per-cpu TSS and GDT, so set these when switching
		 * processors.
		 */
		vmcs_writel(HOST_TR_BASE, kvm_read_tr_base()); /* 22.2.4 */
		kvm_get_gdt(&dt);
		vmcs_writel(HOST_GDTR_BASE, dt.base);   /* 22.2.4 */

		rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
		vmcs_writel(HOST_IA32_SYSENTER_ESP, sysenter_esp); /* 22.2.3 */
	}
}

static void vmx_vcpu_put(struct kvm_vcpu *vcpu)
{
	__vmx_load_host_state(to_vmx(vcpu));
	if (!vmm_exclusive) {
		__vcpu_clear(to_vmx(vcpu));
		kvm_cpu_vmxoff();
	}
}

static void vmx_fpu_activate(struct kvm_vcpu *vcpu)
{
	if (vcpu->fpu_active)
		return;
	vcpu->fpu_active = 1;
	vmcs_clear_bits(GUEST_CR0, X86_CR0_TS);
	if (kvm_read_cr0_bits(vcpu, X86_CR0_TS))
		vmcs_set_bits(GUEST_CR0, X86_CR0_TS);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = X86_CR0_TS;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu);

static void vmx_fpu_deactivate(struct kvm_vcpu *vcpu)
{
	vmx_decache_cr0_guest_bits(vcpu);
	vmcs_set_bits(GUEST_CR0, X86_CR0_TS);
	update_exception_bitmap(vcpu);
	vcpu->arch.cr0_guest_owned_bits = 0;
	vmcs_writel(CR0_GUEST_HOST_MASK, ~vcpu->arch.cr0_guest_owned_bits);
	vmcs_writel(CR0_READ_SHADOW, vcpu->arch.cr0);
}

static unsigned long vmx_get_rflags(struct kvm_vcpu *vcpu)
{
	unsigned long rflags, save_rflags;

	rflags = vmcs_readl(GUEST_RFLAGS);
	if (to_vmx(vcpu)->rmode.vm86_active) {
		rflags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
		save_rflags = to_vmx(vcpu)->rmode.save_rflags;
		rflags |= save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	}
	return rflags;
}

static void vmx_set_rflags(struct kvm_vcpu *vcpu, unsigned long rflags)
{
	if (to_vmx(vcpu)->rmode.vm86_active) {
		to_vmx(vcpu)->rmode.save_rflags = rflags;
		rflags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;
	}
	vmcs_writel(GUEST_RFLAGS, rflags);
}

static u32 vmx_get_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	int ret = 0;

	if (interruptibility & GUEST_INTR_STATE_STI)
		ret |= X86_SHADOW_INT_STI;
	if (interruptibility & GUEST_INTR_STATE_MOV_SS)
		ret |= X86_SHADOW_INT_MOV_SS;

	return ret & mask;
}

static void vmx_set_interrupt_shadow(struct kvm_vcpu *vcpu, int mask)
{
	u32 interruptibility_old = vmcs_read32(GUEST_INTERRUPTIBILITY_INFO);
	u32 interruptibility = interruptibility_old;

	interruptibility &= ~(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS);

	if (mask & X86_SHADOW_INT_MOV_SS)
		interruptibility |= GUEST_INTR_STATE_MOV_SS;
	if (mask & X86_SHADOW_INT_STI)
		interruptibility |= GUEST_INTR_STATE_STI;

	if ((interruptibility != interruptibility_old))
		vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, interruptibility);
}

static void skip_emulated_instruction(struct kvm_vcpu *vcpu)
{
	unsigned long rip;

	rip = kvm_rip_read(vcpu);
	rip += vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	kvm_rip_write(vcpu, rip);

	/* skipping an emulated instruction also counts */
	vmx_set_interrupt_shadow(vcpu, 0);
}

static void vmx_clear_hlt(struct kvm_vcpu *vcpu)
{
	/* Ensure that we clear the HLT state in the VMCS.  We don't need to
	 * explicitly skip the instruction because if the HLT state is set, then
	 * the instruction is already executing and RIP has already been
	 * advanced. */
	if (!yield_on_hlt &&
	    vmcs_read32(GUEST_ACTIVITY_STATE) == GUEST_ACTIVITY_HLT)
		vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
}

static void vmx_queue_exception(struct kvm_vcpu *vcpu, unsigned nr,
				bool has_error_code, u32 error_code)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 intr_info = nr | INTR_INFO_VALID_MASK;

	if (has_error_code) {
		vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
		intr_info |= INTR_INFO_DELIVER_CODE_MASK;
	}

	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = true;
		vmx->rmode.irq.vector = nr;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		if (kvm_exception_is_soft(nr))
			vmx->rmode.irq.rip +=
				vmx->vcpu.arch.event_exit_inst_len;
		intr_info |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}

	if (kvm_exception_is_soft(nr)) {
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
		intr_info |= INTR_TYPE_SOFT_EXCEPTION;
	} else
		intr_info |= INTR_TYPE_HARD_EXCEPTION;

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr_info);
	vmx_clear_hlt(vcpu);
}

/*
 * Swap MSR entry in host/guest MSR entry array.
 */
static void move_msr_up(struct vcpu_vmx *vmx, int from, int to)
{
	struct shared_msr_entry tmp;

	tmp = vmx->guest_msrs[to];
	vmx->guest_msrs[to] = vmx->guest_msrs[from];
	vmx->guest_msrs[from] = tmp;
}

/*
 * Set up the vmcs to automatically save and restore system
 * msrs.  Don't touch the 64-bit msrs if the guest is in legacy
 * mode, as fiddling with msrs is very expensive.
 */
static void setup_msrs(struct vcpu_vmx *vmx)
{
	int save_nmsrs, index;
	unsigned long *msr_bitmap;

	vmx_load_host_state(vmx);
	save_nmsrs = 0;
#ifdef CONFIG_X86_64
	if (is_long_mode(&vmx->vcpu)) {
		index = __find_msr_index(vmx, MSR_SYSCALL_MASK);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_LSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		index = __find_msr_index(vmx, MSR_CSTAR);
		if (index >= 0)
			move_msr_up(vmx, index, save_nmsrs++);
		/*
		 * MSR_K6_STAR is only needed on long mode guests, and only
		 * if efer.sce is enabled.
		 */
		index = __find_msr_index(vmx, MSR_K6_STAR);
		if ((index >= 0) && (vmx->vcpu.arch.shadow_efer & EFER_SCE))
			move_msr_up(vmx, index, save_nmsrs++);
	}
#endif
	vmx->msr_offset_efer = index = __find_msr_index(vmx, MSR_EFER);
	if (index >= 0 && update_transition_efer(vmx))
		move_msr_up(vmx, index, save_nmsrs++);

	vmx->save_nmsrs = save_nmsrs;

	if (cpu_has_vmx_msr_bitmap()) {
		if (is_long_mode(&vmx->vcpu))
			msr_bitmap = vmx_msr_bitmap_longmode;
		else
			msr_bitmap = vmx_msr_bitmap_legacy;

		vmcs_write64(MSR_BITMAP, __pa(msr_bitmap));
	}
}

/*
 * reads and returns guest's timestamp counter "register"
 * guest_tsc = host_tsc + tsc_offset    -- 21.3
 */
static u64 guest_read_tsc(void)
{
	u64 host_tsc, tsc_offset;

	rdtscll(host_tsc);
	tsc_offset = vmcs_read64(TSC_OFFSET);
	return host_tsc + tsc_offset;
}

/*
 * Empty call-back. Needs to be implemented when VMX enables the SET_TSC_KHZ
 * ioctl. In this case the call-back should update internal vmx state to make
 * the changes effective.
 */
static void vmx_set_tsc_khz(struct kvm_vcpu *vcpu, u32 user_tsc_khz)
{
	/* Nothing to do here */
}

/*
 * writes 'offset' into guest's timestamp counter offset register
 */
static void vmx_write_tsc_offset(struct kvm_vcpu *vcpu, u64 offset)
{
	trace_kvm_write_tsc_offset(vcpu->vcpu_id, vmcs_read64(TSC_OFFSET),
				   offset);
	vmcs_write64(TSC_OFFSET, offset);
}

static void vmx_adjust_tsc_offset(struct kvm_vcpu *vcpu, s64 adjustment, bool host)
{
	u64 offset = vmcs_read64(TSC_OFFSET);
	vmcs_write64(TSC_OFFSET, offset + adjustment);

	trace_kvm_write_tsc_offset(vcpu->vcpu_id, offset,
				   offset + adjustment);
}

static u64 vmx_compute_tsc_offset(struct kvm_vcpu *vcpu, u64 target_tsc)
{
	return target_tsc - native_read_tsc();
}

/*
 * Reads an msr value (of 'msr_index') into 'pdata'.
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_get_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct shared_msr_entry *msr;

	switch (msr_info->index) {
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		msr_info->data = vmcs_readl(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		msr_info->data = vmcs_readl(GUEST_GS_BASE);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(to_vmx(vcpu));
		msr_info->data = to_vmx(vcpu)->msr_guest_kernel_gs_base;
		break;
#endif
	case MSR_EFER:
		return kvm_get_msr_common(vcpu, msr_info);
	case MSR_IA32_TSC:
		msr_info->data = guest_read_tsc();
		break;
	case MSR_IA32_SPEC_CTRL:
		msr_info->data = to_vmx(vcpu)->spec_ctrl;
		break;
	case MSR_IA32_ARCH_CAPABILITIES:
		msr_info->data = to_vmx(vcpu)->arch_capabilities;
		break;
	case MSR_IA32_SYSENTER_CS:
		msr_info->data = vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_EIP:
		msr_info->data = vmcs_readl(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_SYSENTER_ESP:
		msr_info->data = vmcs_readl(GUEST_SYSENTER_ESP);
		break;
	default:
		vmx_load_host_state(to_vmx(vcpu));
		msr = find_msr_entry(to_vmx(vcpu), msr_info->index);
		if (msr) {
			vmx_load_host_state(to_vmx(vcpu));
			msr_info->data = msr->data;
			break;
		}
		return kvm_get_msr_common(vcpu, msr_info);
	}

	return 0;
}

/*
 * Writes msr value into into the appropriate "register".
 * Returns 0 on success, non-0 otherwise.
 * Assumes vcpu_load() was already called.
 */
static int vmx_set_msr(struct kvm_vcpu *vcpu, struct msr_data *msr_info)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr;
	int ret = 0;
	u32 msr_index = msr_info->index;
	u64 data = msr_info->data;

	switch (msr_index) {
	case MSR_EFER:
		vmx_load_host_state(vmx);
		ret = kvm_set_msr_common(vcpu, msr_info);
		break;
#ifdef CONFIG_X86_64
	case MSR_FS_BASE:
		vmcs_writel(GUEST_FS_BASE, data);
		break;
	case MSR_GS_BASE:
		vmcs_writel(GUEST_GS_BASE, data);
		break;
	case MSR_KERNEL_GS_BASE:
		vmx_load_host_state(vmx);
		vmx->msr_guest_kernel_gs_base = data;
		break;
#endif
	case MSR_IA32_SYSENTER_CS:
		vmcs_write32(GUEST_SYSENTER_CS, data);
		break;
	case MSR_IA32_SYSENTER_EIP:
		vmcs_writel(GUEST_SYSENTER_EIP, data);
		break;
	case MSR_IA32_SYSENTER_ESP:
		vmcs_writel(GUEST_SYSENTER_ESP, data);
		break;
	case MSR_IA32_TSC:
		kvm_write_tsc(vcpu, msr_info);
		break;
	case MSR_IA32_SPEC_CTRL:
		to_vmx(vcpu)->spec_ctrl = msr_info->data;
		break;
	case MSR_IA32_ARCH_CAPABILITIES:
		vmx->arch_capabilities = data;
		break;
	case MSR_IA32_CR_PAT:
		if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
			vmcs_write64(GUEST_IA32_PAT, data);
			vcpu->arch.pat = data;
			break;
		}
		/* Otherwise falls through to kvm_set_msr_common */
	default:
		msr = find_msr_entry(vmx, msr_index);
		if (msr) {
			vmx_load_host_state(vmx);
			msr->data = data;
			break;
		}
		ret = kvm_set_msr_common(vcpu, msr_info);
	}

	return ret;
}

static void vmx_cache_reg(struct kvm_vcpu *vcpu, enum kvm_reg reg)
{
	__set_bit(reg, (unsigned long *)&vcpu->arch.regs_avail);
	switch (reg) {
	case VCPU_REGS_RSP:
		vcpu->arch.regs[VCPU_REGS_RSP] = vmcs_readl(GUEST_RSP);
		break;
	case VCPU_REGS_RIP:
		vcpu->arch.regs[VCPU_REGS_RIP] = vmcs_readl(GUEST_RIP);
		break;
	case VCPU_EXREG_PDPTR:
		if (enable_ept)
			ept_save_pdptrs(vcpu);
		break;
	default:
		break;
	}
}

static int set_guest_debug(struct kvm_vcpu *vcpu, struct kvm_guest_debug *dbg)
{
	int old_debug = vcpu->guest_debug;
	unsigned long flags;

	vcpu->guest_debug = dbg->control;
	if (!(vcpu->guest_debug & KVM_GUESTDBG_ENABLE))
		vcpu->guest_debug = 0;

	if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)
		vmcs_writel(GUEST_DR7, dbg->arch.debugreg[7]);
	else
		vmcs_writel(GUEST_DR7, vcpu->arch.dr7);

	flags = vmcs_readl(GUEST_RFLAGS);
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		flags |= X86_EFLAGS_TF | X86_EFLAGS_RF;
	else if (old_debug & KVM_GUESTDBG_SINGLESTEP)
		flags &= ~(X86_EFLAGS_TF | X86_EFLAGS_RF);
	vmcs_writel(GUEST_RFLAGS, flags);

	update_exception_bitmap(vcpu);

	return 0;
}

static __init int cpu_has_kvm_support(void)
{
	return cpu_has_vmx();
}

static __init int vmx_disabled_by_bios(void)
{
	u64 msr;

	rdmsrl(MSR_IA32_FEATURE_CONTROL, msr);
	if (msr & FEATURE_CONTROL_LOCKED) {
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX)
			&& tboot_enabled())
			return 1;
		if (!(msr & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX)
			&& !tboot_enabled())
			return 1;
	}

	return 0;
	/* locked but not enabled */
}

static void kvm_cpu_vmxon(u64 addr)
{
	asm volatile (ASM_VMX_VMXON_RAX
			: : "a"(&addr), "m"(addr)
			: "memory", "cc");
}

static int hardware_enable(void *garbage)
{
	int cpu = raw_smp_processor_id();
	u64 phys_addr = __pa(per_cpu(vmxarea, cpu));
	u64 old, test_bits;

	if (read_cr4() & X86_CR4_VMXE)
		return -EBUSY;

	INIT_LIST_HEAD(&per_cpu(vcpus_on_cpu, cpu));

	/*
	 * Now we can enable the vmclear operation in kdump
	 * since the vcpus_on_cpu list on this cpu
	 * has been initialized.
	 *
	 * Though the cpu is not in VMX operation now, there
	 * is no problem to enable the vmclear operation
	 * for the vcpus_on_cpu list is empty!
	 */
	crash_enable_local_vmclear(cpu);

	rdmsrl(MSR_IA32_FEATURE_CONTROL, old);

	test_bits = FEATURE_CONTROL_LOCKED;
	test_bits |= FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX;
	if (tboot_enabled())
		test_bits |= FEATURE_CONTROL_VMXON_ENABLED_INSIDE_SMX;

	if ((old & test_bits) != test_bits) {
		/* enable and lock */
		wrmsrl(MSR_IA32_FEATURE_CONTROL, old | test_bits);
	}
	write_cr4(read_cr4() | X86_CR4_VMXE); /* FIXME: not cpu hotplug safe */

	if (vmm_exclusive) {
		kvm_cpu_vmxon(phys_addr);
		ept_sync_global();
	}

	store_gdt(&__get_cpu_var(host_gdt));

	return 0;
}

static void vmclear_local_vcpus(void)
{
	int cpu = raw_smp_processor_id();
	struct vcpu_vmx *vmx, *n;

	list_for_each_entry_safe(vmx, n, &per_cpu(vcpus_on_cpu, cpu),
				 local_vcpus_link)
		__vcpu_clear(vmx);
}

/* Just like cpu_vmxoff(), but with the __kvm_handle_fault_on_reboot()
 * tricks.
 */
static void kvm_cpu_vmxoff(void)
{
	asm volatile (__ex(ASM_VMX_VMXOFF) : : : "cc");
}

static void hardware_disable(void *garbage)
{
	if (vmm_exclusive) {
		vmclear_local_vcpus();
		kvm_cpu_vmxoff();
	}
	write_cr4(read_cr4() & ~X86_CR4_VMXE);
}

static __init int adjust_vmx_controls(u32 ctl_min, u32 ctl_opt,
				      u32 msr, u32 *result)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 ctl = ctl_min | ctl_opt;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);

	ctl &= vmx_msr_high; /* bit == 0 in high word ==> must be zero */
	ctl |= vmx_msr_low;  /* bit == 1 in low word  ==> must be one  */

	/* Ensure minimum (required) set of control bits are supported. */
	if (ctl_min & ~ctl)
		return -EIO;

	*result = ctl;
	return 0;
}

static __init bool allow_1_setting(u32 msr, u32 ctl)
{
	u32 vmx_msr_low, vmx_msr_high;

	rdmsr(msr, vmx_msr_low, vmx_msr_high);
	return vmx_msr_high & ctl;
}

static __init int setup_vmcs_config(struct vmcs_config *vmcs_conf)
{
	u32 vmx_msr_low, vmx_msr_high;
	u32 min, opt, min2, opt2;
	u32 _pin_based_exec_control = 0;
	u32 _cpu_based_exec_control = 0;
	u32 _cpu_based_2nd_exec_control = 0;
	u32 _vmexit_control = 0;
	u32 _vmentry_control = 0;

	min = PIN_BASED_EXT_INTR_MASK | PIN_BASED_NMI_EXITING;
	opt = PIN_BASED_VIRTUAL_NMIS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PINBASED_CTLS,
				&_pin_based_exec_control) < 0)
		return -EIO;

	min =
#ifdef CONFIG_X86_64
	      CPU_BASED_CR8_LOAD_EXITING |
	      CPU_BASED_CR8_STORE_EXITING |
#endif
	      CPU_BASED_CR3_LOAD_EXITING |
	      CPU_BASED_CR3_STORE_EXITING |
	      CPU_BASED_USE_IO_BITMAPS |
	      CPU_BASED_MOV_DR_EXITING |
	      CPU_BASED_USE_TSC_OFFSETING |
	      CPU_BASED_INVLPG_EXITING |
	      CPU_BASED_RDPMC_EXITING;

	if (yield_on_hlt)
		min |= CPU_BASED_HLT_EXITING;

	opt = CPU_BASED_TPR_SHADOW |
	      CPU_BASED_USE_MSR_BITMAPS |
	      CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_PROCBASED_CTLS,
				&_cpu_based_exec_control) < 0)
		return -EIO;
#ifdef CONFIG_X86_64
	if ((_cpu_based_exec_control & CPU_BASED_TPR_SHADOW))
		_cpu_based_exec_control &= ~CPU_BASED_CR8_LOAD_EXITING &
					   ~CPU_BASED_CR8_STORE_EXITING;
#endif
	if (_cpu_based_exec_control & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS) {
		min2 = 0;
		opt2 = SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES |
			SECONDARY_EXEC_WBINVD_EXITING |
			SECONDARY_EXEC_ENABLE_VPID |
			SECONDARY_EXEC_ENABLE_EPT |
			SECONDARY_EXEC_UNRESTRICTED_GUEST |
			SECONDARY_EXEC_PAUSE_LOOP_EXITING |
			SECONDARY_EXEC_ENABLE_INVPCID;
		if (adjust_vmx_controls(min2, opt2,
					MSR_IA32_VMX_PROCBASED_CTLS2,
					&_cpu_based_2nd_exec_control) < 0)
			return -EIO;
	}
#ifndef CONFIG_X86_64
	if (!(_cpu_based_2nd_exec_control &
				SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES))
		_cpu_based_exec_control &= ~CPU_BASED_TPR_SHADOW;
#endif
	if (_cpu_based_2nd_exec_control & SECONDARY_EXEC_ENABLE_EPT) {
		/* CR3 accesses and invlpg don't need to cause VM Exits when EPT
		   enabled */
		_cpu_based_exec_control &= ~(CPU_BASED_CR3_LOAD_EXITING |
					     CPU_BASED_CR3_STORE_EXITING |
					     CPU_BASED_INVLPG_EXITING);
		rdmsr(MSR_IA32_VMX_EPT_VPID_CAP,
		      vmx_capability.ept, vmx_capability.vpid);
	}

	min = 0;
#ifdef CONFIG_X86_64
	min |= VM_EXIT_HOST_ADDR_SPACE_SIZE;
#endif
	opt = VM_EXIT_SAVE_IA32_PAT | VM_EXIT_LOAD_IA32_PAT |
		VM_EXIT_ACK_INTR_ON_EXIT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_EXIT_CTLS,
				&_vmexit_control) < 0)
		return -EIO;

	min = 0;
	opt = VM_ENTRY_LOAD_IA32_PAT;
	if (adjust_vmx_controls(min, opt, MSR_IA32_VMX_ENTRY_CTLS,
				&_vmentry_control) < 0)
		return -EIO;

	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	/* IA-32 SDM Vol 3B: VMCS size is never greater than 4kB. */
	if ((vmx_msr_high & 0x1fff) > PAGE_SIZE)
		return -EIO;

#ifdef CONFIG_X86_64
	/* IA-32 SDM Vol 3B: 64-bit CPUs always have VMX_BASIC_MSR[48]==0. */
	if (vmx_msr_high & (1u<<16))
		return -EIO;
#endif

	/* Require Write-Back (WB) memory type for VMCS accesses. */
	if (((vmx_msr_high >> 18) & 15) != 6)
		return -EIO;

	vmcs_conf->size = vmx_msr_high & 0x1fff;
	vmcs_conf->order = get_order(vmcs_config.size);
	vmcs_conf->revision_id = vmx_msr_low;

	vmcs_conf->pin_based_exec_ctrl = _pin_based_exec_control;
	vmcs_conf->cpu_based_exec_ctrl = _cpu_based_exec_control;
	vmcs_conf->cpu_based_2nd_exec_ctrl = _cpu_based_2nd_exec_control;
	vmcs_conf->vmexit_ctrl         = _vmexit_control;
	vmcs_conf->vmentry_ctrl        = _vmentry_control;

	cpu_has_load_perf_global_ctrl =
		allow_1_setting(MSR_IA32_VMX_ENTRY_CTLS,
				VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		&& allow_1_setting(MSR_IA32_VMX_EXIT_CTLS,
				   VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL);

	/*
	 * Some cpus support VM_ENTRY_(LOAD|SAVE)_IA32_PERF_GLOBAL_CTRL
	 * but due to arrata below it can't be used. Workaround is to use
	 * msr load mechanism to switch IA32_PERF_GLOBAL_CTRL.
	 *
	 * VM Exit May Incorrectly Clear IA32_PERF_GLOBAL_CTRL [34:32]
	 *
	 * AAK155             (model 26)
	 * AAP115             (model 30)
	 * AAT100             (model 37)
	 * BC86,AAY89,BD102   (model 44)
	 * BA97               (model 46)
	 *
	 */
	if (cpu_has_load_perf_global_ctrl && boot_cpu_data.x86 == 0x6) {
		switch (boot_cpu_data.x86_model) {
		case 26:
		case 30:
		case 37:
		case 44:
		case 46:
			cpu_has_load_perf_global_ctrl = false;
			printk_once(KERN_WARNING"kvm: VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL "
					"does not work properly. Using workaround\n");
			break;
		default:
			break;
		}
	}

	return 0;
}

static struct vmcs *alloc_vmcs_cpu(int cpu)
{
	int node = cpu_to_node(cpu);
	struct page *pages;
	struct vmcs *vmcs;

	pages = alloc_pages_exact_node(node, GFP_KERNEL, vmcs_config.order);
	if (!pages)
		return NULL;
	vmcs = page_address(pages);
	memset(vmcs, 0, vmcs_config.size);
	vmcs->revision_id = vmcs_config.revision_id; /* vmcs revision id */
	return vmcs;
}

static struct vmcs *alloc_vmcs(void)
{
	return alloc_vmcs_cpu(raw_smp_processor_id());
}

static void free_vmcs(struct vmcs *vmcs)
{
	free_pages((unsigned long)vmcs, vmcs_config.order);
}

static void free_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		free_vmcs(per_cpu(vmxarea, cpu));
		per_cpu(vmxarea, cpu) = NULL;
	}
}

static __init int alloc_kvm_area(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct vmcs *vmcs;

		vmcs = alloc_vmcs_cpu(cpu);
		if (!vmcs) {
			free_kvm_area();
			return -ENOMEM;
		}

		per_cpu(vmxarea, cpu) = vmcs;
	}
	return 0;
}

static __init int hardware_setup(void)
{
	if (setup_vmcs_config(&vmcs_config) < 0)
		return -EIO;

	if (boot_cpu_has(X86_FEATURE_NX))
		kvm_enable_efer_bits(EFER_NX);

	if (!cpu_has_vmx_vpid())
		enable_vpid = 0;

	if (!cpu_has_vmx_ept()) {
		enable_ept = 0;
		enable_unrestricted_guest = 0;
		enable_ept_ad_bits = 0;
	}

	if (!cpu_has_vmx_ept_ad_bits())
		enable_ept_ad_bits = 0;

	if (!cpu_has_vmx_unrestricted_guest())
		enable_unrestricted_guest = 0;

	if (!cpu_has_vmx_flexpriority())
		flexpriority_enabled = 0;

	if (!cpu_has_vmx_tpr_shadow())
		kvm_x86_ops->update_cr8_intercept = NULL;

	if (enable_ept && !cpu_has_vmx_ept_2m_page())
		kvm_disable_largepages();

	if (!cpu_has_vmx_ple())
		ple_gap = 0;

	return alloc_kvm_area();
}

static __exit void hardware_unsetup(void)
{
	free_kvm_area();
}

static void fix_pmode_dataseg(int seg, struct kvm_save_segment *save)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	if (vmcs_readl(sf->base) == save->base && (save->base & AR_S_MASK)) {
		vmcs_write16(sf->selector, save->selector);
		vmcs_writel(sf->base, save->base);
		vmcs_write32(sf->limit, save->limit);
		vmcs_write32(sf->ar_bytes, save->ar);
	} else {
		u32 dpl = (vmcs_read16(sf->selector) & SELECTOR_RPL_MASK)
			<< AR_DPL_SHIFT;
		vmcs_write32(sf->ar_bytes, 0x93 | dpl);
	}
}

static void enter_pmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	vmx->emulation_required = 1;
	vmx->rmode.vm86_active = 0;

	vmcs_write16(GUEST_TR_SELECTOR, vmx->rmode.tr.selector);
	vmcs_writel(GUEST_TR_BASE, vmx->rmode.tr.base);
	vmcs_write32(GUEST_TR_LIMIT, vmx->rmode.tr.limit);
	vmcs_write32(GUEST_TR_AR_BYTES, vmx->rmode.tr.ar);

	flags = vmcs_readl(GUEST_RFLAGS);
	flags &= RMODE_GUEST_OWNED_EFLAGS_BITS;
	flags |= vmx->rmode.save_rflags & ~RMODE_GUEST_OWNED_EFLAGS_BITS;
	vmcs_writel(GUEST_RFLAGS, flags);

	vmcs_writel(GUEST_CR4, (vmcs_readl(GUEST_CR4) & ~X86_CR4_VME) |
			(vmcs_readl(CR4_READ_SHADOW) & X86_CR4_VME));

	update_exception_bitmap(vcpu);

	if (emulate_invalid_guest_state)
		return;

	fix_pmode_dataseg(VCPU_SREG_ES, &vmx->rmode.es);
	fix_pmode_dataseg(VCPU_SREG_DS, &vmx->rmode.ds);
	fix_pmode_dataseg(VCPU_SREG_GS, &vmx->rmode.gs);
	fix_pmode_dataseg(VCPU_SREG_FS, &vmx->rmode.fs);

	vmcs_write16(GUEST_SS_SELECTOR, 0);
	vmcs_write32(GUEST_SS_AR_BYTES, 0x93);

	vmcs_write16(GUEST_CS_SELECTOR,
		     vmcs_read16(GUEST_CS_SELECTOR) & ~SELECTOR_RPL_MASK);
	vmcs_write32(GUEST_CS_AR_BYTES, 0x9b);
}

static gva_t rmode_tss_base(struct kvm *kvm)
{
	if (!kvm->arch.tss_addr) {
		struct kvm_memslots *slots;
		gfn_t base_gfn;

		slots = rcu_dereference(kvm->memslots);
		base_gfn = kvm->memslots->memslots[0].base_gfn +
				 kvm->memslots->memslots[0].npages - 3;
		return base_gfn << PAGE_SHIFT;
	}
	return kvm->arch.tss_addr;
}

static void fix_rmode_seg(int seg, struct kvm_save_segment *save)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	save->selector = vmcs_read16(sf->selector);
	save->base = vmcs_readl(sf->base);
	save->limit = vmcs_read32(sf->limit);
	save->ar = vmcs_read32(sf->ar_bytes);
	vmcs_write16(sf->selector, save->base >> 4);
	vmcs_write32(sf->base, save->base & 0xffff0);
	vmcs_write32(sf->limit, 0xffff);
	vmcs_write32(sf->ar_bytes, 0xf3);
	if (save->base & 0xf)
		printk_once(KERN_WARNING "kvm: segment base is not paragraph"
			    " aligned when entering protected mode (seg=%d)",
			    seg);
}

static void enter_rmode(struct kvm_vcpu *vcpu)
{
	unsigned long flags;
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_segment var;

	if (enable_unrestricted_guest)
		return;

	vmx->emulation_required = 1;
	vmx->rmode.vm86_active = 1;

	/*
	 * Very old userspace does not call KVM_SET_TSS_ADDR before entering
	 * vcpu. Call it here with phys address pointing 16M below 4G.
	 */
	if (!vcpu->kvm->arch.tss_addr) {
		printk_once(KERN_WARNING "kvm: KVM_SET_TSS_ADDR need to be "
			     "called before entering vcpu\n");
		srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
		vmx_set_tss_addr(vcpu->kvm, 0xfeffd000);
		vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	}

	vmx->rmode.tr.selector = vmcs_read16(GUEST_TR_SELECTOR);
	vmx->rmode.tr.base = vmcs_readl(GUEST_TR_BASE);
	vmcs_writel(GUEST_TR_BASE, rmode_tss_base(vcpu->kvm));

	vmx->rmode.tr.limit = vmcs_read32(GUEST_TR_LIMIT);
	vmcs_write32(GUEST_TR_LIMIT, RMODE_TSS_SIZE - 1);

	vmx->rmode.tr.ar = vmcs_read32(GUEST_TR_AR_BYTES);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	flags = vmcs_readl(GUEST_RFLAGS);
	vmx->rmode.save_rflags = flags;

	flags |= X86_EFLAGS_IOPL | X86_EFLAGS_VM;

	vmcs_writel(GUEST_RFLAGS, flags);
	vmcs_writel(GUEST_CR4, vmcs_readl(GUEST_CR4) | X86_CR4_VME);
	update_exception_bitmap(vcpu);

	if (emulate_invalid_guest_state)
		goto continue_rmode;

	vmx_get_segment(vcpu, &var, VCPU_SREG_SS);
	vmx_set_segment(vcpu, &var, VCPU_SREG_SS);

	vmx_get_segment(vcpu, &var, VCPU_SREG_CS);
	vmx_set_segment(vcpu, &var, VCPU_SREG_CS);

	vmx_get_segment(vcpu, &var, VCPU_SREG_ES);
	vmx_set_segment(vcpu, &var, VCPU_SREG_ES);

	vmx_get_segment(vcpu, &var, VCPU_SREG_DS);
	vmx_set_segment(vcpu, &var, VCPU_SREG_DS);

	vmx_get_segment(vcpu, &var, VCPU_SREG_GS);
	vmx_set_segment(vcpu, &var, VCPU_SREG_GS);

	vmx_get_segment(vcpu, &var, VCPU_SREG_FS);
	vmx_set_segment(vcpu, &var, VCPU_SREG_FS);

continue_rmode:
	kvm_mmu_reset_context(vcpu);
}

static void vmx_set_efer(struct kvm_vcpu *vcpu, u64 efer)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct shared_msr_entry *msr = find_msr_entry(vmx, MSR_EFER);

	if (!msr)
		return;

	/*
	 * Force kernel_gs_base reloading before EFER changes, as control
	 * of this msr depends on is_long_mode().
	 */
	vmx_load_host_state(to_vmx(vcpu));
	vcpu->arch.shadow_efer = efer;
	if (!msr)
		return;
	if (efer & EFER_LMA) {
		vmcs_write32(VM_ENTRY_CONTROLS,
			     vmcs_read32(VM_ENTRY_CONTROLS) |
			     VM_ENTRY_IA32E_MODE);
		msr->data = efer;
	} else {
		vmcs_write32(VM_ENTRY_CONTROLS,
			     vmcs_read32(VM_ENTRY_CONTROLS) &
			     ~VM_ENTRY_IA32E_MODE);

		msr->data = efer & ~EFER_LME;
	}
	setup_msrs(vmx);
}

#ifdef CONFIG_X86_64

static void enter_lmode(struct kvm_vcpu *vcpu)
{
	u32 guest_tr_ar;

	guest_tr_ar = vmcs_read32(GUEST_TR_AR_BYTES);
	if ((guest_tr_ar & AR_TYPE_MASK) != AR_TYPE_BUSY_64_TSS) {
		printk(KERN_DEBUG "%s: tss fixup for long mode. \n",
		       __func__);
		vmcs_write32(GUEST_TR_AR_BYTES,
			     (guest_tr_ar & ~AR_TYPE_MASK)
			     | AR_TYPE_BUSY_64_TSS);
	}
	vcpu->arch.shadow_efer |= EFER_LMA;
	vmx_set_efer(vcpu, vcpu->arch.shadow_efer);
}

static void exit_lmode(struct kvm_vcpu *vcpu)
{
	vcpu->arch.shadow_efer &= ~EFER_LMA;

	vmcs_write32(VM_ENTRY_CONTROLS,
		     vmcs_read32(VM_ENTRY_CONTROLS)
		     & ~VM_ENTRY_IA32E_MODE);
}

#endif

static void vmx_flush_tlb(struct kvm_vcpu *vcpu)
{
	vpid_sync_vcpu_all(to_vmx(vcpu));
	if (enable_ept)
		ept_sync_context(construct_eptp(vcpu->arch.mmu.root_hpa));
}

static void vmx_decache_cr0_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr0_guest_owned_bits = vcpu->arch.cr0_guest_owned_bits;

	vcpu->arch.cr0 &= ~cr0_guest_owned_bits;
	vcpu->arch.cr0 |= vmcs_readl(GUEST_CR0) & cr0_guest_owned_bits;
}

static void vmx_decache_cr4_guest_bits(struct kvm_vcpu *vcpu)
{
	ulong cr4_guest_owned_bits = vcpu->arch.cr4_guest_owned_bits;

	vcpu->arch.cr4 &= ~cr4_guest_owned_bits;
	vcpu->arch.cr4 |= vmcs_readl(GUEST_CR4) & cr4_guest_owned_bits;
}

static void ept_load_pdptrs(struct kvm_vcpu *vcpu)
{
	if (!test_bit(VCPU_EXREG_PDPTR,
		      (unsigned long *)&vcpu->arch.regs_dirty))
		return;

	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vmcs_write64(GUEST_PDPTR0, vcpu->arch.pdptrs[0]);
		vmcs_write64(GUEST_PDPTR1, vcpu->arch.pdptrs[1]);
		vmcs_write64(GUEST_PDPTR2, vcpu->arch.pdptrs[2]);
		vmcs_write64(GUEST_PDPTR3, vcpu->arch.pdptrs[3]);
	}
}

static void ept_save_pdptrs(struct kvm_vcpu *vcpu)
{
	if (is_paging(vcpu) && is_pae(vcpu) && !is_long_mode(vcpu)) {
		vcpu->arch.pdptrs[0] = vmcs_read64(GUEST_PDPTR0);
		vcpu->arch.pdptrs[1] = vmcs_read64(GUEST_PDPTR1);
		vcpu->arch.pdptrs[2] = vmcs_read64(GUEST_PDPTR2);
		vcpu->arch.pdptrs[3] = vmcs_read64(GUEST_PDPTR3);
	}

	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_avail);
	__set_bit(VCPU_EXREG_PDPTR,
		  (unsigned long *)&vcpu->arch.regs_dirty);
}

static void vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4);

static void ept_update_paging_mode_cr0(unsigned long *hw_cr0,
					unsigned long cr0,
					struct kvm_vcpu *vcpu)
{
	if (!(cr0 & X86_CR0_PG)) {
		/* From paging/starting to nonpaging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) |
			     (CPU_BASED_CR3_LOAD_EXITING |
			      CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	} else if (!is_paging(vcpu)) {
		/* From nonpaging to paging */
		vmcs_write32(CPU_BASED_VM_EXEC_CONTROL,
			     vmcs_read32(CPU_BASED_VM_EXEC_CONTROL) &
			     ~(CPU_BASED_CR3_LOAD_EXITING |
			       CPU_BASED_CR3_STORE_EXITING));
		vcpu->arch.cr0 = cr0;
		vmx_set_cr4(vcpu, kvm_read_cr4(vcpu));
	}

	if (!(cr0 & X86_CR0_WP))
		*hw_cr0 &= ~X86_CR0_WP;
}

static void ept_update_paging_mode_cr4(unsigned long *hw_cr4,
					struct kvm_vcpu *vcpu)
{
	if (!is_paging(vcpu)) {
		*hw_cr4 &= ~X86_CR4_PAE;
		*hw_cr4 |= X86_CR4_PSE;
	} else if (!(vcpu->arch.cr4 & X86_CR4_PAE))
		*hw_cr4 &= ~X86_CR4_PAE;
}

static void vmx_set_cr0(struct kvm_vcpu *vcpu, unsigned long cr0)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long hw_cr0;

	if (enable_unrestricted_guest)
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK_UNRESTRICTED_GUEST)
			| KVM_VM_CR0_ALWAYS_ON_UNRESTRICTED_GUEST;
	else
		hw_cr0 = (cr0 & ~KVM_GUEST_CR0_MASK) | KVM_VM_CR0_ALWAYS_ON;

	if (vmx->rmode.vm86_active && (cr0 & X86_CR0_PE))
		enter_pmode(vcpu);

	if (!vmx->rmode.vm86_active && !(cr0 & X86_CR0_PE))
		enter_rmode(vcpu);

#ifdef CONFIG_X86_64
	if (vcpu->arch.shadow_efer & EFER_LME) {
		if (!is_paging(vcpu) && (cr0 & X86_CR0_PG))
			enter_lmode(vcpu);
		if (is_paging(vcpu) && !(cr0 & X86_CR0_PG))
			exit_lmode(vcpu);
	}
#endif

	if (enable_ept)
		ept_update_paging_mode_cr0(&hw_cr0, cr0, vcpu);

	if (!vcpu->fpu_active)
		hw_cr0 |= X86_CR0_TS;

	vmcs_writel(CR0_READ_SHADOW, cr0);
	vmcs_writel(GUEST_CR0, hw_cr0);
	vcpu->arch.cr0 = cr0;
}

static u64 construct_eptp(unsigned long root_hpa)
{
	u64 eptp;

	/* TODO write the value reading from MSR */
	eptp = VMX_EPT_DEFAULT_MT |
		VMX_EPT_DEFAULT_GAW << VMX_EPT_GAW_EPTP_SHIFT;
	if (enable_ept_ad_bits)
		eptp |= VMX_EPT_AD_ENABLE_BIT;
	eptp |= (root_hpa & PAGE_MASK);

	return eptp;
}

static void vmx_set_cr3(struct kvm_vcpu *vcpu, unsigned long cr3)
{
	unsigned long guest_cr3;
	u64 eptp;

	guest_cr3 = cr3;
	if (enable_ept) {
		eptp = construct_eptp(cr3);
		vmcs_write64(EPT_POINTER, eptp);
		guest_cr3 = is_paging(vcpu) ? vcpu->arch.cr3 :
			vcpu->kvm->arch.ept_identity_map_addr;
	}

	vmx_flush_tlb(vcpu);
	vmcs_writel(GUEST_CR3, guest_cr3);
}

static void vmx_set_cr4(struct kvm_vcpu *vcpu, unsigned long cr4)
{
	unsigned long hw_cr4 = cr4 | (to_vmx(vcpu)->rmode.vm86_active ?
		    KVM_RMODE_VM_CR4_ALWAYS_ON : KVM_PMODE_VM_CR4_ALWAYS_ON);

	vcpu->arch.cr4 = cr4;
	if (enable_ept)
		ept_update_paging_mode_cr4(&hw_cr4, vcpu);

	vmcs_writel(CR4_READ_SHADOW, cr4);
	vmcs_writel(GUEST_CR4, hw_cr4);
}

static u64 vmx_get_segment_base(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];

	return vmcs_readl(sf->base);
}

static void vmx_get_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	u32 ar;

	var->base = vmcs_readl(sf->base);
	var->limit = vmcs_read32(sf->limit);
	var->selector = vmcs_read16(sf->selector);
	ar = vmcs_read32(sf->ar_bytes);
	if ((ar & AR_UNUSABLE_MASK) && !emulate_invalid_guest_state)
		ar = 0;
	var->type = ar & 15;
	var->s = (ar >> 4) & 1;
	var->dpl = (ar >> 5) & 3;
	var->present = (ar >> 7) & 1;
	var->avl = (ar >> 12) & 1;
	var->l = (ar >> 13) & 1;
	var->db = (ar >> 14) & 1;
	var->g = (ar >> 15) & 1;
	var->unusable = (ar >> 16) & 1;
}

static int vmx_get_cpl(struct kvm_vcpu *vcpu)
{
	if (!kvm_read_cr0_bits(vcpu, X86_CR0_PE)) /* if real mode */
		return 0;

	if (vmx_get_rflags(vcpu) & X86_EFLAGS_VM) /* if virtual 8086 */
		return 3;

	return vmcs_read16(GUEST_CS_SELECTOR) & 3;
}

static u32 vmx_segment_access_rights(struct kvm_segment *var)
{
	u32 ar;

	if (var->unusable)
		ar = 1 << 16;
	else {
		ar = var->type & 15;
		ar |= (var->s & 1) << 4;
		ar |= (var->dpl & 3) << 5;
		ar |= (var->present & 1) << 7;
		ar |= (var->avl & 1) << 12;
		ar |= (var->l & 1) << 13;
		ar |= (var->db & 1) << 14;
		ar |= (var->g & 1) << 15;
	}
	if (ar == 0) /* a 0 value means unusable */
		ar = AR_UNUSABLE_MASK;

	return ar;
}

static void vmx_set_segment(struct kvm_vcpu *vcpu,
			    struct kvm_segment *var, int seg)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	u32 ar;

	if (vmx->rmode.vm86_active && seg == VCPU_SREG_TR) {
		vmcs_write16(sf->selector, var->selector);
		vmx->rmode.tr.selector = var->selector;
		vmx->rmode.tr.base = var->base;
		vmx->rmode.tr.limit = var->limit;
		vmx->rmode.tr.ar = vmx_segment_access_rights(var);
		return;
	}
	vmcs_writel(sf->base, var->base);
	vmcs_write32(sf->limit, var->limit);
	vmcs_write16(sf->selector, var->selector);
	if (vmx->rmode.vm86_active && var->s) {
		/*
		 * Hack real-mode segments into vm86 compatibility.
		 */
		if (var->base == 0xffff0000 && var->selector == 0xf000)
			vmcs_writel(sf->base, 0xf0000);
		ar = 0xf3;
	} else
		ar = vmx_segment_access_rights(var);

	/*
	 *   Fix the "Accessed" bit in AR field of segment registers for older
	 * qemu binaries.
	 *   IA32 arch specifies that at the time of processor reset the
	 * "Accessed" bit in the AR field of segment registers is 1. And qemu
	 * is setting it to 0 in the usedland code. This causes invalid guest
	 * state vmexit when "unrestricted guest" mode is turned on.
	 *    Fix for this setup issue in cpu_reset is being pushed in the qemu
	 * tree. Newer qemu binaries with that qemu fix would not need this
	 * kvm hack.
	 */
	if (enable_unrestricted_guest && (seg != VCPU_SREG_LDTR))
		ar |= 0x1; /* Accessed */

	vmcs_write32(sf->ar_bytes, ar);

	/*
	 * Fix segments for real mode guest in hosts that don't have
	 * "unrestricted_mode" or it was disabled.
	 * This is done to allow migration of the guests from hosts with
	 * unrestricted guest like Westmere to older host that don't have
	 * unrestricted guest like Nehelem.
	 */
	if (!enable_unrestricted_guest && vmx->rmode.vm86_active) {
		switch (seg) {
		case VCPU_SREG_CS:
			vmcs_write32(GUEST_CS_AR_BYTES, 0xf3);
			vmcs_write32(GUEST_CS_LIMIT, 0xffff);
			if (vmcs_readl(GUEST_CS_BASE) == 0xffff0000)
				vmcs_writel(GUEST_CS_BASE, 0xf0000);
			vmcs_write16(GUEST_CS_SELECTOR,
				     vmcs_readl(GUEST_CS_BASE) >> 4);
			break;
		case VCPU_SREG_ES:
			fix_rmode_seg(VCPU_SREG_ES, &vmx->rmode.es);
			break;
		case VCPU_SREG_DS:
			fix_rmode_seg(VCPU_SREG_DS, &vmx->rmode.ds);
			break;
		case VCPU_SREG_GS:
			fix_rmode_seg(VCPU_SREG_GS, &vmx->rmode.gs);
			break;
		case VCPU_SREG_FS:
			fix_rmode_seg(VCPU_SREG_FS, &vmx->rmode.fs);
			break;
		case VCPU_SREG_SS:
			vmcs_write16(GUEST_SS_SELECTOR,
				     vmcs_readl(GUEST_SS_BASE) >> 4);
			vmcs_write32(GUEST_SS_LIMIT, 0xffff);
			vmcs_write32(GUEST_SS_AR_BYTES, 0xf3);
			break;
		}
	}
}

static void vmx_get_cs_db_l_bits(struct kvm_vcpu *vcpu, int *db, int *l)
{
	u32 ar = vmcs_read32(GUEST_CS_AR_BYTES);

	*db = (ar >> 14) & 1;
	*l = (ar >> 13) & 1;
}

static void vmx_get_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_IDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_IDTR_BASE);
}

static void vmx_set_idt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_IDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_IDTR_BASE, dt->base);
}

static void vmx_get_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	dt->limit = vmcs_read32(GUEST_GDTR_LIMIT);
	dt->base = vmcs_readl(GUEST_GDTR_BASE);
}

static void vmx_set_gdt(struct kvm_vcpu *vcpu, struct descriptor_table *dt)
{
	vmcs_write32(GUEST_GDTR_LIMIT, dt->limit);
	vmcs_writel(GUEST_GDTR_BASE, dt->base);
}

static bool rmode_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	u32 ar;

	vmx_get_segment(vcpu, &var, seg);
	ar = vmx_segment_access_rights(&var);

	if (var.base != (var.selector << 4))
		return false;
	if (var.limit != 0xffff)
		return false;
	if (ar != 0xf3)
		return false;

	return true;
}

static bool code_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs;
	unsigned int cs_rpl;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	cs_rpl = cs.selector & SELECTOR_RPL_MASK;

	if (cs.unusable)
		return false;
	if (~cs.type & (AR_TYPE_CODE_MASK|AR_TYPE_ACCESSES_MASK))
		return false;
	if (!cs.s)
		return false;
	if (cs.type & AR_TYPE_WRITEABLE_MASK) {
		if (cs.dpl > cs_rpl)
			return false;
	} else {
		if (cs.dpl != cs_rpl)
			return false;
	}
	if (!cs.present)
		return false;

	/* TODO: Add Reserved field check, this'll require a new member in the kvm_segment_field structure */
	return true;
}

static bool stack_segment_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ss;
	unsigned int ss_rpl;

	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);
	ss_rpl = ss.selector & SELECTOR_RPL_MASK;

	if (ss.unusable)
		return true;
	if (ss.type != 3 && ss.type != 7)
		return false;
	if (!ss.s)
		return false;
	if (ss.dpl != ss_rpl) /* DPL != RPL */
		return false;
	if (!ss.present)
		return false;

	return true;
}

static bool data_segment_valid(struct kvm_vcpu *vcpu, int seg)
{
	struct kvm_segment var;
	unsigned int rpl;

	vmx_get_segment(vcpu, &var, seg);
	rpl = var.selector & SELECTOR_RPL_MASK;

	if (var.unusable)
		return true;
	if (!var.s)
		return false;
	if (!var.present)
		return false;
	if (~var.type & (AR_TYPE_CODE_MASK|AR_TYPE_WRITEABLE_MASK)) {
		if (var.dpl < rpl) /* DPL < RPL */
			return false;
	}

	/* TODO: Add other members to kvm_segment_field to allow checking for other access
	 * rights flags
	 */
	return true;
}

static bool tr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment tr;

	vmx_get_segment(vcpu, &tr, VCPU_SREG_TR);

	if (tr.unusable)
		return false;
	if (tr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return false;
	if (tr.type != 3 && tr.type != 11) /* TODO: Check if guest is in IA32e mode */
		return false;
	if (!tr.present)
		return false;

	return true;
}

static bool ldtr_valid(struct kvm_vcpu *vcpu)
{
	struct kvm_segment ldtr;

	vmx_get_segment(vcpu, &ldtr, VCPU_SREG_LDTR);

	if (ldtr.unusable)
		return true;
	if (ldtr.selector & SELECTOR_TI_MASK)	/* TI = 1 */
		return false;
	if (ldtr.type != 2)
		return false;
	if (!ldtr.present)
		return false;

	return true;
}

static bool cs_ss_rpl_check(struct kvm_vcpu *vcpu)
{
	struct kvm_segment cs, ss;

	vmx_get_segment(vcpu, &cs, VCPU_SREG_CS);
	vmx_get_segment(vcpu, &ss, VCPU_SREG_SS);

	return ((cs.selector & SELECTOR_RPL_MASK) ==
		 (ss.selector & SELECTOR_RPL_MASK));
}

/*
 * Check if guest state is valid. Returns true if valid, false if
 * not.
 * We assume that registers are always usable
 */
static bool guest_state_valid(struct kvm_vcpu *vcpu)
{
	/* real mode guest state checks */
	if (!kvm_read_cr0_bits(vcpu, X86_CR0_PE)) {
		if (!rmode_segment_valid(vcpu, VCPU_SREG_CS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_SS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!rmode_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
	} else {
	/* protected mode guest state checks */
		if (!cs_ss_rpl_check(vcpu))
			return false;
		if (!code_segment_valid(vcpu))
			return false;
		if (!stack_segment_valid(vcpu))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_DS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_ES))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_FS))
			return false;
		if (!data_segment_valid(vcpu, VCPU_SREG_GS))
			return false;
		if (!tr_valid(vcpu))
			return false;
		if (!ldtr_valid(vcpu))
			return false;
	}
	/* TODO:
	 * - Add checks on RIP
	 * - Add checks on RFLAGS
	 */

	return true;
}

static int init_rmode_tss(struct kvm *kvm)
{
	gfn_t fn;
	u16 data = 0;
	int r, idx, ret = 0;

	idx = srcu_read_lock(&kvm->srcu);
	fn = rmode_tss_base(kvm) >> PAGE_SHIFT;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = TSS_BASE_SIZE + TSS_REDIRECTION_SIZE;
	r = kvm_write_guest_page(kvm, fn++, &data,
			TSS_IOPB_BASE_OFFSET, sizeof(u16));
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn++, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	r = kvm_clear_guest_page(kvm, fn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	data = ~0;
	r = kvm_write_guest_page(kvm, fn, &data,
				 RMODE_TSS_SIZE - 2 * PAGE_SIZE - 1,
				 sizeof(u8));
	if (r < 0)
		goto out;

	ret = 1;
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int init_rmode_identity_map(struct kvm *kvm)
{
	int i, idx, r, ret;
	pfn_t identity_map_pfn;
	u32 tmp;

	if (!enable_ept)
		return 1;
	if (unlikely(!kvm->arch.ept_identity_pagetable)) {
		printk(KERN_ERR "EPT: identity-mapping pagetable "
			"haven't been allocated!\n");
		return 0;
	}
	if (likely(kvm->arch.ept_identity_pagetable_done))
		return 1;
	ret = 0;
	identity_map_pfn = kvm->arch.ept_identity_map_addr >> PAGE_SHIFT;
	idx = srcu_read_lock(&kvm->srcu);
	r = kvm_clear_guest_page(kvm, identity_map_pfn, 0, PAGE_SIZE);
	if (r < 0)
		goto out;
	/* Set up identity-mapping pagetable for EPT in real mode */
	for (i = 0; i < PT32_ENT_PER_PAGE; i++) {
		tmp = (i << 22) + (_PAGE_PRESENT | _PAGE_RW | _PAGE_USER |
			_PAGE_ACCESSED | _PAGE_DIRTY | _PAGE_PSE);
		r = kvm_write_guest_page(kvm, identity_map_pfn,
				&tmp, i * sizeof(tmp), sizeof(tmp));
		if (r < 0)
			goto out;
	}
	kvm->arch.ept_identity_pagetable_done = true;
	ret = 1;
out:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static void seg_setup(int seg)
{
	struct kvm_vmx_segment_field *sf = &kvm_vmx_segment_fields[seg];
	unsigned int ar;

	vmcs_write16(sf->selector, 0);
	vmcs_writel(sf->base, 0);
	vmcs_write32(sf->limit, 0xffff);
	if (enable_unrestricted_guest) {
		ar = 0x93;
		if (seg == VCPU_SREG_CS)
			ar |= 0x08; /* code segment */
	} else
		ar = 0xf3;

	vmcs_write32(sf->ar_bytes, ar);
}

static int alloc_apic_access_page(struct kvm *kvm)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.apic_access_page)
		goto out;
	kvm_userspace_mem.slot = APIC_ACCESS_PAGE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr = 0xfee00000ULL;
	kvm_userspace_mem.memory_size = PAGE_SIZE;
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem, 0);
	if (r)
		goto out;

	kvm->arch.apic_access_page = gfn_to_page(kvm, 0xfee00);
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static int alloc_identity_pagetable(struct kvm *kvm)
{
	struct kvm_userspace_memory_region kvm_userspace_mem;
	int r = 0;

	mutex_lock(&kvm->slots_lock);
	if (kvm->arch.ept_identity_pagetable)
		goto out;
	kvm_userspace_mem.slot = IDENTITY_PAGETABLE_PRIVATE_MEMSLOT;
	kvm_userspace_mem.flags = 0;
	kvm_userspace_mem.guest_phys_addr =
		kvm->arch.ept_identity_map_addr;
	kvm_userspace_mem.memory_size = PAGE_SIZE;
	r = __kvm_set_memory_region(kvm, &kvm_userspace_mem, 0);
	if (r)
		goto out;

	kvm->arch.ept_identity_pagetable = gfn_to_page(kvm,
			kvm->arch.ept_identity_map_addr >> PAGE_SHIFT);
out:
	mutex_unlock(&kvm->slots_lock);
	return r;
}

static void allocate_vpid(struct vcpu_vmx *vmx)
{
	int vpid;

	vmx->vpid = 0;
	if (!enable_vpid)
		return;
	spin_lock(&vmx_vpid_lock);
	vpid = find_first_zero_bit(vmx_vpid_bitmap, VMX_NR_VPIDS);
	if (vpid < VMX_NR_VPIDS) {
		vmx->vpid = vpid;
		__set_bit(vpid, vmx_vpid_bitmap);
	}
	spin_unlock(&vmx_vpid_lock);
}

static void free_vpid(struct vcpu_vmx *vmx)
{
	if (!enable_vpid)
		return;
	spin_lock(&vmx_vpid_lock);
	if (vmx->vpid != 0)
		__clear_bit(vmx->vpid, vmx_vpid_bitmap);
	spin_unlock(&vmx_vpid_lock);
}

static void __vmx_disable_intercept_for_msr(unsigned long *msr_bitmap, u32 msr)
{
	int f = sizeof(unsigned long);

	if (!cpu_has_vmx_msr_bitmap())
		return;

	/*
	 * See Intel PRM Vol. 3, 20.6.9 (MSR-Bitmap Address). Early manuals
	 * have the write-low and read-high bitmap offsets the wrong way round.
	 * We can control MSRs 0x00000000-0x00001fff and 0xc0000000-0xc0001fff.
	 */
	if (msr <= 0x1fff) {
		__clear_bit(msr, msr_bitmap + 0x000 / f); /* read-low */
		__clear_bit(msr, msr_bitmap + 0x800 / f); /* write-low */
	} else if ((msr >= 0xc0000000) && (msr <= 0xc0001fff)) {
		msr &= 0x1fff;
		__clear_bit(msr, msr_bitmap + 0x400 / f); /* read-high */
		__clear_bit(msr, msr_bitmap + 0xc00 / f); /* write-high */
	}
}

static void vmx_disable_intercept_for_msr(u32 msr, bool longmode_only)
{
	if (!longmode_only)
		__vmx_disable_intercept_for_msr(vmx_msr_bitmap_legacy, msr);
	__vmx_disable_intercept_for_msr(vmx_msr_bitmap_longmode, msr);
}

/*
 * Sets up the vmcs for emulated real mode.
 */
static int vmx_vcpu_setup(struct vcpu_vmx *vmx)
{
	u32 host_sysenter_cs, msr_low, msr_high;
	u32 junk;
	u64 host_pat;
	unsigned long a;
	struct descriptor_table dt;
	int i;
	unsigned long kvm_vmx_return;
	u32 exec_control;
	unsigned long cr4;

	/* I/O */
	vmcs_write64(IO_BITMAP_A, __pa(vmx_io_bitmap_a));
	vmcs_write64(IO_BITMAP_B, __pa(vmx_io_bitmap_b));

	if (cpu_has_vmx_msr_bitmap())
		vmcs_write64(MSR_BITMAP, __pa(vmx_msr_bitmap_legacy));

	vmcs_write64(VMCS_LINK_POINTER, -1ull); /* 22.3.1.5 */

	/* Control */
	vmcs_write32(PIN_BASED_VM_EXEC_CONTROL,
		vmcs_config.pin_based_exec_ctrl);

	exec_control = vmcs_config.cpu_based_exec_ctrl;
	if (!vm_need_tpr_shadow(vmx->vcpu.kvm)) {
		exec_control &= ~CPU_BASED_TPR_SHADOW;
#ifdef CONFIG_X86_64
		exec_control |= CPU_BASED_CR8_STORE_EXITING |
				CPU_BASED_CR8_LOAD_EXITING;
#endif
	}
	if (!enable_ept)
		exec_control |= CPU_BASED_CR3_STORE_EXITING |
				CPU_BASED_CR3_LOAD_EXITING  |
				CPU_BASED_INVLPG_EXITING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, exec_control);

	if (cpu_has_secondary_exec_ctrls()) {
		exec_control = vmcs_config.cpu_based_2nd_exec_ctrl;
		if (!vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
			exec_control &=
				~SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES;
		if (vmx->vpid == 0)
			exec_control &= ~SECONDARY_EXEC_ENABLE_VPID;
		if (!enable_ept) {
			exec_control &= ~SECONDARY_EXEC_ENABLE_EPT;
			enable_unrestricted_guest = 0;
			/* Enable INVPCID for non-ept guests may cause performance regression. */
			exec_control &= ~SECONDARY_EXEC_ENABLE_INVPCID;
		}
		if (!enable_unrestricted_guest)
			exec_control &= ~SECONDARY_EXEC_UNRESTRICTED_GUEST;
		if (!ple_gap)
			exec_control &= ~SECONDARY_EXEC_PAUSE_LOOP_EXITING;
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL, exec_control);
	}

	if (ple_gap) {
		vmcs_write32(PLE_GAP, ple_gap);
		vmx->ple_window = ple_window;
		vmx->ple_window_dirty = true;
	}

	vmcs_write32(PAGE_FAULT_ERROR_CODE_MASK, !!bypass_guest_pf);
	vmcs_write32(PAGE_FAULT_ERROR_CODE_MATCH, !!bypass_guest_pf);
	vmcs_write32(CR3_TARGET_COUNT, 0);           /* 22.2.1 */

	vmcs_writel(HOST_CR0, read_cr0());  /* 22.2.3 */
	vmcs_writel(HOST_CR3, read_cr3());  /* 22.2.3  FIXME: shadow tables */
	
	/* Save the most likely value for this task's CR4 in the VMCS. */
	cr4 = read_cr4();
	vmcs_writel(HOST_CR4, read_cr4());  /* 22.2.3, 22.2.5 */
	vmx->host_state.vmcs_host_cr4 = cr4;

	vmcs_write16(HOST_CS_SELECTOR, __KERNEL_CS);  /* 22.2.4 */
	vmcs_write16(HOST_DS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_ES_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
	vmcs_write16(HOST_FS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_GS_SELECTOR, 0);            /* 22.2.4 */
	vmcs_write16(HOST_SS_SELECTOR, __KERNEL_DS);  /* 22.2.4 */
#ifdef CONFIG_X86_64
	rdmsrl(MSR_FS_BASE, a);
	vmcs_writel(HOST_FS_BASE, a); /* 22.2.4 */
	rdmsrl(MSR_GS_BASE, a);
	vmcs_writel(HOST_GS_BASE, a); /* 22.2.4 */
#else
	vmcs_writel(HOST_FS_BASE, 0); /* 22.2.4 */
	vmcs_writel(HOST_GS_BASE, 0); /* 22.2.4 */
#endif

	vmcs_write16(HOST_TR_SELECTOR, GDT_ENTRY_TSS*8);  /* 22.2.4 */

	kvm_get_idt(&dt);
	vmcs_writel(HOST_IDTR_BASE, dt.base);   /* 22.2.4 */
	vmx->host_idt_base = dt.base;

	asm("mov $.Lkvm_vmx_return, %0" : "=r"(kvm_vmx_return));
	vmcs_writel(HOST_RIP, kvm_vmx_return); /* 22.2.5 */
	vmcs_write32(VM_EXIT_MSR_STORE_COUNT, 0);
	vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.host.val));
	vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, __pa(vmx->msr_autoload.guest.val));

	rdmsr(MSR_IA32_SYSENTER_CS, host_sysenter_cs, junk);
	vmcs_write32(HOST_IA32_SYSENTER_CS, host_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, a);
	vmcs_writel(HOST_IA32_SYSENTER_ESP, a);   /* 22.2.3 */
	rdmsrl(MSR_IA32_SYSENTER_EIP, a);
	vmcs_writel(HOST_IA32_SYSENTER_EIP, a);   /* 22.2.3 */

	if (vmcs_config.vmexit_ctrl & VM_EXIT_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((u64) msr_high << 32);
		vmcs_write64(HOST_IA32_PAT, host_pat);
	}
	if (vmcs_config.vmentry_ctrl & VM_ENTRY_LOAD_IA32_PAT) {
		rdmsr(MSR_IA32_CR_PAT, msr_low, msr_high);
		host_pat = msr_low | ((u64) msr_high << 32);
		/* Write the default value follow host pat */
		vmcs_write64(GUEST_IA32_PAT, host_pat);
		/* Keep arch.pat sync with GUEST_IA32_PAT */
		vmx->vcpu.arch.pat = host_pat;
	}

	for (i = 0; i < NR_VMX_MSR; ++i) {
		u32 index = vmx_msr_index[i];
		u32 data_low, data_high;
		u64 data;
		int j = vmx->nmsrs;

		if (rdmsr_safe(index, &data_low, &data_high) < 0)
			continue;
		if (wrmsr_safe(index, data_low, data_high) < 0)
			continue;
		data = data_low | ((u64)data_high << 32);
		vmx->guest_msrs[j].index = i;
		vmx->guest_msrs[j].data = 0;
		vmx->guest_msrs[j].mask = -1ull;
		++vmx->nmsrs;
	}

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES))
		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, vmx->arch_capabilities);

	vmcs_write32(VM_EXIT_CONTROLS, vmcs_config.vmexit_ctrl);

	/* 22.2.1, 20.8.1 */
	vmcs_write32(VM_ENTRY_CONTROLS, vmcs_config.vmentry_ctrl);

	vmcs_writel(CR0_GUEST_HOST_MASK, ~0UL);
	vmcs_writel(CR4_GUEST_HOST_MASK, KVM_GUEST_CR4_MASK);
	vmx->vcpu.arch.cr4_guest_owned_bits = ~KVM_GUEST_CR4_MASK;

	return 0;
}

static int vmx_vcpu_reset(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u64 msr;
	int ret;

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP));

	vmx->rmode.vm86_active = 0;

	vmx->soft_vnmi_blocked = 0;

	vmx->vcpu.arch.regs[VCPU_REGS_RDX] = get_rdx_init_val();
	kvm_set_cr8(&vmx->vcpu, 0);
	msr = 0xfee00000 | MSR_IA32_APICBASE_ENABLE;
	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		msr |= MSR_IA32_APICBASE_BSP;
	kvm_set_apic_base(&vmx->vcpu, msr);

	fx_init(&vmx->vcpu);

	seg_setup(VCPU_SREG_CS);
	/*
	 * GUEST_CS_BASE should really be 0xffff0000, but VT vm86 mode
	 * insists on having GUEST_CS_BASE == GUEST_CS_SELECTOR << 4.  Sigh.
	 */
	if (kvm_vcpu_is_bsp(&vmx->vcpu)) {
		vmcs_write16(GUEST_CS_SELECTOR, 0xf000);
		vmcs_writel(GUEST_CS_BASE, 0x000f0000);
	} else {
		vmcs_write16(GUEST_CS_SELECTOR, vmx->vcpu.arch.sipi_vector << 8);
		vmcs_writel(GUEST_CS_BASE, vmx->vcpu.arch.sipi_vector << 12);
	}

	seg_setup(VCPU_SREG_DS);
	seg_setup(VCPU_SREG_ES);
	seg_setup(VCPU_SREG_FS);
	seg_setup(VCPU_SREG_GS);
	seg_setup(VCPU_SREG_SS);

	vmcs_write16(GUEST_TR_SELECTOR, 0);
	vmcs_writel(GUEST_TR_BASE, 0);
	vmcs_write32(GUEST_TR_LIMIT, 0xffff);
	vmcs_write32(GUEST_TR_AR_BYTES, 0x008b);

	vmcs_write16(GUEST_LDTR_SELECTOR, 0);
	vmcs_writel(GUEST_LDTR_BASE, 0);
	vmcs_write32(GUEST_LDTR_LIMIT, 0xffff);
	vmcs_write32(GUEST_LDTR_AR_BYTES, 0x00082);

	vmcs_write32(GUEST_SYSENTER_CS, 0);
	vmcs_writel(GUEST_SYSENTER_ESP, 0);
	vmcs_writel(GUEST_SYSENTER_EIP, 0);

	vmcs_writel(GUEST_RFLAGS, 0x02);
	if (kvm_vcpu_is_bsp(&vmx->vcpu))
		kvm_rip_write(vcpu, 0xfff0);
	else
		kvm_rip_write(vcpu, 0);
	kvm_register_write(vcpu, VCPU_REGS_RSP, 0);

	vmcs_writel(GUEST_DR7, 0x400);

	vmcs_writel(GUEST_GDTR_BASE, 0);
	vmcs_write32(GUEST_GDTR_LIMIT, 0xffff);

	vmcs_writel(GUEST_IDTR_BASE, 0);
	vmcs_write32(GUEST_IDTR_LIMIT, 0xffff);

	vmcs_write32(GUEST_ACTIVITY_STATE, GUEST_ACTIVITY_ACTIVE);
	vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, 0);

	/* Special registers */
	vmcs_write64(GUEST_IA32_DEBUGCTL, 0);

	setup_msrs(vmx);

	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, 0);  /* 22.2.1 */

	if (cpu_has_vmx_tpr_shadow()) {
		vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, 0);
		if (vm_need_tpr_shadow(vmx->vcpu.kvm))
			vmcs_write64(VIRTUAL_APIC_PAGE_ADDR,
				page_to_phys(vmx->vcpu.arch.apic->regs_page));
		vmcs_write32(TPR_THRESHOLD, 0);
	}

	if (vm_need_virtualize_apic_accesses(vmx->vcpu.kvm))
		vmcs_write64(APIC_ACCESS_ADDR,
			     page_to_phys(vmx->vcpu.kvm->arch.apic_access_page));

	if (vmx->vpid != 0)
		vmcs_write16(VIRTUAL_PROCESSOR_ID, vmx->vpid);

	vmx->vcpu.arch.cr0 = X86_CR0_NW | X86_CR0_CD | X86_CR0_ET;
	vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
	vmx_set_cr0(&vmx->vcpu, kvm_read_cr0(vcpu)); /* enter rmode */
	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
	vmx_set_cr4(&vmx->vcpu, 0);
	vmx_set_efer(&vmx->vcpu, 0);
	vmx_fpu_activate(&vmx->vcpu);
	update_exception_bitmap(&vmx->vcpu);

	vpid_sync_vcpu_all(vmx);

	ret = 0;

	/* HACK: Don't enable emulation on guest boot/reset */
	vmx->emulation_required = 0;

	return ret;
}

static void enable_irq_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void enable_nmi_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	if (!cpu_has_virtual_nmis()) {
		enable_irq_window(vcpu);
		return;
	}

	if (vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) & GUEST_INTR_STATE_STI) {
		enable_irq_window(vcpu);
		return;
	}
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control |= CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
}

static void vmx_inject_irq(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	uint32_t intr;
	int irq = vcpu->arch.interrupt.nr;

	trace_kvm_inj_virq(irq);

	++vcpu->stat.irq_injections;
	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = true;
		vmx->rmode.irq.vector = irq;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		if (vcpu->arch.interrupt.soft)
			vmx->rmode.irq.rip +=
				vmx->vcpu.arch.event_exit_inst_len;
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     irq | INTR_TYPE_SOFT_INTR | INTR_INFO_VALID_MASK);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}
	intr = irq | INTR_INFO_VALID_MASK;
	if (vcpu->arch.interrupt.soft) {
		intr |= INTR_TYPE_SOFT_INTR;
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN,
			     vmx->vcpu.arch.event_exit_inst_len);
	} else
		intr |= INTR_TYPE_EXT_INTR;
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, intr);
	vmx_clear_hlt(vcpu);
}

static void vmx_inject_nmi(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		/*
		 * Tracking the NMI-blocked state in software is built upon
		 * finding the next open IRQ window. This, in turn, depends on
		 * well-behaving guests: They have to keep IRQs disabled at
		 * least as long as the NMI handler runs. Otherwise we may
		 * cause NMI nesting, maybe breaking the guest. But as this is
		 * highly unlikely, we can live with the residual risk.
		 */
		vmx->soft_vnmi_blocked = 1;
		vmx->vnmi_blocked_time = 0;
	}

	++vcpu->stat.nmi_injections;
	if (vmx->rmode.vm86_active) {
		vmx->rmode.irq.pending = true;
		vmx->rmode.irq.vector = NMI_VECTOR;
		vmx->rmode.irq.rip = kvm_rip_read(vcpu);
		vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			     NMI_VECTOR | INTR_TYPE_SOFT_INTR |
			     INTR_INFO_VALID_MASK);
		vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, 1);
		kvm_rip_write(vcpu, vmx->rmode.irq.rip - 1);
		return;
	}
	vmcs_write32(VM_ENTRY_INTR_INFO_FIELD,
			INTR_TYPE_NMI_INTR | INTR_INFO_VALID_MASK | NMI_VECTOR);
	vmx_clear_hlt(vcpu);
}

static int vmx_nmi_allowed(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis() && to_vmx(vcpu)->soft_vnmi_blocked)
		return 0;

	return	!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
		  (GUEST_INTR_STATE_MOV_SS | GUEST_INTR_STATE_STI
		   | GUEST_INTR_STATE_NMI));
}

static bool vmx_get_nmi_mask(struct kvm_vcpu *vcpu)
{
	if (!cpu_has_virtual_nmis())
		return to_vmx(vcpu)->soft_vnmi_blocked;
	else
		return !!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			  GUEST_INTR_STATE_NMI);
}

static void vmx_set_nmi_mask(struct kvm_vcpu *vcpu, bool masked)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (!cpu_has_virtual_nmis()) {
		if (vmx->soft_vnmi_blocked != masked) {
			vmx->soft_vnmi_blocked = masked;
			vmx->vnmi_blocked_time = 0;
		}
	} else {
		if (masked)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
		else
			vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
					GUEST_INTR_STATE_NMI);
	}
}

static int vmx_interrupt_allowed(struct kvm_vcpu *vcpu)
{
	return (vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF) &&
		!(vmcs_read32(GUEST_INTERRUPTIBILITY_INFO) &
			(GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS));
}

static int vmx_set_tss_addr(struct kvm *kvm, unsigned int addr)
{
	int ret;
	struct kvm_userspace_memory_region tss_mem = {
		.slot = TSS_PRIVATE_MEMSLOT,
		.guest_phys_addr = addr,
		.memory_size = PAGE_SIZE * 3,
		.flags = 0,
	};

	ret = kvm_set_memory_region(kvm, &tss_mem, 0);
	if (ret)
		return ret;
	kvm->arch.tss_addr = addr;
	if (!init_rmode_tss(kvm))
		return  -ENOMEM;

	return 0;
}

static int handle_rmode_exception(struct kvm_vcpu *vcpu,
				  int vec, u32 err_code)
{
	/*
	 * Instruction with address size override prefix opcode 0x67
	 * Cause the #SS fault with 0 error code in VM86 mode.
	 */
	if (((vec == GP_VECTOR) || (vec == SS_VECTOR)) && err_code == 0)
		if (emulate_instruction(vcpu, 0) == EMULATE_DONE)
			return 1;
	/*
	 * Forward all other exceptions that are valid in real mode.
	 * FIXME: Breaks guest debugging in real mode, needs to be fixed with
	 *        the required debugging infrastructure rework.
	 */
	switch (vec) {
	case DB_VECTOR:
		if (vcpu->guest_debug &
		    (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))
			return 0;
		kvm_queue_exception(vcpu, vec);
		return 1;
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject the exception
		 * from user space while in guest debugging mode.
		 */
		to_vmx(vcpu)->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_SW_BP)
			return 0;
		/* fall through */
	case DE_VECTOR:
	case OF_VECTOR:
	case BR_VECTOR:
	case UD_VECTOR:
	case DF_VECTOR:
	case SS_VECTOR:
	case GP_VECTOR:
	case MF_VECTOR:
		kvm_queue_exception(vcpu, vec);
		return 1;
	}
	return 0;
}

/*
 * Trigger machine check on the host. We assume all the MSRs are already set up
 * by the CPU and that we still run on the same CPU as the MCE occurred on.
 * We pass a fake environment to the machine check handler because we want
 * the guest to be always treated like user space, no matter what context
 * it used internally.
 */
static void kvm_machine_check(void)
{
#if defined(CONFIG_X86_MCE) && defined(CONFIG_X86_64)
	struct pt_regs regs = {
		.cs = 3, /* Fake ring 3 no matter what the guest ran on */
		.flags = X86_EFLAGS_IF,
	};

	do_machine_check(&regs, 0);
#endif
}

static int handle_machine_check(struct kvm_vcpu *vcpu)
{
	/* already handled by vcpu_run */
	return 1;
}

static int handle_exception(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct kvm_run *kvm_run = vcpu->run;
	u32 intr_info, ex_no, error_code;
	unsigned long cr2, rip, dr6;
	u32 vect_info;
	enum emulation_result er;

	vect_info = vmx->idt_vectoring_info;
	intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	if (is_machine_check(intr_info))
		return handle_machine_check(vcpu);

	if ((vect_info & VECTORING_INFO_VALID_MASK) &&
	    !is_page_fault(intr_info)) {
		vcpu->run->exit_reason = KVM_EXIT_INTERNAL_ERROR;
		vcpu->run->internal.suberror = KVM_INTERNAL_ERROR_SIMUL_EX;
		vcpu->run->internal.ndata = 2;
		vcpu->run->internal.data[0] = vect_info;
		vcpu->run->internal.data[1] = intr_info;
		return 0;
	}

	if ((intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR)
		return 1;  /* already handled by vmx_vcpu_run() */

	if (is_no_device(intr_info)) {
		vmx_fpu_activate(vcpu);
		return 1;
	}

	if (is_invalid_opcode(intr_info)) {
		er = emulate_instruction(vcpu, EMULTYPE_TRAP_UD);
		if (er != EMULATE_DONE)
			kvm_queue_exception(vcpu, UD_VECTOR);
		return 1;
	}

	error_code = 0;
	rip = kvm_rip_read(vcpu);
	if (intr_info & INTR_INFO_DELIVER_CODE_MASK)
		error_code = vmcs_read32(VM_EXIT_INTR_ERROR_CODE);
	if (is_page_fault(intr_info)) {
		/* EPT won't cause page fault directly */
		if (enable_ept)
			BUG();
		cr2 = vmcs_readl(EXIT_QUALIFICATION);
		trace_kvm_page_fault(cr2, error_code);

		if (kvm_event_needs_reinjection(vcpu))
			kvm_mmu_unprotect_page_virt(vcpu, cr2);
		return kvm_mmu_page_fault(vcpu, cr2, error_code, NULL, 0);
	}

	if (vmx->rmode.vm86_active &&
	    handle_rmode_exception(vcpu, intr_info & INTR_INFO_VECTOR_MASK,
								error_code)) {
		if (vcpu->arch.halt_request) {
			vcpu->arch.halt_request = 0;
			return kvm_emulate_halt(vcpu);
		}
		return 1;
	}

	ex_no = intr_info & INTR_INFO_VECTOR_MASK;
	switch (ex_no) {
	case AC_VECTOR:
		kvm_queue_exception_e(vcpu, AC_VECTOR, error_code);
		return 1;
	case DB_VECTOR:
		dr6 = vmcs_readl(EXIT_QUALIFICATION);
		if (!(vcpu->guest_debug &
		      (KVM_GUESTDBG_SINGLESTEP | KVM_GUESTDBG_USE_HW_BP))) {
			vcpu->arch.dr6 = dr6 | DR6_FIXED_1;
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
		kvm_run->debug.arch.dr6 = dr6 | DR6_FIXED_1;
		kvm_run->debug.arch.dr7 = vmcs_readl(GUEST_DR7);
		/* fall through */
	case BP_VECTOR:
		/*
		 * Update instruction length as we may reinject #BP from
		 * user space while in guest debugging mode. Reading it for
		 * #DB as well causes no harm, it is not used in that case.
		 */
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		kvm_run->exit_reason = KVM_EXIT_DEBUG;
		kvm_run->debug.arch.pc = vmcs_readl(GUEST_CS_BASE) + rip;
		kvm_run->debug.arch.exception = ex_no;
		break;
	default:
		kvm_run->exit_reason = KVM_EXIT_EXCEPTION;
		kvm_run->ex.exception = ex_no;
		kvm_run->ex.error_code = error_code;
		break;
	}
	return 0;
}

static int handle_external_interrupt(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.irq_exits;
	return 1;
}

static int handle_triple_fault(struct kvm_vcpu *vcpu)
{
	vcpu->run->exit_reason = KVM_EXIT_SHUTDOWN;
	return 0;
}

static int handle_io(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	int size, in, string;
	unsigned port;

	++vcpu->stat.io_exits;
	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	string = (exit_qualification & 16) != 0;

	if (string)
		return emulate_instruction(vcpu, 0) == EMULATE_DONE;

	size = (exit_qualification & 7) + 1;
	in = (exit_qualification & 8) != 0;
	port = exit_qualification >> 16;

	skip_emulated_instruction(vcpu);
	return kvm_emulate_pio(vcpu, in, size, port);
}

static void
vmx_patch_hypercall(struct kvm_vcpu *vcpu, unsigned char *hypercall)
{
	/*
	 * Patch in the VMCALL instruction:
	 */
	hypercall[0] = 0x0f;
	hypercall[1] = 0x01;
	hypercall[2] = 0xc1;
}

static void complete_insn_gp(struct kvm_vcpu *vcpu, int err)
{
	if (err)
		kvm_inject_gp(vcpu, 0);
	else
		skip_emulated_instruction(vcpu);
}

static int handle_cr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification, val;
	int cr;
	int reg;
	int err;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	cr = exit_qualification & 15;
	reg = (exit_qualification >> 8) & 15;
	switch ((exit_qualification >> 4) & 3) {
	case 0: /* mov to cr */
		val = kvm_register_read(vcpu, reg);
		trace_kvm_cr_write(cr, val);
		switch (cr) {
		case 0:
			err = kvm_set_cr0(vcpu, val);
			complete_insn_gp(vcpu, err);
			return 1;
		case 3:
			err = kvm_set_cr3(vcpu, val);
			complete_insn_gp(vcpu, err);
			return 1;
		case 4:
			err = kvm_set_cr4(vcpu, val);
			complete_insn_gp(vcpu, err);
			return 1;
		case 8: {
				u8 cr8_prev = kvm_get_cr8(vcpu);
				u8 cr8 = kvm_register_read(vcpu, reg);
				if (kvm_set_cr8(vcpu, cr8))
					kvm_inject_gp(vcpu, 0);
				else
					skip_emulated_instruction(vcpu);
				if (irqchip_in_kernel(vcpu->kvm))
					return 1;
				if (cr8_prev <= cr8)
					return 1;
				vcpu->run->exit_reason = KVM_EXIT_SET_TPR;
				return 0;
			}
		};
		break;
	case 2: /* clts */
		vmx_set_cr0(vcpu, kvm_read_cr0_bits(vcpu, ~X86_CR0_TS));
		trace_kvm_cr_write(0, kvm_read_cr0(vcpu));
		skip_emulated_instruction(vcpu);
		return 1;
	case 1: /*mov from cr*/
		switch (cr) {
		case 3:
			kvm_register_write(vcpu, reg, vcpu->arch.cr3);
			trace_kvm_cr_read(cr, vcpu->arch.cr3);
			skip_emulated_instruction(vcpu);
			return 1;
		case 8:
			val = kvm_get_cr8(vcpu);
			kvm_register_write(vcpu, reg, val);
			trace_kvm_cr_read(cr, val);
			skip_emulated_instruction(vcpu);
			return 1;
		}
		break;
	case 3: /* lmsw */
		val = (exit_qualification >> LMSW_SOURCE_DATA_SHIFT) & 0x0f;
		trace_kvm_cr_write(0, (kvm_read_cr0(vcpu) & ~0xful) | val);
		kvm_lmsw(vcpu, val);

		skip_emulated_instruction(vcpu);
		return 1;
	default:
		break;
	}
	vcpu->run->exit_reason = 0;
	pr_unimpl(vcpu, "unhandled control register: op %d cr %d\n",
	       (int)(exit_qualification >> 4) & 3, cr);
	return 0;
}

static int handle_dr(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	unsigned long val;
	int dr, reg;

	if (!kvm_require_cpl(vcpu, 0))
		return 1;
	dr = vmcs_readl(GUEST_DR7);
	if (dr & DR7_GD) {
		/*
		 * As the vm-exit takes precedence over the debug trap, we
		 * need to emulate the latter, either for the host or the
		 * guest debugging itself.
		 */
		if (vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP) {
			vcpu->run->debug.arch.dr6 = vcpu->arch.dr6;
			vcpu->run->debug.arch.dr7 = dr;
			vcpu->run->debug.arch.pc =
				vmcs_readl(GUEST_CS_BASE) +
				vmcs_readl(GUEST_RIP);
			vcpu->run->debug.arch.exception = DB_VECTOR;
			vcpu->run->exit_reason = KVM_EXIT_DEBUG;
			return 0;
		} else {
			vcpu->arch.dr7 &= ~DR7_GD;
			vcpu->arch.dr6 |= DR6_BD;
			vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
			kvm_queue_exception(vcpu, DB_VECTOR);
			return 1;
		}
	}

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);
	dr = exit_qualification & DEBUG_REG_ACCESS_NUM;
	reg = DEBUG_REG_ACCESS_REG(exit_qualification);
	if (exit_qualification & TYPE_MOV_FROM_DR) {
		switch (dr) {
		case 0 ... 3:
			val = vcpu->arch.db[dr];
			break;
		case 6:
			val = vcpu->arch.dr6;
			break;
		case 7:
			val = vcpu->arch.dr7;
			break;
		default:
			val = 0;
		}
		kvm_register_write(vcpu, reg, val);
	} else {
		val = vcpu->arch.regs[reg];
		switch (dr) {
		case 0 ... 3:
			vcpu->arch.db[dr] = val;
			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP))
				vcpu->arch.eff_db[dr] = val;
			break;
		case 4 ... 5:
			if (kvm_read_cr4_bits(vcpu, X86_CR4_DE))
				kvm_queue_exception(vcpu, UD_VECTOR);
			break;
		case 6:
			if (val & 0xffffffff00000000ULL) {
				kvm_queue_exception(vcpu, GP_VECTOR);
				break;
			}
			vcpu->arch.dr6 = (val & DR6_VOLATILE) | DR6_FIXED_1;
			break;
		case 7:
			if (val & 0xffffffff00000000ULL) {
				kvm_queue_exception(vcpu, GP_VECTOR);
				break;
			}
			vcpu->arch.dr7 = (val & DR7_VOLATILE) | DR7_FIXED_1;
			if (!(vcpu->guest_debug & KVM_GUESTDBG_USE_HW_BP)) {
				vmcs_writel(GUEST_DR7, vcpu->arch.dr7);
				vcpu->arch.switch_db_regs =
					(val & DR7_BP_EN_MASK);
			}
			break;
		}
	}
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_cpuid(struct kvm_vcpu *vcpu)
{
	kvm_emulate_cpuid(vcpu);
	return 1;
}

static int handle_rdmsr(struct kvm_vcpu *vcpu)
{
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	struct msr_data msr_info;

	msr_info.index = ecx;
	msr_info.host_initiated = false;
	if (vmx_get_msr(vcpu, &msr_info)) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	trace_kvm_msr_read(ecx, msr_info.data);

	/* FIXME: handling of bits 32:63 of rax, rdx */
	vcpu->arch.regs[VCPU_REGS_RAX] = msr_info.data & -1u;
	vcpu->arch.regs[VCPU_REGS_RDX] = (msr_info.data >> 32) & -1u;
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_wrmsr(struct kvm_vcpu *vcpu)
{
	struct msr_data msr;
	u32 ecx = vcpu->arch.regs[VCPU_REGS_RCX];
	u64 data = (vcpu->arch.regs[VCPU_REGS_RAX] & -1u)
		| ((u64)(vcpu->arch.regs[VCPU_REGS_RDX] & -1u) << 32);

	trace_kvm_msr_write(ecx, data);

	msr.data = data;
	msr.index = ecx;
	msr.host_initiated = false;
	if (kvm_set_msr(vcpu, &msr) != 0) {
		kvm_inject_gp(vcpu, 0);
		return 1;
	}

	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_tpr_below_threshold(struct kvm_vcpu *vcpu)
{
	return 1;
}

static int handle_interrupt_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	/* clear pending irq */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);

	++vcpu->stat.irq_window_exits;

	/*
	 * If the user space waits to inject interrupts, exit as soon as
	 * possible
	 */
	if (!irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->run->request_interrupt_window &&
	    !kvm_cpu_has_interrupt(vcpu)) {
		vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
		return 0;
	}
	return 1;
}

static int handle_halt(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	return kvm_emulate_halt(vcpu);
}

static int handle_vmcall(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	kvm_emulate_hypercall(vcpu);
	return 1;
}

static int handle_vmx_insn(struct kvm_vcpu *vcpu)
{
	kvm_queue_exception(vcpu, UD_VECTOR);
	return 1;
}

static int handle_invlpg(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	kvm_mmu_invlpg(vcpu, exit_qualification);
	skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_rdpmc(struct kvm_vcpu *vcpu)
{
	int err;

	err = kvm_rdpmc(vcpu);
	complete_insn_gp(vcpu, err);

	return 1;
}

static int handle_wbinvd(struct kvm_vcpu *vcpu)
{
	skip_emulated_instruction(vcpu);
	/* TODO: Add support for VT-d/pass-through device */
	return 1;
}

static int handle_xsetbv(struct kvm_vcpu *vcpu)
{
	u64 new_bv = kvm_read_edx_eax(vcpu);
	u32 index = kvm_register_read(vcpu, VCPU_REGS_RCX);

	if (kvm_set_xcr(vcpu, index, new_bv) == 0)
		skip_emulated_instruction(vcpu);
	return 1;
}

static int handle_apic_access(struct kvm_vcpu *vcpu)
{
	return emulate_instruction(vcpu, 0) == EMULATE_DONE;
}

static int handle_task_switch(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long exit_qualification;
	bool has_error_code = false;
	u32 error_code = 0;
	u16 tss_selector;
	int reason, type, idt_v, idt_index;

	idt_v = (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK);
	idt_index = (vmx->idt_vectoring_info & VECTORING_INFO_VECTOR_MASK);
	type = (vmx->idt_vectoring_info & VECTORING_INFO_TYPE_MASK);

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	reason = (u32)exit_qualification >> 30;
	if (reason == TASK_SWITCH_GATE && idt_v) {
		switch (type) {
		case INTR_TYPE_NMI_INTR:
			vcpu->arch.nmi_injected = false;
			if (cpu_has_virtual_nmis())
				vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
					      GUEST_INTR_STATE_NMI);
			break;
		case INTR_TYPE_EXT_INTR:
		case INTR_TYPE_SOFT_INTR:
			kvm_clear_interrupt_queue(vcpu);
			break;
		case INTR_TYPE_HARD_EXCEPTION:
			if (vmx->idt_vectoring_info &
			    VECTORING_INFO_DELIVER_CODE_MASK) {
				has_error_code = true;
				error_code =
					vmcs_read32(IDT_VECTORING_ERROR_CODE);
			}
			/* fall through */
		case INTR_TYPE_SOFT_EXCEPTION:
			kvm_clear_exception_queue(vcpu);
			break;
		default:
			break;
		}
	}
	tss_selector = exit_qualification;

	if (!idt_v || (type != INTR_TYPE_HARD_EXCEPTION &&
		       type != INTR_TYPE_EXT_INTR &&
		       type != INTR_TYPE_NMI_INTR))
		skip_emulated_instruction(vcpu);

	if (!kvm_task_switch(vcpu, tss_selector,
			     type == INTR_TYPE_SOFT_INTR ? idt_index : -1, reason,
			     has_error_code, error_code))
		return 0;

	/* clear all local breakpoint enable flags */
	vmcs_writel(GUEST_DR7, vmcs_readl(GUEST_DR7) & ~55);

	/*
	 * TODO: What about debug traps on tss switch?
	 *       Are we supposed to inject them and update dr6?
	 */

	return 1;
}

static int handle_ept_violation(struct kvm_vcpu *vcpu)
{
	unsigned long exit_qualification;
	gpa_t gpa;
	int gla_validity;

	exit_qualification = vmcs_readl(EXIT_QUALIFICATION);

	if (exit_qualification & (1 << 6)) {
		printk(KERN_ERR "EPT: GPA exceeds GAW!\n");
		return -EINVAL;
	}

	gla_validity = (exit_qualification >> 7) & 0x3;
	if (gla_validity != 0x3 && gla_validity != 0x1 && gla_validity != 0) {
		printk(KERN_ERR "EPT: Handling EPT violation failed!\n");
		printk(KERN_ERR "EPT: GPA: 0x%lx, GVA: 0x%lx\n",
			(long unsigned int)vmcs_read64(GUEST_PHYSICAL_ADDRESS),
			vmcs_readl(GUEST_LINEAR_ADDRESS));
		printk(KERN_ERR "EPT: Exit qualification is 0x%lx\n",
			(long unsigned int)exit_qualification);
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_VIOLATION;
		return 0;
	}

	/*
	 * EPT violation happened while executing iret from NMI,
	 * "blocked by NMI" bit has to be set before next VM entry.
	 * There are errata that may cause this bit to not be set:
	 * AAK134, BY25.
	 */
	if (!(to_vmx(vcpu)->idt_vectoring_info & VECTORING_INFO_VALID_MASK) &&
			cpu_has_virtual_nmis() &&
			(exit_qualification & INTR_INFO_UNBLOCK_NMI))
		vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO, GUEST_INTR_STATE_NMI);

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);
	trace_kvm_page_fault(gpa, exit_qualification);
	return kvm_mmu_page_fault(vcpu, gpa & PAGE_MASK, 0, NULL, 0);
}

static u64 ept_rsvd_mask(u64 spte, int level)
{
	int i;
	u64 mask = 0;

	for (i = 51; i > boot_cpu_data.x86_phys_bits; i--)
		mask |= (1ULL << i);

	if (level > 2)
		/* bits 7:3 reserved */
		mask |= 0xf8;
	else if (level == 2) {
		if (spte & (1ULL << 7))
			/* 2MB ref, bits 20:12 reserved */
			mask |= 0x1ff000;
		else
			/* bits 6:3 reserved */
			mask |= 0x78;
	}

	return mask;
}

static void ept_misconfig_inspect_spte(struct kvm_vcpu *vcpu, u64 spte,
				       int level)
{
	printk(KERN_ERR "%s: spte 0x%llx level %d\n", __func__, spte, level);

	/* 010b (write-only) */
	WARN_ON((spte & 0x7) == 0x2);

	/* 110b (write/execute) */
	WARN_ON((spte & 0x7) == 0x6);

	/* 100b (execute-only) and value not supported by logical processor */
	if (!cpu_has_vmx_ept_execute_only())
		WARN_ON((spte & 0x7) == 0x4);

	/* not 000b */
	if ((spte & 0x7)) {
		u64 rsvd_bits = spte & ept_rsvd_mask(spte, level);

		if (rsvd_bits != 0) {
			printk(KERN_ERR "%s: rsvd_bits = 0x%llx\n",
					 __func__, rsvd_bits);
			WARN_ON(1);
		}

		if (level == 1 || (level == 2 && (spte & (1ULL << 7)))) {
			u64 ept_mem_type = (spte & 0x38) >> 3;

			if (ept_mem_type == 2 || ept_mem_type == 3 ||
			    ept_mem_type == 7) {
				printk(KERN_ERR "%s: ept_mem_type=0x%llx\n",
						__func__, ept_mem_type);
				WARN_ON(1);
			}
		}
	}
}

static int handle_ept_misconfig(struct kvm_vcpu *vcpu)
{
	u64 sptes[4];
	int nr_sptes, i;
	gpa_t gpa;

	gpa = vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	printk(KERN_ERR "EPT: Misconfiguration.\n");
	printk(KERN_ERR "EPT: GPA: 0x%llx\n", gpa);

	nr_sptes = kvm_mmu_get_spte_hierarchy(vcpu, gpa, sptes);

	for (i = PT64_ROOT_LEVEL; i > PT64_ROOT_LEVEL - nr_sptes; --i)
		ept_misconfig_inspect_spte(vcpu, sptes[i-1], i);

	vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
	vcpu->run->hw.hardware_exit_reason = EXIT_REASON_EPT_MISCONFIG;

	return 0;
}

static int handle_nmi_window(struct kvm_vcpu *vcpu)
{
	u32 cpu_based_vm_exec_control;

	/* clear pending NMI */
	cpu_based_vm_exec_control = vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	cpu_based_vm_exec_control &= ~CPU_BASED_VIRTUAL_NMI_PENDING;
	vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control);
	++vcpu->stat.nmi_window_exits;

	return 1;
}

static void handle_invalid_guest_state(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	enum emulation_result err = EMULATE_DONE;

	local_irq_enable();
	preempt_enable();

	while (!guest_state_valid(vcpu)) {
		err = emulate_instruction(vcpu, 0);

		if (err == EMULATE_DO_MMIO)
			break;

		if (err != EMULATE_DONE)
			break;

		if (signal_pending(current))
			break;
		if (need_resched())
			schedule();
	}

	preempt_disable();
	local_irq_disable();

	vmx->invalid_state_emulation_result = err;
}

static int __grow_ple_window(int val)
{
	if (ple_window_grow < 1)
		return ple_window;

	val = min(val, ple_window_actual_max);

	if (ple_window_grow < ple_window)
		val *= ple_window_grow;
	else
		val += ple_window_grow;

	return val;
}

static int __shrink_ple_window(int val, int modifier, int minimum)
{
	if (modifier < 1)
		return ple_window;

	if (modifier < ple_window)
		val /= modifier;
	else
		val -= modifier;

	return max(val, minimum);
}

static void grow_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int old = vmx->ple_window;

	vmx->ple_window = __grow_ple_window(old);

	if (vmx->ple_window != old)
		vmx->ple_window_dirty = true;

	trace_kvm_ple_window_grow(vcpu->vcpu_id, vmx->ple_window, old);
}

static void shrink_ple_window(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int old = vmx->ple_window;

	vmx->ple_window = __shrink_ple_window(old,
	                                      ple_window_shrink, ple_window);

	if (vmx->ple_window != old)
		vmx->ple_window_dirty = true;

	trace_kvm_ple_window_shrink(vcpu->vcpu_id, vmx->ple_window, old);
}

/*
 * ple_window_actual_max is computed to be one grow_ple_window() below
 * ple_window_max. (See __grow_ple_window for the reason.)
 * This prevents overflows, because ple_window_max is int.
 * ple_window_max effectively rounded down to a multiple of ple_window_grow in
 * this process.
 * ple_window_max is also prevented from setting vmx->ple_window < ple_window.
 */
static void update_ple_window_actual_max(void)
{
	ple_window_actual_max =
			__shrink_ple_window(max(ple_window_max, ple_window),
			                    ple_window_grow, INT_MIN);
}

/*
 * Indicate a busy-waiting vcpu in spinlock. We do not enable the PAUSE
 * exiting, so only get here on cpu with PAUSE-Loop-Exiting.
 */
static int handle_pause(struct kvm_vcpu *vcpu)
{
	if (ple_gap)
		grow_ple_window(vcpu);

	skip_emulated_instruction(vcpu);
	kvm_vcpu_on_spin(vcpu);

	return 1;
}

/*
 * The exit handlers return 1 if the exit was handled fully and guest execution
 * may resume.  Otherwise they set the kvm_run parameter to indicate what needs
 * to be done to userspace and return 0.
 */
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
	[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
	[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
	[EXIT_REASON_TRIPLE_FAULT]            = handle_triple_fault,
	[EXIT_REASON_NMI_WINDOW]	      = handle_nmi_window,
	[EXIT_REASON_IO_INSTRUCTION]          = handle_io,
	[EXIT_REASON_CR_ACCESS]               = handle_cr,
	[EXIT_REASON_DR_ACCESS]               = handle_dr,
	[EXIT_REASON_CPUID]                   = handle_cpuid,
	[EXIT_REASON_MSR_READ]                = handle_rdmsr,
	[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
	[EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
	[EXIT_REASON_HLT]                     = handle_halt,
	[EXIT_REASON_INVLPG]		      = handle_invlpg,
	[EXIT_REASON_RDPMC]		      = handle_rdpmc,	
	[EXIT_REASON_VMCALL]                  = handle_vmcall,
	[EXIT_REASON_VMCLEAR]	              = handle_vmx_insn,
	[EXIT_REASON_VMLAUNCH]                = handle_vmx_insn,
	[EXIT_REASON_VMPTRLD]                 = handle_vmx_insn,
	[EXIT_REASON_VMPTRST]                 = handle_vmx_insn,
	[EXIT_REASON_VMREAD]                  = handle_vmx_insn,
	[EXIT_REASON_VMRESUME]                = handle_vmx_insn,
	[EXIT_REASON_VMWRITE]                 = handle_vmx_insn,
	[EXIT_REASON_VMOFF]                   = handle_vmx_insn,
	[EXIT_REASON_VMON]                    = handle_vmx_insn,
	[EXIT_REASON_TPR_BELOW_THRESHOLD]     = handle_tpr_below_threshold,
	[EXIT_REASON_APIC_ACCESS]             = handle_apic_access,
	[EXIT_REASON_INVVPID]		      = handle_vmx_insn,
	[EXIT_REASON_INVEPT]		      = handle_vmx_insn,
	[EXIT_REASON_WBINVD]                  = handle_wbinvd,
	[EXIT_REASON_XSETBV]                  = handle_xsetbv,
	[EXIT_REASON_TASK_SWITCH]             = handle_task_switch,
	[EXIT_REASON_MCE_DURING_VMENTRY]      = handle_machine_check,
	[EXIT_REASON_EPT_VIOLATION]	      = handle_ept_violation,
	[EXIT_REASON_EPT_MISCONFIG]           = handle_ept_misconfig,
	[EXIT_REASON_PAUSE_INSTRUCTION]       = handle_pause,
};

static const int kvm_vmx_max_exit_handlers =
	ARRAY_SIZE(kvm_vmx_exit_handlers);

/*
 * The guest has exited.  See if we can fix it or if we need userspace
 * assistance.
 */
static int vmx_handle_exit(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	u32 exit_reason = vmx->exit_reason;
	u32 vectoring_info = vmx->idt_vectoring_info;

	trace_kvm_exit(exit_reason, kvm_rip_read(vcpu), KVM_ISA_VMX);

	/* If we need to emulate an MMIO from handle_invalid_guest_state
	 * we just return 0 */
	if (vmx->emulation_required && emulate_invalid_guest_state) {
		if (guest_state_valid(vcpu))
			vmx->emulation_required = 0;
		return vmx->invalid_state_emulation_result != EMULATE_DO_MMIO;
	}

	/* Access CR3 don't cause VMExit in paging mode, so we need
	 * to sync with guest real CR3. */
	if (enable_ept && is_paging(vcpu))
		vcpu->arch.cr3 = vmcs_readl(GUEST_CR3);

	if (exit_reason & VMX_EXIT_REASONS_FAILED_VMENTRY) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= exit_reason;
		return 0;
	}

	if (unlikely(vmx->fail)) {
		vcpu->run->exit_reason = KVM_EXIT_FAIL_ENTRY;
		vcpu->run->fail_entry.hardware_entry_failure_reason
			= vmcs_read32(VM_INSTRUCTION_ERROR);
		return 0;
	}

	if ((vectoring_info & VECTORING_INFO_VALID_MASK) &&
			(exit_reason != EXIT_REASON_EXCEPTION_NMI &&
			exit_reason != EXIT_REASON_EPT_VIOLATION &&
			exit_reason != EXIT_REASON_TASK_SWITCH))
		printk(KERN_WARNING "%s: unexpected, valid vectoring info "
		       "(0x%x) and exit reason is 0x%x\n",
		       __func__, vectoring_info, exit_reason);

	if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked)) {
		if (vmx_interrupt_allowed(vcpu)) {
			vmx->soft_vnmi_blocked = 0;
		} else if (vmx->vnmi_blocked_time > 1000000000LL &&
			   vcpu->arch.nmi_pending) {
			/*
			 * This CPU don't support us in finding the end of an
			 * NMI-blocked window if the guest runs with IRQs
			 * disabled. So we pull the trigger after 1 s of
			 * futile waiting, but inform the user about this.
			 */
			printk(KERN_WARNING "%s: Breaking out of NMI-blocked "
			       "state on VCPU %d after 1 s timeout\n",
			       __func__, vcpu->vcpu_id);
			vmx->soft_vnmi_blocked = 0;
		}
	}

	if (exit_reason < kvm_vmx_max_exit_handlers
	    && kvm_vmx_exit_handlers[exit_reason])
		return kvm_vmx_exit_handlers[exit_reason](vcpu);
	else {
		vcpu->run->exit_reason = KVM_EXIT_UNKNOWN;
		vcpu->run->hw.hardware_exit_reason = exit_reason;
	}
	return 0;
}

/*
 * Software based L1D cache flush which is used when microcode providing
 * the cache control MSR is not loaded.
 *
 * The L1D cache is 32 KiB on Nehalem and later microarchitectures, but to
 * flush it is required to read in 64 KiB because the replacement algorithm
 * is not exactly LRU. This could be sized at runtime via topology
 * information but as all relevant affected CPUs have 32KiB L1D cache size
 * there is no point in doing so.
 */
#define L1D_CACHE_ORDER 4
static void *vmx_l1d_flush_pages;

static void vmx_l1d_flush(struct kvm_vcpu *vcpu)
{
	int size = PAGE_SIZE << L1D_CACHE_ORDER;
	bool always;

	/*
	 * This code is only executed when the the flush mode is 'cond' or
	 * 'always'
	 *
	 * If 'flush always', keep the flush bit set, otherwise clear
	 * it. The flush bit gets set again either from vcpu_run() or from
	 * one of the unsafe VMEXIT handlers.
	 */
	always = l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_ALWAYS;
	vcpu->arch.l1tf_flush_l1d = always;

	vcpu->stat.l1d_flush++;

	if (static_cpu_has(X86_FEATURE_FLUSH_L1D)) {
		wrmsrl(MSR_IA32_FLUSH_CMD, L1D_FLUSH);
		return;
	}

	asm volatile(
		/* First ensure the pages are in the TLB */
		"xorl	%%eax, %%eax\n"
		".Lpopulate_tlb:\n\t"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$4096, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lpopulate_tlb\n\t"
		"xorl	%%eax, %%eax\n\t"
		"cpuid\n\t"
		/* Now fill the cache */
		"xorl	%%eax, %%eax\n"
		".Lfill_cache:\n"
		"movzbl	(%[flush_pages], %%" _ASM_AX "), %%ecx\n\t"
		"addl	$64, %%eax\n\t"
		"cmpl	%%eax, %[size]\n\t"
		"jne	.Lfill_cache\n\t"
		"lfence\n"
		:: [flush_pages] "r" (vmx_l1d_flush_pages),
		    [size] "r" (size)
		: "eax", "ebx", "ecx", "edx");
}

static void update_cr8_intercept(struct kvm_vcpu *vcpu, int tpr, int irr)
{
	if (irr == -1 || tpr < irr) {
		vmcs_write32(TPR_THRESHOLD, 0);
		return;
	}

	vmcs_write32(TPR_THRESHOLD, irr);
}

static void vmx_complete_interrupts(struct vcpu_vmx *vmx)
{
	u32 exit_intr_info;
	u32 idt_vectoring_info = vmx->idt_vectoring_info;
	bool unblock_nmi;
	u8 vector;
	int type;
	bool idtv_info_valid;

	exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	vmx->exit_reason = vmcs_read32(VM_EXIT_REASON);

	/* Handle machine checks before interrupts are enabled */
	if ((vmx->exit_reason == EXIT_REASON_MCE_DURING_VMENTRY)
	    || (vmx->exit_reason == EXIT_REASON_EXCEPTION_NMI
		&& is_machine_check(exit_intr_info)))
		kvm_machine_check();

	/* We need to handle NMIs before interrupts are enabled */
	if ((exit_intr_info & INTR_INFO_INTR_TYPE_MASK) == INTR_TYPE_NMI_INTR &&
	    (exit_intr_info & INTR_INFO_VALID_MASK)) {
		kvm_before_handle_nmi(&vmx->vcpu);
		asm("int $2");
		kvm_after_handle_nmi(&vmx->vcpu);
	}

	idtv_info_valid = idt_vectoring_info & VECTORING_INFO_VALID_MASK;

	if (cpu_has_virtual_nmis()) {
		unblock_nmi = (exit_intr_info & INTR_INFO_UNBLOCK_NMI) != 0;
		vector = exit_intr_info & INTR_INFO_VECTOR_MASK;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Re-set bit "block by NMI" before VM entry if vmexit caused by
		 * a guest IRET fault.
		 * SDM 3: 23.2.2 (September 2008)
		 * Bit 12 is undefined in any of the following cases:
		 *  If the VM exit sets the valid bit in the IDT-vectoring
		 *   information field.
		 *  If the VM exit is due to a double fault.
		 */
		if ((exit_intr_info & INTR_INFO_VALID_MASK) && unblock_nmi &&
		    vector != DF_VECTOR && !idtv_info_valid)
			vmcs_set_bits(GUEST_INTERRUPTIBILITY_INFO,
				      GUEST_INTR_STATE_NMI);
	} else if (unlikely(vmx->soft_vnmi_blocked))
		vmx->vnmi_blocked_time +=
			ktime_to_ns(ktime_sub(ktime_get(), vmx->entry_time));

	vmx->vcpu.arch.nmi_injected = false;
	kvm_clear_exception_queue(&vmx->vcpu);
	kvm_clear_interrupt_queue(&vmx->vcpu);

	if (!idtv_info_valid)
		return;

	vector = idt_vectoring_info & VECTORING_INFO_VECTOR_MASK;
	type = idt_vectoring_info & VECTORING_INFO_TYPE_MASK;

	switch (type) {
	case INTR_TYPE_NMI_INTR:
		vmx->vcpu.arch.nmi_injected = true;
		/*
		 * SDM 3: 27.7.1.2 (September 2008)
		 * Clear bit "block by NMI" before VM entry if a NMI
		 * delivery faulted.
		 */
		vmcs_clear_bits(GUEST_INTERRUPTIBILITY_INFO,
				GUEST_INTR_STATE_NMI);
		break;
	case INTR_TYPE_SOFT_EXCEPTION:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_HARD_EXCEPTION:
		if (idt_vectoring_info & VECTORING_INFO_DELIVER_CODE_MASK) {
			u32 err = vmcs_read32(IDT_VECTORING_ERROR_CODE);
			kvm_queue_exception_e(&vmx->vcpu, vector, err);
		} else
			kvm_queue_exception(&vmx->vcpu, vector);
		break;
	case INTR_TYPE_SOFT_INTR:
		vmx->vcpu.arch.event_exit_inst_len =
			vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
		/* fall through */
	case INTR_TYPE_EXT_INTR:
		kvm_queue_interrupt(&vmx->vcpu, vector,
			type == INTR_TYPE_SOFT_INTR);
		break;
	default:
		break;
	}
}

static void vmx_handle_external_intr(struct kvm_vcpu *vcpu)
{
	u32 exit_intr_info = vmcs_read32(VM_EXIT_INTR_INFO);

	/*
	 * If external interrupt exists, IF bit is set in rflags/eflags on the
	 * interrupt stack frame, and interrupt will be enabled on a return
	 * from interrupt handler.
	 */
	if ((exit_intr_info & (INTR_INFO_VALID_MASK | INTR_INFO_INTR_TYPE_MASK))
			== (INTR_INFO_VALID_MASK | INTR_TYPE_EXT_INTR)) {
		unsigned int vector;
		unsigned long entry;
		gate_desc *desc;
		struct vcpu_vmx *vmx = to_vmx(vcpu);
#ifdef CONFIG_X86_64
		unsigned long tmp;
#endif

		vector =  exit_intr_info & INTR_INFO_VECTOR_MASK;
		desc = (gate_desc *)vmx->host_idt_base + vector;
		entry = gate_offset(*desc);
		asm volatile(
#ifdef CONFIG_X86_64
			"mov %%" _ASM_SP ", %[sp]\n\t"
			"and $0xfffffffffffffff0, %%" _ASM_SP "\n\t"
			"push $%c[ss]\n\t"
			"push %[sp]\n\t"
#endif
			"pushf\n\t"
			"orl $0x200, (%%" _ASM_SP ")\n\t"
			__ASM_SIZE(push) " $%c[cs]\n\t"
			CALL_NOSPEC
			:
#ifdef CONFIG_X86_64
			[sp]"=&r"(tmp)
#endif
			:
			THUNK_TARGET(entry),
			[ss]"i"(__KERNEL_DS),
			[cs]"i"(__KERNEL_CS)
			);
		vcpu->arch.l1tf_flush_l1d = true;
	} else
		local_irq_enable();
}

/*
 * Failure to inject an interrupt should give us the information
 * in IDT_VECTORING_INFO_FIELD.  However, if the failure occurs
 * when fetching the interrupt redirection bitmap in the real-mode
 * tss, this doesn't happen.  So we do it ourselves.
 */
static void fixup_rmode_irq(struct vcpu_vmx *vmx)
{
	vmx->rmode.irq.pending = 0;
	if (kvm_rip_read(&vmx->vcpu) + 1 != vmx->rmode.irq.rip)
		return;
	kvm_rip_write(&vmx->vcpu, vmx->rmode.irq.rip);
	if (vmx->idt_vectoring_info & VECTORING_INFO_VALID_MASK) {
		vmx->idt_vectoring_info &= ~VECTORING_INFO_TYPE_MASK;
		vmx->idt_vectoring_info |= INTR_TYPE_EXT_INTR;
		return;
	}
	vmx->idt_vectoring_info =
		VECTORING_INFO_VALID_MASK
		| INTR_TYPE_EXT_INTR
		| vmx->rmode.irq.vector;
}

static void atomic_switch_perf_msrs(struct vcpu_vmx *vmx)
{
	int i, nr_msrs;
	struct perf_guest_switch_msr *msrs;

	msrs = perf_guest_get_msrs(&nr_msrs);

	if (!msrs)
		return;

	for (i = 0; i < nr_msrs; i++)
		if (msrs[i].host == msrs[i].guest)
			clear_atomic_switch_msr(vmx, msrs[i].msr);
		else
			add_atomic_switch_msr(vmx, msrs[i].msr, msrs[i].guest,
					msrs[i].host, false);
}

#ifdef CONFIG_X86_64
#define R "r"
#define Q "q"
#else
#define R "e"
#define Q "l"
#endif

static void vmx_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	unsigned long cr4;

	if (enable_ept && is_paging(vcpu)) {
		vmcs_writel(GUEST_CR3, vcpu->arch.cr3);
		ept_load_pdptrs(vcpu);
	}
	/* Record the guest's net vcpu time for enforced NMI injections. */
	if (unlikely(!cpu_has_virtual_nmis() && vmx->soft_vnmi_blocked))
		vmx->entry_time = ktime_get();

	/* Handle invalid guest state instead of entering VMX */
	if (vmx->emulation_required && emulate_invalid_guest_state) {
		handle_invalid_guest_state(vcpu);
		return;
	}

	if (vmx->ple_window_dirty) {
		vmx->ple_window_dirty = false;
		vmcs_write32(PLE_WINDOW, vmx->ple_window);
	}

	if (test_bit(VCPU_REGS_RSP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RSP, vcpu->arch.regs[VCPU_REGS_RSP]);
	if (test_bit(VCPU_REGS_RIP, (unsigned long *)&vcpu->arch.regs_dirty))
		vmcs_writel(GUEST_RIP, vcpu->arch.regs[VCPU_REGS_RIP]);

	cr4 = read_cr4();
	if(unlikely(cr4 != vmx->host_state.vmcs_host_cr4)) {
		vmcs_writel(HOST_CR4, cr4);
		vmx->host_state.vmcs_host_cr4 = cr4;
	}
	/* When single-stepping over STI and MOV SS, we must clear the
	 * corresponding interruptibility bits in the guest state. Otherwise
	 * vmentry fails as it then expects bit 14 (BS) in pending debug
	 * exceptions being set, but that's not correct for the guest debugging
	 * case. */
	if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
		vmx_set_interrupt_shadow(vcpu, 0);

	/*
	 * Loading guest fpu may have cleared host cr0.ts
	 */
	vmcs_writel(HOST_CR0, read_cr0());

	if (vcpu->arch.switch_db_regs)
		set_debugreg(vcpu->arch.dr6, 6);

	atomic_switch_perf_msrs(vmx);

	x86_spec_ctrl_set_guest(vmx->spec_ctrl, 0);

	/* L1D Flush includes CPU buffer clear to mitigate MDS */
	if (unlikely((l1tf_vmx_mitigation != VMENTER_L1D_FLUSH_NEVER) &&
		     (l1tf_vmx_mitigation != VMENTER_L1D_FLUSH_EPT_DISABLED) &&
		     (l1tf_vmx_mitigation != VMENTER_L1D_FLUSH_NOT_REQUIRED) &&
		      vcpu->arch.l1tf_flush_l1d))
		vmx_l1d_flush(vcpu);
	else if (static_cpu_has(X86_FEATURE_MDS_USR_CLR))
		mds_clear_cpu_buffers();

	asm(
		/* Store host registers */
		"push %%"R"dx; push %%"R"bp;"
		"push %%"R"cx \n\t"
		"cmp %%"R"sp, %c[host_rsp](%0) \n\t"
		"je 1f \n\t"
		"mov %%"R"sp, %c[host_rsp](%0) \n\t"
		__ex(ASM_VMX_VMWRITE_RSP_RDX) "\n\t"
		"1: \n\t"
		/* Reload cr2 if changed */
		"mov %c[cr2](%0), %%"R"ax \n\t"
		"mov %%cr2, %%"R"dx \n\t"
		"cmp %%"R"ax, %%"R"dx \n\t"
		"je 2f \n\t"
		"mov %%"R"ax, %%cr2 \n\t"
		"2: \n\t"
		/* Check if vmlaunch of vmresume is needed */
		"cmpl $0, %c[launched](%0) \n\t"
		/* Load guest registers.  Don't clobber flags. */
		"mov %c[rax](%0), %%"R"ax \n\t"
		"mov %c[rbx](%0), %%"R"bx \n\t"
		"mov %c[rdx](%0), %%"R"dx \n\t"
		"mov %c[rsi](%0), %%"R"si \n\t"
		"mov %c[rdi](%0), %%"R"di \n\t"
		"mov %c[rbp](%0), %%"R"bp \n\t"
#ifdef CONFIG_X86_64
		"mov %c[r8](%0),  %%r8  \n\t"
		"mov %c[r9](%0),  %%r9  \n\t"
		"mov %c[r10](%0), %%r10 \n\t"
		"mov %c[r11](%0), %%r11 \n\t"
		"mov %c[r12](%0), %%r12 \n\t"
		"mov %c[r13](%0), %%r13 \n\t"
		"mov %c[r14](%0), %%r14 \n\t"
		"mov %c[r15](%0), %%r15 \n\t"
#endif
		"mov %c[rcx](%0), %%"R"cx \n\t" /* kills %0 (ecx) */

		/* Enter guest mode */
		"jne .Llaunched \n\t"
		__ex(ASM_VMX_VMLAUNCH) "\n\t"
		"jmp .Lkvm_vmx_return \n\t"
		".Llaunched: " __ex(ASM_VMX_VMRESUME) "\n\t"
		".Lkvm_vmx_return: "
		/* Save guest registers, load host registers, keep flags */
		"xchg %0,     (%%"R"sp) \n\t"
		"mov %%"R"ax, %c[rax](%0) \n\t"
		"mov %%"R"bx, %c[rbx](%0) \n\t"
		"push"Q" (%%"R"sp); pop"Q" %c[rcx](%0) \n\t"
		"mov %%"R"dx, %c[rdx](%0) \n\t"
		"mov %%"R"si, %c[rsi](%0) \n\t"
		"mov %%"R"di, %c[rdi](%0) \n\t"
		"mov %%"R"bp, %c[rbp](%0) \n\t"
#ifdef CONFIG_X86_64
		"mov %%r8,  %c[r8](%0) \n\t"
		"mov %%r9,  %c[r9](%0) \n\t"
		"mov %%r10, %c[r10](%0) \n\t"
		"mov %%r11, %c[r11](%0) \n\t"
		"mov %%r12, %c[r12](%0) \n\t"
		"mov %%r13, %c[r13](%0) \n\t"
		"mov %%r14, %c[r14](%0) \n\t"
		"mov %%r15, %c[r15](%0) \n\t"
#endif
		"mov %%cr2, %%"R"ax   \n\t"
		"mov %%"R"ax, %c[cr2](%0) \n\t"

		"pop  %%"R"bp; pop  %%"R"bp; pop  %%"R"dx \n\t"
		"setbe %c[fail](%0) \n\t"
		/*
		 * Clear host registers marked as clobbered to prevent
		 * speculative use.
		 */
		"xor %%" _ASM_BX ", %%" _ASM_BX " \n\t"
		"xor %%" _ASM_SI ", %%" _ASM_SI " \n\t"
		"xor %%" _ASM_DI ", %%" _ASM_DI " \n\t"
#ifdef CONFIG_X86_64
		"xor %%r8, %%r8 \n\t"
		"xor %%r9, %%r9 \n\t"
		"xor %%r10, %%r10 \n\t"
		"xor %%r11, %%r11 \n\t"
		"xor %%r12, %%r12 \n\t"
		"xor %%r13, %%r13 \n\t"
		"xor %%r14, %%r14 \n\t"
		"xor %%r15, %%r15 \n\t"
#endif
	      : : "c"(vmx), "d"((unsigned long)HOST_RSP),
		[launched]"i"(offsetof(struct vcpu_vmx, launched)),
		[fail]"i"(offsetof(struct vcpu_vmx, fail)),
		[host_rsp]"i"(offsetof(struct vcpu_vmx, host_rsp)),
		[rax]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RAX])),
		[rbx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBX])),
		[rcx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RCX])),
		[rdx]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDX])),
		[rsi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RSI])),
		[rdi]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RDI])),
		[rbp]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_RBP])),
#ifdef CONFIG_X86_64
		[r8]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R8])),
		[r9]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R9])),
		[r10]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R10])),
		[r11]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R11])),
		[r12]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R12])),
		[r13]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R13])),
		[r14]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R14])),
		[r15]"i"(offsetof(struct vcpu_vmx, vcpu.arch.regs[VCPU_REGS_R15])),
#endif
		[cr2]"i"(offsetof(struct vcpu_vmx, vcpu.arch.cr2))
	      : "cc", "memory"
		, R"bx", R"di", R"si"
#ifdef CONFIG_X86_64
		, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
#endif
	      );

	if (cpu_has_spec_ctrl()) {
		rdmsrl(MSR_IA32_SPEC_CTRL, vmx->spec_ctrl);
		x86_spec_ctrl_restore_host(vmx->spec_ctrl, 0);
	}

	/* Eliminate branch target predictions from guest mode */
	fill_RSB();

	vcpu->arch.regs_avail = ~((1 << VCPU_REGS_RIP) | (1 << VCPU_REGS_RSP)
				  | (1 << VCPU_EXREG_PDPTR));
	vcpu->arch.regs_dirty = 0;

	if (vcpu->arch.switch_db_regs)
		get_debugreg(vcpu->arch.dr6, 6);

	vmx->idt_vectoring_info = vmcs_read32(IDT_VECTORING_INFO_FIELD);
	if (vmx->rmode.irq.pending)
		fixup_rmode_irq(vmx);

	asm("mov %0, %%ds; mov %0, %%es" : : "r"(__USER_DS));
	vmx->launched = 1;

	vmx_complete_interrupts(vmx);
}

#undef R
#undef Q

static void vmx_free_vmcs(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	if (vmx->vmcs) {
		vcpu_clear(vmx);
		free_vmcs(vmx->vmcs);
		vmx->vmcs = NULL;

		/*
		 * The VMCS could be recycled, causing a false negative in
		 * vmx_vcpu_load; block speculative execution.
		 */
		spec_ctrl_ibpb();
	}
}

static void vmx_free_vcpu(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	free_vpid(vmx);
	vmx_free_vmcs(vcpu);
	kfree(vmx->guest_msrs);
	kvm_vcpu_uninit(vcpu);
	kmem_cache_free(kvm_vcpu_cache, vmx);
}

static inline void vmcs_init(struct vmcs *vmcs)
{
	u64 phys_addr = __pa(per_cpu(vmxarea, raw_smp_processor_id()));

	if (!vmm_exclusive)
		kvm_cpu_vmxon(phys_addr);

	vmcs_clear(vmcs);

	if (!vmm_exclusive)
		kvm_cpu_vmxoff();
}

static struct kvm_vcpu *vmx_create_vcpu(struct kvm *kvm, unsigned int id)
{
	int err;
	struct vcpu_vmx *vmx = kmem_cache_zalloc(kvm_vcpu_cache, GFP_KERNEL);
	int cpu;

	if (!vmx)
		return ERR_PTR(-ENOMEM);

	allocate_vpid(vmx);

	err = kvm_vcpu_init(&vmx->vcpu, kvm, id);
	if (err)
		goto free_vcpu;

	vmx->guest_msrs = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!vmx->guest_msrs) {
		err = -ENOMEM;
		goto uninit_vcpu;
	}

	vmx->vmcs = alloc_vmcs();
	if (!vmx->vmcs)
		goto free_msrs;

	vmcs_init(vmx->vmcs);

	cpu = get_cpu();
	vmx_vcpu_load(&vmx->vcpu, cpu);
	vmx->vcpu.cpu = cpu;
	err = vmx_vcpu_setup(vmx);
	vmx_vcpu_put(&vmx->vcpu);
	put_cpu();
	if (err)
		goto free_vmcs;
	if (vm_need_virtualize_apic_accesses(kvm))
		if (alloc_apic_access_page(kvm) != 0)
			goto free_vmcs;

	if (enable_ept) {
		if (!kvm->arch.ept_identity_map_addr)
			kvm->arch.ept_identity_map_addr =
				VMX_EPT_IDENTITY_PAGETABLE_ADDR;
		err = -ENOMEM;
		if (alloc_identity_pagetable(kvm) != 0)
			goto free_vmcs;
		if (!init_rmode_identity_map(kvm))
			goto free_vmcs;
	}

	return &vmx->vcpu;

free_vmcs:
	free_vmcs(vmx->vmcs);
free_msrs:
	kfree(vmx->guest_msrs);
uninit_vcpu:
	kvm_vcpu_uninit(&vmx->vcpu);
free_vcpu:
	free_vpid(vmx);
	kmem_cache_free(kvm_vcpu_cache, vmx);
	return ERR_PTR(err);
}


#define L1TF_MSG_SMT "L1TF CPU bug present and SMT on, data leak possible. See CVE-2018-3646 and https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html for details.\n"
#define L1TF_MSG_L1D "L1TF CPU bug present and virtualization mitigation disabled, data leak possible. See CVE-2018-3646 and https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/l1tf.html for details.\n"

static int vmx_vm_init(struct kvm *kvm)
{
	if (boot_cpu_has_bug(X86_BUG_L1TF) && enable_ept) {
		switch (l1tf_mitigation) {
		case L1TF_MITIGATION_OFF:
		case L1TF_MITIGATION_FLUSH_NOWARN:
			/* 'I explicitly don't care' is set */
			break;
		case L1TF_MITIGATION_FLUSH:
		case L1TF_MITIGATION_FLUSH_NOSMT:
		case L1TF_MITIGATION_FULL:
			/*
			 * Warn upon starting the first VM in a potentially
			 * insecure environment.
			 */
			if (cpu_smt_control == CPU_SMT_ENABLED)
				pr_warn_once(L1TF_MSG_SMT);
			if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_NEVER)
				pr_warn_once(L1TF_MSG_L1D);
			break;
		case L1TF_MITIGATION_FULL_FORCE:
			/* Flush is enforced */
			break;
		}
	}
	return 0;
}

static void __init vmx_check_processor_compat(void *rtn)
{
	struct vmcs_config vmcs_conf;

	*(int *)rtn = 0;
	if (setup_vmcs_config(&vmcs_conf) < 0)
		*(int *)rtn = -EIO;
	if (memcmp(&vmcs_config, &vmcs_conf, sizeof(struct vmcs_config)) != 0) {
		printk(KERN_ERR "kvm: CPU %d feature inconsistency!\n",
				smp_processor_id());
		*(int *)rtn = -EIO;
	}
}

static int get_ept_level(void)
{
	return VMX_EPT_DEFAULT_GAW + 1;
}

static u64 vmx_get_mt_mask(struct kvm_vcpu *vcpu, gfn_t gfn, bool is_mmio)
{
	u64 ret;

	/* For VT-d and EPT combination
	 * 1. MMIO: always map as UC
	 * 2. EPT with VT-d:
	 *   a. VT-d without snooping control feature: can't guarantee the
	 *	result, try to trust guest.
	 *   b. VT-d with snooping control feature: snooping control feature of
	 *	VT-d engine can guarantee the cache correctness. Just set it
	 *	to WB to keep consistent with host. So the same as item 3.
	 * 3. EPT without VT-d: always map as WB and set IGMT=1 to keep
	 *    consistent with host MTRR
	 */
	if (is_mmio)
		ret = MTRR_TYPE_UNCACHABLE << VMX_EPT_MT_EPTE_SHIFT;
	else if (vcpu->kvm->arch.iommu_domain &&
		!(vcpu->kvm->arch.iommu_flags & KVM_IOMMU_CACHE_COHERENCY))
		ret = kvm_get_guest_memory_type(vcpu, gfn) <<
		      VMX_EPT_MT_EPTE_SHIFT;
	else
		ret = (MTRR_TYPE_WRBACK << VMX_EPT_MT_EPTE_SHIFT)
			| VMX_EPT_IGMT_BIT;

	return ret;
}

static void vmx_cpuid_update(struct kvm_vcpu *vcpu)
{
	struct kvm_cpuid_entry2 *best;
	u32 exec_control;

	/* Exposing INVPCID only when PCID is exposed */
	best = kvm_find_cpuid_entry(vcpu, 0x7, 0);
	if (vmx_invpcid_supported() &&
	    best && (best->ebx & bit(X86_FEATURE_INVPCID)) &&
	    guest_cpuid_has_pcid(vcpu)) {
		exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
		exec_control |= SECONDARY_EXEC_ENABLE_INVPCID;
		vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
			     exec_control);
	} else {
		if (cpu_has_secondary_exec_ctrls()) {
			exec_control = vmcs_read32(SECONDARY_VM_EXEC_CONTROL);
			exec_control &= ~SECONDARY_EXEC_ENABLE_INVPCID;
			vmcs_write32(SECONDARY_VM_EXEC_CONTROL,
				     exec_control);
		}
		if (best)
			best->ebx &= ~bit(X86_FEATURE_INVPCID);
	}
}

static int vmx_get_lpage_level(void)
{
	if (enable_ept && !cpu_has_vmx_ept_1g_page())
		return PT_DIRECTORY_LEVEL;
	else
		/* For shadow and EPT supported 1GB page */
		return PT_PDPE_LEVEL;
}

static void vmx_sched_in(struct kvm_vcpu *vcpu, int cpu)
{
	if (ple_gap)
		shrink_ple_window(vcpu);
}

static bool vmx_has_emulated_msr(int index)
{
	switch (index) {
		case MSR_AMD64_VIRT_SPEC_CTRL:
			return false;
		default:
			return true;
	}
}

static struct kvm_x86_ops vmx_x86_ops = {
	.cpu_has_kvm_support = cpu_has_kvm_support,
	.disabled_by_bios = vmx_disabled_by_bios,
	.hardware_setup = hardware_setup,
	.hardware_unsetup = hardware_unsetup,
	.check_processor_compatibility = vmx_check_processor_compat,
	.hardware_enable = hardware_enable,
	.hardware_disable = hardware_disable,
	.cpu_has_accelerated_tpr = report_flexpriority,

	.vm_init = vmx_vm_init,

	.vcpu_create = vmx_create_vcpu,
	.vcpu_free = vmx_free_vcpu,
	.vcpu_reset = vmx_vcpu_reset,

	.prepare_guest_switch = vmx_save_host_state,
	.vcpu_load = vmx_vcpu_load,
	.vcpu_put = vmx_vcpu_put,

	.set_guest_debug = set_guest_debug,
	.get_msr = vmx_get_msr,
	.set_msr = vmx_set_msr,
	.get_segment_base = vmx_get_segment_base,
	.get_segment = vmx_get_segment,
	.set_segment = vmx_set_segment,
	.get_cpl = vmx_get_cpl,
	.get_cs_db_l_bits = vmx_get_cs_db_l_bits,
	.decache_cr0_guest_bits = vmx_decache_cr0_guest_bits,
	.decache_cr4_guest_bits = vmx_decache_cr4_guest_bits,
	.set_cr0 = vmx_set_cr0,
	.set_cr3 = vmx_set_cr3,
	.set_cr4 = vmx_set_cr4,
	.set_efer = vmx_set_efer,
	.get_idt = vmx_get_idt,
	.set_idt = vmx_set_idt,
	.get_gdt = vmx_get_gdt,
	.set_gdt = vmx_set_gdt,
	.cache_reg = vmx_cache_reg,
	.get_rflags = vmx_get_rflags,
	.set_rflags = vmx_set_rflags,
	.fpu_activate = vmx_fpu_activate,
	.fpu_deactivate = vmx_fpu_deactivate,

	.tlb_flush = vmx_flush_tlb,

	.run = vmx_vcpu_run,
	.handle_exit = vmx_handle_exit,
	.skip_emulated_instruction = skip_emulated_instruction,
	.set_interrupt_shadow = vmx_set_interrupt_shadow,
	.get_interrupt_shadow = vmx_get_interrupt_shadow,
	.patch_hypercall = vmx_patch_hypercall,
	.set_irq = vmx_inject_irq,
	.set_nmi = vmx_inject_nmi,
	.queue_exception = vmx_queue_exception,
	.interrupt_allowed = vmx_interrupt_allowed,
	.nmi_allowed = vmx_nmi_allowed,
	.get_nmi_mask = vmx_get_nmi_mask,
	.set_nmi_mask = vmx_set_nmi_mask,
	.enable_nmi_window = enable_nmi_window,
	.enable_irq_window = enable_irq_window,
	.update_cr8_intercept = update_cr8_intercept,

	.set_tss_addr = vmx_set_tss_addr,
	.get_tdp_level = get_ept_level,
	.get_mt_mask = vmx_get_mt_mask,

	.get_lpage_level = vmx_get_lpage_level,

	.cpuid_update = vmx_cpuid_update,
	.invpcid_supported = vmx_invpcid_supported,

	.set_tsc_khz = vmx_set_tsc_khz,
	.write_tsc_offset = vmx_write_tsc_offset,
	.adjust_tsc_offset = vmx_adjust_tsc_offset,
	.compute_tsc_offset = vmx_compute_tsc_offset,

	.sched_in = vmx_sched_in,
	.handle_external_intr = vmx_handle_external_intr,

	.has_emulated_msr = vmx_has_emulated_msr,
};

static void vmx_cleanup_l1d_flush(void)
{
	if (vmx_l1d_flush_pages) {
		free_pages((unsigned long)vmx_l1d_flush_pages, L1D_CACHE_ORDER);
		vmx_l1d_flush_pages = NULL;
	}
	/* Restore state so sysfs ignores VMX */
	l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_AUTO;
}

static void vmx_exit(void)
{
	free_page((unsigned long)vmx_msr_bitmap_legacy);
	free_page((unsigned long)vmx_msr_bitmap_longmode);
	free_page((unsigned long)vmx_io_bitmap_b);
	free_page((unsigned long)vmx_io_bitmap_a);

#ifdef CONFIG_KEXEC
	rcu_assign_pointer(crash_vmclear_loaded_vmcss, NULL);
	synchronize_rcu();
#endif
	vmx_cleanup_l1d_flush();

	kvm_exit();
}
module_exit(vmx_exit)

static int __init vmx_init(void)
{
	int r, i;

	rdmsrl_safe(MSR_EFER, &host_efer);

	for (i = 0; i < NR_VMX_MSR; ++i)
		kvm_define_shared_msr(i, vmx_msr_index[i]);

	vmx_io_bitmap_a = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_io_bitmap_a)
		return -ENOMEM;

	vmx_io_bitmap_b = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_io_bitmap_b) {
		r = -ENOMEM;
		goto out;
	}

	vmx_msr_bitmap_legacy = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_msr_bitmap_legacy) {
		r = -ENOMEM;
		goto out1;
	}

	vmx_msr_bitmap_longmode = (unsigned long *)__get_free_page(GFP_KERNEL);
	if (!vmx_msr_bitmap_longmode) {
		r = -ENOMEM;
		goto out2;
	}

	/*
	 * Allow direct access to the PC debug port (it is often used for I/O
	 * delays, but the vmexits simply slow things down).
	 */
	memset(vmx_io_bitmap_a, 0xff, PAGE_SIZE);
	clear_bit(0x80, vmx_io_bitmap_a);

	memset(vmx_io_bitmap_b, 0xff, PAGE_SIZE);

	memset(vmx_msr_bitmap_legacy, 0xff, PAGE_SIZE);
	memset(vmx_msr_bitmap_longmode, 0xff, PAGE_SIZE);

	set_bit(0, vmx_vpid_bitmap); /* 0 is reserved for host */

	r = kvm_init(&vmx_x86_ops, sizeof(struct vcpu_vmx),
		     __alignof__(struct vcpu_vmx), THIS_MODULE);
	if (r)
		goto out3;

	/*
	 * Must be called after kvm_init() so enable_ept is properly set
	 * up. Hand the parameter mitigation value in which was stored in
	 * the pre module init parser. If no parameter was given, it will
	 * contain 'auto' which will be turned into the default 'cond'
	 * mitigation mode.
	 */
	r = vmx_setup_l1d_flush(vmentry_l1d_flush_param);
	if (r) {
		vmx_exit();
		return r;
	}

#ifdef CONFIG_KEXEC
	rcu_assign_pointer(crash_vmclear_loaded_vmcss,
			   crash_vmclear_local_loaded_vmcss);
#endif

	vmx_disable_intercept_for_msr(MSR_FS_BASE, false);
	vmx_disable_intercept_for_msr(MSR_GS_BASE, false);
	vmx_disable_intercept_for_msr(MSR_KERNEL_GS_BASE, true);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_CS, false);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_ESP, false);
	vmx_disable_intercept_for_msr(MSR_IA32_SYSENTER_EIP, false);
	vmx_disable_intercept_for_msr(MSR_IA32_SPEC_CTRL, false);
	vmx_disable_intercept_for_msr(MSR_IA32_PRED_CMD, false);

	if (enable_ept) {
		bypass_guest_pf = 0;
		kvm_mmu_set_base_ptes(VMX_EPT_READABLE_MASK |
			VMX_EPT_WRITABLE_MASK);
		kvm_mmu_set_mask_ptes(0ull,
			(enable_ept_ad_bits) ? VMX_EPT_ACCESS_BIT : 0ull,
			(enable_ept_ad_bits) ? VMX_EPT_DIRTY_BIT : 0ull,
			0ull, VMX_EPT_EXECUTABLE_MASK);
		kvm_enable_tdp();
	} else
		kvm_disable_tdp();

	if (bypass_guest_pf)
		kvm_mmu_set_nonpresent_ptes(~0xffeull, 0ull);

	update_ple_window_actual_max();

	return 0;

out3:
	free_page((unsigned long)vmx_msr_bitmap_longmode);
out2:
	free_page((unsigned long)vmx_msr_bitmap_legacy);
out1:
	free_page((unsigned long)vmx_io_bitmap_b);
out:
	free_page((unsigned long)vmx_io_bitmap_a);
	return r;
}
module_init(vmx_init)
