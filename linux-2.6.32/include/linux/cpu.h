/*
 * include/linux/cpu.h - generic cpu definition
 *
 * This is mainly for topological representation. We define the 
 * basic 'struct cpu' here, which can be embedded in per-arch 
 * definitions of processors.
 *
 * Basic handling of the devices is done in drivers/base/cpu.c
 * and system devices are handled in drivers/base/sys.c. 
 *
 * CPUs are exported via sysfs in the class/cpu/devices/
 * directory. 
 *
 * Per-cpu interfaces can be implemented using a struct device_interface. 
 * See the following for how to do this: 
 * - drivers/base/intf.c 
 * - Documentation/driver-model/interface.txt
 */
#ifndef _LINUX_CPU_H_
#define _LINUX_CPU_H_

#include <linux/sysdev.h>
#include <linux/node.h>
#include <linux/compiler.h>
#include <linux/cpumask.h>

struct cpu {
	int node_id;		/* The node which contains the CPU */
	int hotpluggable;	/* creates sysfs control file if hotpluggable */
	struct sys_device sysdev;
};

extern void boot_cpu_state_init(void);

extern int register_cpu(struct cpu *cpu, int num);
extern struct sys_device *get_cpu_sysdev(unsigned cpu);

extern int cpu_add_sysdev_attr(struct sysdev_attribute *attr);
extern void cpu_remove_sysdev_attr(struct sysdev_attribute *attr);

extern int cpu_add_sysdev_attr_group(struct attribute_group *attrs);
extern void cpu_remove_sysdev_attr_group(struct attribute_group *attrs);

extern int sched_create_sysfs_power_savings_entries(struct sysdev_class *cls);

#ifdef CONFIG_HOTPLUG_CPU
extern void unregister_cpu(struct cpu *cpu);
extern ssize_t arch_cpu_probe(const char *, size_t);
extern ssize_t arch_cpu_release(const char *, size_t);
#else
static inline int cpu_down(unsigned int cpu) { return -ENOSYS; }
#endif
struct notifier_block;

/*
 * CPU notifier priorities.
 */
enum {
	/*
	 * SCHED_ACTIVE marks a cpu which is coming up active during
	 * CPU_ONLINE and CPU_DOWN_FAILED and must be the first
	 * notifier.  CPUSET_ACTIVE adjusts cpuset according to
	 * cpu_active mask right after SCHED_ACTIVE.  During
	 * CPU_DOWN_PREPARE, SCHED_INACTIVE and CPUSET_INACTIVE are
	 * ordered in the similar way.
	 *
	 * This ordering guarantees consistent cpu_active mask and
	 * migration behavior to all cpu notifiers.
	 */
	CPU_PRI_SCHED_ACTIVE	= INT_MAX,
	CPU_PRI_CPUSET_ACTIVE	= INT_MAX - 1,
	CPU_PRI_SCHED_INACTIVE	= INT_MIN + 1,
	CPU_PRI_CPUSET_INACTIVE	= INT_MIN,

	/* migration should happen before other stuff but after perf */
	CPU_PRI_PERF		= 20,
	CPU_PRI_MIGRATION	= 10,
};

#ifdef CONFIG_SMP
/* Need to know about CPUs going up/down? */
#if defined(CONFIG_HOTPLUG_CPU) || !defined(MODULE)
#define cpu_notifier(fn, pri) {					\
	static struct notifier_block fn##_nb __cpuinitdata =	\
		{ .notifier_call = fn, .priority = pri };	\
	register_cpu_notifier(&fn##_nb);			\
}
#else /* #if defined(CONFIG_HOTPLUG_CPU) || !defined(MODULE) */
#define cpu_notifier(fn, pri)	do { (void)(fn); } while (0)
#endif /* #else #if defined(CONFIG_HOTPLUG_CPU) || !defined(MODULE) */
#ifdef CONFIG_HOTPLUG_CPU
extern int register_cpu_notifier(struct notifier_block *nb);
extern void unregister_cpu_notifier(struct notifier_block *nb);
#else

#ifndef MODULE
extern int register_cpu_notifier(struct notifier_block *nb);
#else
static inline int register_cpu_notifier(struct notifier_block *nb)
{
	return 0;
}
#endif

static inline void unregister_cpu_notifier(struct notifier_block *nb)
{
}
#endif

int cpu_up(unsigned int cpu);
void notify_cpu_starting(unsigned int cpu);
extern void cpu_maps_update_begin(void);
extern void cpu_maps_update_done(void);

#else	/* CONFIG_SMP */

#define cpu_notifier(fn, pri)	do { (void)(fn); } while (0)

static inline int register_cpu_notifier(struct notifier_block *nb)
{
	return 0;
}

static inline void unregister_cpu_notifier(struct notifier_block *nb)
{
}

static inline void cpu_maps_update_begin(void)
{
}

static inline void cpu_maps_update_done(void)
{
}

#endif /* CONFIG_SMP */
extern struct sysdev_class cpu_sysdev_class;

#ifdef CONFIG_HOTPLUG_CPU
/* Stop CPUs going up and down. */

extern void get_online_cpus(void);
extern void put_online_cpus(void);
#define hotcpu_notifier(fn, pri)	cpu_notifier(fn, pri)
#define register_hotcpu_notifier(nb)	register_cpu_notifier(nb)
#define unregister_hotcpu_notifier(nb)	unregister_cpu_notifier(nb)
int cpu_down(unsigned int cpu);

#ifdef CONFIG_ARCH_CPU_PROBE_RELEASE
extern void cpu_hotplug_driver_lock(void);
extern void cpu_hotplug_driver_unlock(void);
#else
static inline void cpu_hotplug_driver_lock(void)
{
}

static inline void cpu_hotplug_driver_unlock(void)
{
}
#endif

#else		/* CONFIG_HOTPLUG_CPU */

#define get_online_cpus()	do { } while (0)
#define put_online_cpus()	do { } while (0)
#define hotcpu_notifier(fn, pri)	do { (void)(fn); } while (0)
/* These aren't inline functions due to a GCC bug. */
#define register_hotcpu_notifier(nb)	({ (void)(nb); 0; })
#define unregister_hotcpu_notifier(nb)	({ (void)(nb); })
#endif		/* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_PM_SLEEP_SMP
extern int suspend_cpu_hotplug;

extern int disable_nonboot_cpus(void);
extern void enable_nonboot_cpus(void);
#else /* !CONFIG_PM_SLEEP_SMP */
#define suspend_cpu_hotplug	0

static inline int disable_nonboot_cpus(void) { return 0; }
static inline void enable_nonboot_cpus(void) {}
#endif /* !CONFIG_PM_SLEEP_SMP */

extern ssize_t cpu_show_meltdown(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_spectre_v1(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_spectre_v2(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_spec_store_bypass(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_l1tf(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_mds(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_itlb_multihit(struct sysdev_class *class, char *buf);
extern ssize_t cpu_show_tsx_async_abort(struct sysdev_class *class, char *buf);

enum cpuhp_smt_control {
	CPU_SMT_ENABLED,
	CPU_SMT_DISABLED,
	CPU_SMT_FORCE_DISABLED,
	CPU_SMT_NOT_SUPPORTED,
};

#if defined(CONFIG_SMP) && defined(CONFIG_HOTPLUG_SMT)
extern enum cpuhp_smt_control cpu_smt_control;
extern void cpu_smt_disable(bool force);
extern void cpu_smt_check_topology(void);
#else
# define cpu_smt_control		(CPU_SMT_ENABLED)
static inline void cpu_smt_disable(bool force) { }
static inline void cpu_smt_check_topology(void) { }
#endif

#ifdef CONFIG_HOTPLUG_SMT
bool cpu_smt_allowed(unsigned int cpu);
#else
static inline bool cpu_smt_allowed(unsigned int cpu) { return true; }
#endif

#endif /* _LINUX_CPU_H_ */
