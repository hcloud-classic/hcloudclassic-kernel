/* CPU control.
 * (C) 2001, 2002, 2003, 2004 Rusty Russell
 *
 * This code is licenced under the GPL.
 */
#include <linux/proc_fs.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/stop_machine.h>
#include <linux/mutex.h>
#include <linux/suspend.h>
#include <linux/device.h>

#ifdef CONFIG_SMP
/* Serializes the updates to cpu_online_mask, cpu_present_mask */
static DEFINE_MUTEX(cpu_add_remove_lock);

static RAW_NOTIFIER_HEAD(cpu_chain);

/* If set, cpu_up and cpu_down will return -EBUSY and do nothing.
 * Should always be manipulated under cpu_add_remove_lock
 */
static int cpu_hotplug_disabled;

static struct {
	struct task_struct *active_writer;
	struct mutex lock; /* Synchronizes accesses to refcount, */
	/*
	 * Also blocks the new readers during
	 * an ongoing cpu hotplug operation.
	 */
	int refcount;
} cpu_hotplug = {
	.active_writer = NULL,
	.lock = __MUTEX_INITIALIZER(cpu_hotplug.lock),
	.refcount = 0,
};

#ifdef CONFIG_HOTPLUG_CPU

void get_online_cpus(void)
{
	might_sleep();
	if (cpu_hotplug.active_writer == current)
		return;
	mutex_lock(&cpu_hotplug.lock);
	cpu_hotplug.refcount++;
	mutex_unlock(&cpu_hotplug.lock);

}
EXPORT_SYMBOL_GPL(get_online_cpus);

void put_online_cpus(void)
{
	if (cpu_hotplug.active_writer == current)
		return;
	mutex_lock(&cpu_hotplug.lock);
	if (!--cpu_hotplug.refcount && unlikely(cpu_hotplug.active_writer))
		wake_up_process(cpu_hotplug.active_writer);
	mutex_unlock(&cpu_hotplug.lock);

}
EXPORT_SYMBOL_GPL(put_online_cpus);

#endif	/* CONFIG_HOTPLUG_CPU */

static DEFINE_PER_CPU(bool, booted_once);

/*
 * The following two API's must be used when attempting
 * to serialize the updates to cpu_online_mask, cpu_present_mask.
 */
void cpu_maps_update_begin(void)
{
	mutex_lock(&cpu_add_remove_lock);
}

void cpu_maps_update_done(void)
{
	mutex_unlock(&cpu_add_remove_lock);
}

/*
 * This ensures that the hotplug operation can begin only when the
 * refcount goes to zero.
 *
 * Note that during a cpu-hotplug operation, the new readers, if any,
 * will be blocked by the cpu_hotplug.lock
 *
 * Since cpu_hotplug_begin() is always called after invoking
 * cpu_maps_update_begin(), we can be sure that only one writer is active.
 *
 * Note that theoretically, there is a possibility of a livelock:
 * - Refcount goes to zero, last reader wakes up the sleeping
 *   writer.
 * - Last reader unlocks the cpu_hotplug.lock.
 * - A new reader arrives at this moment, bumps up the refcount.
 * - The writer acquires the cpu_hotplug.lock finds the refcount
 *   non zero and goes to sleep again.
 *
 * However, this is very difficult to achieve in practice since
 * get_online_cpus() not an api which is called all that often.
 *
 */
static void cpu_hotplug_begin(void)
{
	cpu_hotplug.active_writer = current;

	for (;;) {
		mutex_lock(&cpu_hotplug.lock);
		if (likely(!cpu_hotplug.refcount))
			break;
		__set_current_state(TASK_UNINTERRUPTIBLE);
		mutex_unlock(&cpu_hotplug.lock);
		schedule();
	}
}

static void cpu_hotplug_done(void)
{
	cpu_hotplug.active_writer = NULL;
	mutex_unlock(&cpu_hotplug.lock);
}
/* Need to know about CPUs going up/down? */
int __ref register_cpu_notifier(struct notifier_block *nb)
{
	int ret;
	cpu_maps_update_begin();
	ret = raw_notifier_chain_register(&cpu_chain, nb);
	cpu_maps_update_done();
	return ret;
}

static int __cpu_notify(unsigned long val, void *v, int nr_to_call,
			int *nr_calls)
{
	int ret;

	ret = __raw_notifier_call_chain(&cpu_chain, val, v, nr_to_call,
					nr_calls);

	return notifier_to_errno(ret);
}

static int cpu_notify(unsigned long val, void *v)
{
	return __cpu_notify(val, v, -1, NULL);
}

static void cpu_notify_nofail(unsigned long val, void *v)
{
	int err;

	err = cpu_notify(val, v);
	BUG_ON(err);
}

/*
 * Architectures that need SMT-specific errata handling during SMT hotplug
 * should override this.
 */
void __weak arch_smt_update(void) { };

#ifdef CONFIG_HOTPLUG_CPU

EXPORT_SYMBOL(register_cpu_notifier);

void __ref unregister_cpu_notifier(struct notifier_block *nb)
{
	cpu_maps_update_begin();
	raw_notifier_chain_unregister(&cpu_chain, nb);
	cpu_maps_update_done();
}
EXPORT_SYMBOL(unregister_cpu_notifier);

static inline void check_for_tasks(int cpu)
{
	struct task_struct *p;

	write_lock_irq(&tasklist_lock);
	for_each_process(p) {
		if (task_cpu(p) == cpu && p->state == TASK_RUNNING &&
		    (!cputime_eq(p->utime, cputime_zero) ||
		     !cputime_eq(p->stime, cputime_zero)))
			printk(KERN_WARNING "Task %s (pid = %d) is on cpu %d\
				(state = %ld, flags = %x) \n",
				 p->comm, task_pid_nr(p), cpu,
				 p->state, p->flags);
	}
	write_unlock_irq(&tasklist_lock);
}

struct take_cpu_down_param {
	struct task_struct *caller;
	unsigned long mod;
	void *hcpu;
};

/* Take this CPU down. */
static int __ref take_cpu_down(void *_param)
{
	struct take_cpu_down_param *param = _param;
	unsigned int cpu = (unsigned long)param->hcpu;
	int err;

	/* Ensure this CPU doesn't handle any more interrupts. */
	err = __cpu_disable();
	if (err < 0)
		return err;

	cpu_notify(CPU_DYING | param->mod, param->hcpu);

	if (task_cpu(param->caller) == cpu)
		move_task_off_dead_cpu(cpu, param->caller);
	/* Force idle task to run as soon as we yield: it should
	   immediately notice cpu is offline and die quickly. */
	sched_idle_next();
	return 0;
}

/* Requires cpu_add_remove_lock to be held */
static int __ref _cpu_down(unsigned int cpu, int tasks_frozen)
{
	int err, nr_calls = 0;
	void *hcpu = (void *)(long)cpu;
	unsigned long mod = tasks_frozen ? CPU_TASKS_FROZEN : 0;
	struct take_cpu_down_param tcd_param = {
		.caller = current,
		.mod = mod,
		.hcpu = hcpu,
	};

	if (num_online_cpus() == 1)
		return -EBUSY;

	if (!cpu_online(cpu))
		return -EINVAL;

	cpu_hotplug_begin();
	err = __cpu_notify(CPU_DOWN_PREPARE | mod, hcpu, -1, &nr_calls);
	if (err) {
		nr_calls--;
		__cpu_notify(CPU_DOWN_FAILED | mod, hcpu, nr_calls, NULL);
		printk("%s: attempt to take down CPU %u failed\n",
				__func__, cpu);
		goto out_release;
	}

	/*
	 * The sibling_mask will be cleared in take_cpu_down when the
	 * operation succeeds. So we can't test the sibling mask after
	 * that. We needs to call sched_cpu_activate() if it fails.
	 */
	sched_cpu_deactivate(cpu);

	err = __stop_machine(take_cpu_down, &tcd_param, cpumask_of(cpu));
	if (err) {
		/* CPU didn't die: tell everyone.  Can't complain. */
		cpu_notify_nofail(CPU_DOWN_FAILED | mod, hcpu);
		sched_cpu_activate(cpu);

		goto out_release;
	}
	BUG_ON(cpu_online(cpu));

	/* Wait for it to sleep (leaving idle task). */
	while (!idle_cpu(cpu))
		yield();

	/* This actually kills the CPU. */
	__cpu_die(cpu);

	/* CPU is completely dead: tell everyone.  Too late to complain. */
	cpu_notify_nofail(CPU_DEAD | mod, hcpu);

	check_for_tasks(cpu);

out_release:
	cpu_hotplug_done();
	if (!err)
		cpu_notify_nofail(CPU_POST_DEAD | mod, hcpu);
	arch_smt_update();
	return err;
}

static int cpu_down_maps_locked(unsigned int cpu)
{
	if (cpu_hotplug_disabled)
		return -EBUSY;
	return _cpu_down(cpu, 0);
}

int __ref cpu_down(unsigned int cpu)
{
	int err;

	cpu_maps_update_begin();
	err = cpu_down_maps_locked(cpu);
	cpu_maps_update_done();
	return err;
}
EXPORT_SYMBOL(cpu_down);
#endif /*CONFIG_HOTPLUG_CPU*/

#ifdef CONFIG_HOTPLUG_SMT
enum cpuhp_smt_control cpu_smt_control __read_mostly = CPU_SMT_ENABLED;
EXPORT_SYMBOL_GPL(cpu_smt_control);

void __init cpu_smt_disable(bool force)
{
	if (cpu_smt_control == CPU_SMT_FORCE_DISABLED ||
		cpu_smt_control == CPU_SMT_NOT_SUPPORTED)
		return;

	if (force) {
		pr_info("SMT: Force disabled\n");
		cpu_smt_control = CPU_SMT_FORCE_DISABLED;
	} else {
		cpu_smt_control = CPU_SMT_DISABLED;
	}
}

/*
 * The decision whether SMT is supported can only be done after the full
 * CPU identification. Called from architecture code.
 */
void __init cpu_smt_check_topology(void)
{
	if (!topology_smt_supported())
		cpu_smt_control = CPU_SMT_NOT_SUPPORTED;
}

static int __init smt_cmdline_disable(char *str)
{
	cpu_smt_disable(str && !strcmp(str, "force"));
	return 0;
}
early_param("nosmt", smt_cmdline_disable);

bool cpu_smt_allowed(unsigned int cpu)
{
	if (cpu_smt_control == CPU_SMT_ENABLED)
		return true;

	if (topology_is_primary_thread(cpu))
		return true;

	/*
	 * On x86 it's required to boot all logical CPUs at least once so
	 * that the init code can get a chance to set CR4.MCE on each
	 * CPU. Otherwise, a broadacasted MCE observing CR4.MCE=0b on any
	 * core will shutdown the machine.
	 */
	return !per_cpu(booted_once, cpu);
}
#endif

/* Requires cpu_add_remove_lock to be held */
static int _cpu_up(unsigned int cpu, int tasks_frozen)
{
	int ret, nr_calls = 0;
	void *hcpu = (void *)(long)cpu;
	unsigned long mod = tasks_frozen ? CPU_TASKS_FROZEN : 0;

	cpu_hotplug_begin();

	if (cpu_online(cpu) || !cpu_present(cpu)) {
		ret = -EINVAL;
		goto out;
	}

	ret = __cpu_notify(CPU_UP_PREPARE | mod, hcpu, -1, &nr_calls);
	if (ret) {
		nr_calls--;
		printk("%s: attempt to bring up CPU %u failed\n",
				__func__, cpu);
		goto out_notify;
	}

	/* Arch-specific enabling code. */
	ret = __cpu_up(cpu);
	if (ret != 0)
		goto out_notify;
	BUG_ON(!cpu_online(cpu));

	/* Now call notifier in preparation. */
	cpu_notify(CPU_ONLINE | mod, hcpu);

	sched_cpu_activate(cpu);

out_notify:
	if (ret != 0)
		__cpu_notify(CPU_UP_CANCELED | mod, hcpu, nr_calls, NULL);
out:
	cpu_hotplug_done();
	arch_smt_update();

	return ret;
}

int __cpuinit cpu_up(unsigned int cpu)
{
	int err = 0;

#ifdef	CONFIG_MEMORY_HOTPLUG
	int nid;
	pg_data_t	*pgdat;
#endif

	if (!cpu_possible(cpu)) {
		printk(KERN_ERR "can't online cpu %d because it is not "
			"configured as may-hotadd at boot time\n", cpu);
#if defined(CONFIG_IA64) || defined(CONFIG_X86_64)
		printk(KERN_ERR "please check additional_cpus= boot "
				"parameter\n");
#endif
		return -EINVAL;
	}

#ifdef	CONFIG_MEMORY_HOTPLUG
	nid = cpu_to_node(cpu);
	if (!node_online(nid)) {
		err = mem_online_node(nid);
		if (err)
			return err;
	}

	pgdat = NODE_DATA(nid);
	if (!pgdat) {
		printk(KERN_ERR
			"Can't online cpu %d due to NULL pgdat\n", cpu);
		return -ENOMEM;
	}

	if (pgdat->node_zonelists->_zonerefs->zone == NULL) {
		mutex_lock(&zonelists_mutex);
		build_all_zonelists(NULL);
		mutex_unlock(&zonelists_mutex);
	}
#endif

	cpu_maps_update_begin();

	if (cpu_hotplug_disabled) {
		err = -EBUSY;
		goto out;
	}
	if (!cpu_smt_allowed(cpu)) {
		err = -EPERM;
		goto out;
	}

	err = _cpu_up(cpu, 0);

out:
	cpu_maps_update_done();
	return err;
}

#ifdef CONFIG_PM_SLEEP_SMP
static cpumask_var_t frozen_cpus;

int disable_nonboot_cpus(void)
{
	int cpu, first_cpu, error = 0;

	cpu_maps_update_begin();
	first_cpu = cpumask_first(cpu_online_mask);
	/*
	 * We take down all of the non-boot CPUs in one shot to avoid races
	 * with the userspace trying to use the CPU hotplug at the same time
	 */
	cpumask_clear(frozen_cpus);

	printk("Disabling non-boot CPUs ...\n");
	for_each_online_cpu(cpu) {
		if (cpu == first_cpu)
			continue;
		error = _cpu_down(cpu, 1);
		if (!error)
			cpumask_set_cpu(cpu, frozen_cpus);
		else {
			printk(KERN_ERR "Error taking CPU%d down: %d\n",
				cpu, error);
			break;
		}
	}

	if (!error) {
		BUG_ON(num_online_cpus() > 1);
		/* Make sure the CPUs won't be enabled by someone else */
		cpu_hotplug_disabled = 1;
	} else {
		printk(KERN_ERR "Non-boot CPUs are not disabled\n");
	}
	cpu_maps_update_done();
	return error;
}

void __weak arch_enable_nonboot_cpus_begin(void)
{
}

void __weak arch_enable_nonboot_cpus_end(void)
{
}

void __ref enable_nonboot_cpus(void)
{
	int cpu, error;

	/* Allow everyone to use the CPU hotplug again */
	cpu_maps_update_begin();
	cpu_hotplug_disabled = 0;
	if (cpumask_empty(frozen_cpus))
		goto out;

	printk("Enabling non-boot CPUs ...\n");

	arch_enable_nonboot_cpus_begin();

	for_each_cpu(cpu, frozen_cpus) {
		error = _cpu_up(cpu, 1);
		if (!error) {
			printk("CPU%d is up\n", cpu);
			continue;
		}
		printk(KERN_WARNING "Error taking CPU%d up: %d\n", cpu, error);
	}

	arch_enable_nonboot_cpus_end();

	cpumask_clear(frozen_cpus);
out:
	cpu_maps_update_done();
}

static int alloc_frozen_cpus(void)
{
	if (!alloc_cpumask_var(&frozen_cpus, GFP_KERNEL|__GFP_ZERO))
		return -ENOMEM;
	return 0;
}
core_initcall(alloc_frozen_cpus);

/*
 * Prevent regular CPU hotplug from racing with the freezer, by disabling CPU
 * hotplug when tasks are about to be frozen. Also, don't allow the freezer
 * to continue until any currently running CPU hotplug operation gets
 * completed.
 * To modify the 'cpu_hotplug_disabled' flag, we need to acquire the
 * 'cpu_add_remove_lock'. And this same lock is also taken by the regular
 * CPU hotplug path and released only after it is complete. Thus, we
 * (and hence the freezer) will block here until any currently running CPU
 * hotplug operation gets completed.
 */
void cpu_hotplug_disable_before_freeze(void)
{
	cpu_maps_update_begin();
	cpu_hotplug_disabled = 1;
	cpu_maps_update_done();
}


/*
 * When tasks have been thawed, re-enable regular CPU hotplug (which had been
 * disabled while beginning to freeze tasks).
 */
void cpu_hotplug_enable_after_thaw(void)
{
	cpu_maps_update_begin();
	cpu_hotplug_disabled = 0;
	cpu_maps_update_done();
}

/*
 * When callbacks for CPU hotplug notifications are being executed, we must
 * ensure that the state of the system with respect to the tasks being frozen
 * or not, as reported by the notification, remains unchanged *throughout the
 * duration* of the execution of the callbacks.
 * Hence we need to prevent the freezer from racing with regular CPU hotplug.
 *
 * This synchronization is implemented by mutually excluding regular CPU
 * hotplug and Suspend/Hibernate call paths by hooking onto the Suspend/
 * Hibernate notifications.
 */
static int
cpu_hotplug_pm_callback(struct notifier_block *nb,
			unsigned long action, void *ptr)
{
	switch (action) {

	case PM_SUSPEND_PREPARE:
	case PM_HIBERNATION_PREPARE:
		cpu_hotplug_disable_before_freeze();
		break;

	case PM_POST_SUSPEND:
	case PM_POST_HIBERNATION:
		cpu_hotplug_enable_after_thaw();
		break;

	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_OK;
}


int cpu_hotplug_pm_sync_init(void)
{
	pm_notifier(cpu_hotplug_pm_callback, 0);
	return 0;
}
core_initcall(cpu_hotplug_pm_sync_init);

#endif /* CONFIG_PM_SLEEP_SMP */

/**
 * notify_cpu_starting(cpu) - call the CPU_STARTING notifiers
 * @cpu: cpu that just started
 *
 * This function calls the cpu_chain notifiers with CPU_STARTING.
 * It must be called by the arch code on the new cpu, before the new cpu
 * enables interrupts and before the "boot" cpu returns from __cpu_up().
 */
void __cpuinit notify_cpu_starting(unsigned int cpu)
{
	unsigned long val = CPU_STARTING;

	per_cpu(booted_once, cpu) = true;
#ifdef CONFIG_PM_SLEEP_SMP
	if (frozen_cpus != NULL && cpumask_test_cpu(cpu, frozen_cpus))
		val = CPU_STARTING_FROZEN;
#endif /* CONFIG_PM_SLEEP_SMP */
	cpu_notify(val, (void *)(long)cpu);
}

#endif /* CONFIG_SMP */

#if defined(CONFIG_SYSFS) && defined(CONFIG_HOTPLUG_CPU)

#ifdef CONFIG_HOTPLUG_SMT

static const char *smt_states[] = {
	[CPU_SMT_ENABLED]		= "on",
	[CPU_SMT_DISABLED]		= "off",
	[CPU_SMT_FORCE_DISABLED]	= "forceoff",
	[CPU_SMT_NOT_SUPPORTED]		= "notsupported",
};

static ssize_t
show_smt_control(struct sysdev_class *class, char *buf)
{
	return snprintf(buf, PAGE_SIZE - 2, "%s\n", smt_states[cpu_smt_control]);
}

static int cpuhp_smt_disable(enum cpuhp_smt_control ctrlval)
{
	int cpu, ret = 0;

	cpu_maps_update_begin();
	for_each_online_cpu(cpu) {
		if (topology_is_primary_thread(cpu))
			continue;
		ret = cpu_down_maps_locked(cpu);
		if (ret)
			break;
	}
	if (!ret)
		cpu_smt_control = ctrlval;
	cpu_maps_update_done();
	return ret;
}

static int cpuhp_smt_enable(void)
{
	int cpu, ret = 0;

	cpu_maps_update_begin();
	cpu_smt_control = CPU_SMT_ENABLED;
	for_each_present_cpu(cpu) {
		/* Skip online CPUs and CPUs on offline nodes */
		if (cpu_online(cpu) || !node_online(cpu_to_node(cpu)))
			continue;
		ret = _cpu_up(cpu, 0);
		if (ret)
			break;
		/* See comment in cpuhp_smt_disable() */
	}
	cpu_maps_update_done();
	return ret;
}

static ssize_t
store_smt_control(struct sysdev_class *class, const char *buf, size_t count)
{
	int ctrlval, ret = 0;

	if (sysfs_streq(buf, "on"))
		ctrlval = CPU_SMT_ENABLED;
	else if (sysfs_streq(buf, "off"))
		ctrlval = CPU_SMT_DISABLED;
	else if (sysfs_streq(buf, "forceoff"))
		ctrlval = CPU_SMT_FORCE_DISABLED;
	else
		return -EINVAL;

	if (cpu_smt_control == CPU_SMT_FORCE_DISABLED)
		return -EPERM;

	if (cpu_smt_control == CPU_SMT_NOT_SUPPORTED)
		return -ENODEV;

	cpu_hotplug_driver_lock();
	if (ctrlval != cpu_smt_control) {
		switch (ctrlval) {
		case CPU_SMT_ENABLED:
			ret = cpuhp_smt_enable();
			break;
		case CPU_SMT_DISABLED:
		case CPU_SMT_FORCE_DISABLED:
			ret = cpuhp_smt_disable(ctrlval);
			break;
		}
	}
	cpu_hotplug_driver_unlock();

	return ret ? ret : count;
}
static SYSDEV_CLASS_ATTR(control, 0644, show_smt_control, store_smt_control);

static ssize_t
show_smt_active(struct sysdev_class *class, char *buf)
{
	bool active = smp_num_siblings > 1;

	return snprintf(buf, PAGE_SIZE - 2, "%d\n", active);
}
static SYSDEV_CLASS_ATTR(active, 0444, show_smt_active, NULL);

static struct attribute *cpuhp_smt_attrs[] = {
	&attr_control.attr,
	&attr_active.attr,
	NULL
};

static const struct attribute_group cpuhp_smt_attr_group = {
	.attrs = cpuhp_smt_attrs,
	.name = "smt",
};

static int __init cpu_smt_state_init(void)
{
	/*
	 * If SMT was disabled by BIOS, detect it here, after the CPUs have
	 * been brought online.  This ensures the smt/l1tf sysfs entries are
	 * consistent with reality.  Note this may overwrite cpu_smt_control's
	 * previous setting.
	 */
	if (topology_max_smt_threads() == 1)
		cpu_smt_control = CPU_SMT_NOT_SUPPORTED;

	return sysfs_create_group(&cpu_sysdev_class.kset.kobj,
				  &cpuhp_smt_attr_group);
}

#else
static inline int cpu_smt_state_init(void) { return 0; }
#endif

static int __init cpuhp_sysfs_init(void)
{
	return cpu_smt_state_init();
}
device_initcall(cpuhp_sysfs_init);
#endif

/*
 * cpu_bit_bitmap[] is a special, "compressed" data structure that
 * represents all NR_CPUS bits binary values of 1<<nr.
 *
 * It is used by cpumask_of() to get a constant address to a CPU
 * mask value that has a single bit set only.
 */

/* cpu_bit_bitmap[0] is empty - so we can back into it */
#define MASK_DECLARE_1(x)	[x+1][0] = 1UL << (x)
#define MASK_DECLARE_2(x)	MASK_DECLARE_1(x), MASK_DECLARE_1(x+1)
#define MASK_DECLARE_4(x)	MASK_DECLARE_2(x), MASK_DECLARE_2(x+2)
#define MASK_DECLARE_8(x)	MASK_DECLARE_4(x), MASK_DECLARE_4(x+4)

const unsigned long cpu_bit_bitmap[BITS_PER_LONG+1][BITS_TO_LONGS(NR_CPUS)] = {

	MASK_DECLARE_8(0),	MASK_DECLARE_8(8),
	MASK_DECLARE_8(16),	MASK_DECLARE_8(24),
#if BITS_PER_LONG > 32
	MASK_DECLARE_8(32),	MASK_DECLARE_8(40),
	MASK_DECLARE_8(48),	MASK_DECLARE_8(56),
#endif
};
EXPORT_SYMBOL_GPL(cpu_bit_bitmap);

const DECLARE_BITMAP(cpu_all_bits, NR_CPUS) = CPU_BITS_ALL;
EXPORT_SYMBOL(cpu_all_bits);

#ifdef CONFIG_INIT_ALL_POSSIBLE
static DECLARE_BITMAP(cpu_possible_bits, CONFIG_NR_CPUS) __read_mostly
	= CPU_BITS_ALL;
#else
static DECLARE_BITMAP(cpu_possible_bits, CONFIG_NR_CPUS) __read_mostly;
#endif
const struct cpumask *const cpu_possible_mask = to_cpumask(cpu_possible_bits);
EXPORT_SYMBOL(cpu_possible_mask);

static DECLARE_BITMAP(cpu_online_bits, CONFIG_NR_CPUS) __read_mostly;
const struct cpumask *const cpu_online_mask = to_cpumask(cpu_online_bits);
EXPORT_SYMBOL(cpu_online_mask);

static DECLARE_BITMAP(cpu_present_bits, CONFIG_NR_CPUS) __read_mostly;
const struct cpumask *const cpu_present_mask = to_cpumask(cpu_present_bits);
EXPORT_SYMBOL(cpu_present_mask);

static DECLARE_BITMAP(cpu_active_bits, CONFIG_NR_CPUS) __read_mostly;
const struct cpumask *const cpu_active_mask = to_cpumask(cpu_active_bits);
EXPORT_SYMBOL(cpu_active_mask);

void set_cpu_possible(unsigned int cpu, bool possible)
{
	if (possible)
		cpumask_set_cpu(cpu, to_cpumask(cpu_possible_bits));
	else
		cpumask_clear_cpu(cpu, to_cpumask(cpu_possible_bits));
}

void set_cpu_present(unsigned int cpu, bool present)
{
	if (present)
		cpumask_set_cpu(cpu, to_cpumask(cpu_present_bits));
	else
		cpumask_clear_cpu(cpu, to_cpumask(cpu_present_bits));
}

void set_cpu_online(unsigned int cpu, bool online)
{
	if (online)
		cpumask_set_cpu(cpu, to_cpumask(cpu_online_bits));
	else
		cpumask_clear_cpu(cpu, to_cpumask(cpu_online_bits));
}

void set_cpu_active(unsigned int cpu, bool active)
{
	if (active)
		cpumask_set_cpu(cpu, to_cpumask(cpu_active_bits));
	else
		cpumask_clear_cpu(cpu, to_cpumask(cpu_active_bits));
}

void init_cpu_present(const struct cpumask *src)
{
	cpumask_copy(to_cpumask(cpu_present_bits), src);
}

void init_cpu_possible(const struct cpumask *src)
{
	cpumask_copy(to_cpumask(cpu_possible_bits), src);
}

void init_cpu_online(const struct cpumask *src)
{
	cpumask_copy(to_cpumask(cpu_online_bits), src);
}

void __init boot_cpu_state_init(void)
{
	percpu_write(booted_once, true);
}
