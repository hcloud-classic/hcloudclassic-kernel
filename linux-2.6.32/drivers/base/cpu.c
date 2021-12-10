/*
 * drivers/base/cpu.c - basic CPU class support
 */

#include <linux/sysdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/cpu.h>
#include <linux/topology.h>
#include <linux/device.h>
#include <linux/node.h>
#include <linux/nospec.h>

#include "base.h"

struct sysdev_class cpu_sysdev_class = {
	.name = "cpu",
};
EXPORT_SYMBOL(cpu_sysdev_class);

static DEFINE_PER_CPU(struct sys_device *, cpu_sys_devices);

#ifdef CONFIG_HOTPLUG_CPU
static ssize_t show_online(struct sys_device *dev, struct sysdev_attribute *attr,
			   char *buf)
{
	struct cpu *cpu = container_of(dev, struct cpu, sysdev);

	return sprintf(buf, "%u\n", !!cpu_online(cpu->sysdev.id));
}

static ssize_t __ref store_online(struct sys_device *dev, struct sysdev_attribute *attr,
				 const char *buf, size_t count)
{
	struct cpu *cpu = container_of(dev, struct cpu, sysdev);
	ssize_t ret;

	cpu_hotplug_driver_lock();
	switch (buf[0]) {
	case '0':
		ret = cpu_down(cpu->sysdev.id);
		if (!ret)
			kobject_uevent(&dev->kobj, KOBJ_OFFLINE);
		break;
	case '1':
		ret = cpu_up(cpu->sysdev.id);
		if (!ret)
			kobject_uevent(&dev->kobj, KOBJ_ONLINE);
		break;
	default:
		ret = -EINVAL;
	}
	cpu_hotplug_driver_unlock();

	if (ret >= 0)
		ret = count;
	return ret;
}
static SYSDEV_ATTR(online, 0644, show_online, store_online);

static void __cpuinit register_cpu_control(struct cpu *cpu)
{
	sysdev_create_file(&cpu->sysdev, &attr_online);
}
void unregister_cpu(struct cpu *cpu)
{
	int logical_cpu = cpu->sysdev.id;

	unregister_cpu_under_node(logical_cpu, cpu_to_node(logical_cpu));

	sysdev_remove_file(&cpu->sysdev, &attr_online);

	sysdev_unregister(&cpu->sysdev);
	per_cpu(cpu_sys_devices, logical_cpu) = NULL;
	return;
}

#ifdef CONFIG_ARCH_CPU_PROBE_RELEASE
static ssize_t cpu_probe_store(struct class *class, const char *buf,
			       size_t count)
{
	return arch_cpu_probe(buf, count);
}

static ssize_t cpu_release_store(struct class *class, const char *buf,
				 size_t count)
{
	return arch_cpu_release(buf, count);
}

static CLASS_ATTR(probe, S_IWUSR, NULL, cpu_probe_store);
static CLASS_ATTR(release, S_IWUSR, NULL, cpu_release_store);

int __init cpu_probe_release_init(void)
{
	int rc;

	rc = sysfs_create_file(&cpu_sysdev_class.kset.kobj,
			       &class_attr_probe.attr);
	if (!rc)
		rc = sysfs_create_file(&cpu_sysdev_class.kset.kobj,
				       &class_attr_release.attr);

	return rc;
}
device_initcall(cpu_probe_release_init);
#endif /* CONFIG_ARCH_CPU_PROBE_RELEASE */

#else /* ... !CONFIG_HOTPLUG_CPU */
static inline void register_cpu_control(struct cpu *cpu)
{
}
#endif /* CONFIG_HOTPLUG_CPU */

#ifdef CONFIG_KEXEC
#include <linux/kexec.h>

static ssize_t show_crash_notes(struct sys_device *dev, struct sysdev_attribute *attr,
				char *buf)
{
	struct cpu *cpu = container_of(dev, struct cpu, sysdev);
	ssize_t rc;
	unsigned long long addr;
	int cpunum;

	cpunum = cpu->sysdev.id;

	/*
	 * Might be reading other cpu's data based on which cpu read thread
	 * has been scheduled. But cpu data (memory) is allocated once during
	 * boot up and this data does not change there after. Hence this
	 * operation should be safe. No locking required.
	 */
	addr = per_cpu_ptr_to_phys(per_cpu_ptr(crash_notes, cpunum));
	rc = sprintf(buf, "%Lx\n", addr);
	return rc;
}
static SYSDEV_ATTR(crash_notes, 0400, show_crash_notes, NULL);
#endif

/*
 * Print cpu online, possible, present, and system maps
 */
static ssize_t print_cpus_map(char *buf, const struct cpumask *map)
{
	int n = cpulist_scnprintf(buf, PAGE_SIZE-2, map);

	buf[n++] = '\n';
	buf[n] = '\0';
	return n;
}

#define	print_cpus_func(type) \
static ssize_t print_cpus_##type(struct sysdev_class *class, char *buf)	\
{									\
	return print_cpus_map(buf, cpu_##type##_mask);			\
}									\
static struct sysdev_class_attribute attr_##type##_map = 		\
	_SYSDEV_CLASS_ATTR(type, 0444, print_cpus_##type, NULL)

print_cpus_func(online);
print_cpus_func(possible);
print_cpus_func(present);

/*
 * Print values for NR_CPUS and offlined cpus
 */
static ssize_t print_cpus_kernel_max(struct sysdev_class *class, char *buf)
{
	int n = snprintf(buf, PAGE_SIZE-2, "%d\n", NR_CPUS - 1);
	return n;
}
static SYSDEV_CLASS_ATTR(kernel_max, 0444, print_cpus_kernel_max, NULL);

/* arch-optional setting to enable display of offline cpus >= nr_cpu_ids */
unsigned int total_cpus;

static ssize_t print_cpus_offline(struct sysdev_class *class, char *buf)
{
	int n = 0, len = PAGE_SIZE-2;
	cpumask_var_t offline;

	/* display offline cpus < nr_cpu_ids */
	if (!alloc_cpumask_var(&offline, GFP_KERNEL))
		return -ENOMEM;
	cpumask_complement(offline, cpu_online_mask);
	n = cpulist_scnprintf(buf, len, offline);
	free_cpumask_var(offline);

	/* display offline cpus >= nr_cpu_ids */
	if (total_cpus && nr_cpu_ids < total_cpus) {
		if (n && n < len)
			buf[n++] = ',';

		if (nr_cpu_ids == total_cpus-1)
			n += snprintf(&buf[n], len - n, "%d", nr_cpu_ids);
		else
			n += snprintf(&buf[n], len - n, "%d-%d",
						      nr_cpu_ids, total_cpus-1);
	}

	n += snprintf(&buf[n], len - n, "\n");
	return n;
}
static SYSDEV_CLASS_ATTR(offline, 0444, print_cpus_offline, NULL);

static struct sysdev_class_attribute *cpu_state_attr[] = {
	&attr_online_map,
	&attr_possible_map,
	&attr_present_map,
	&attr_kernel_max,
	&attr_offline,
};

static int cpu_states_init(void)
{
	int i;
	int err = 0;

	for (i = 0;  i < ARRAY_SIZE(cpu_state_attr); i++) {
		int ret;
		ret = sysdev_class_create_file(&cpu_sysdev_class,
						cpu_state_attr[i]);
		if (!err)
			err = ret;
	}
	return err;
}

/*
 * register_cpu - Setup a sysfs device for a CPU.
 * @cpu - cpu->hotpluggable field set to 1 will generate a control file in
 *	  sysfs for this CPU.
 * @num - CPU number to use when creating the device.
 *
 * Initialize and register the CPU device.
 */
int __cpuinit register_cpu(struct cpu *cpu, int num)
{
	int error;
	cpu->node_id = cpu_to_node(num);
	cpu->sysdev.id = num;
	cpu->sysdev.cls = &cpu_sysdev_class;

	sysdev_initialize(&cpu->sysdev);
	cpu->sysdev.kobj.uevent_suppress = 1;
	error = sysdev_add(&cpu->sysdev);

	if (!error && cpu->hotpluggable)
		register_cpu_control(cpu);
	if (!error)
		per_cpu(cpu_sys_devices, num) = &cpu->sysdev;
	if (!error)
		register_cpu_under_node(num, cpu_to_node(num));

#ifdef CONFIG_KEXEC
	if (!error)
		error = sysdev_create_file(&cpu->sysdev, &attr_crash_notes);
#endif

	cpu->sysdev.kobj.uevent_suppress = 0;
	if (!error)
		kobject_uevent(&cpu->sysdev.kobj, KOBJ_ADD);

	return error;
}

struct sys_device *get_cpu_sysdev(unsigned cpu)
{
	if (cpu < nr_cpu_ids && cpu_possible(cpu)) {
		cpu = array_index_nospec(cpu, nr_cpu_ids);
		return per_cpu(cpu_sys_devices, cpu);
	} else
		return NULL;
}
EXPORT_SYMBOL_GPL(get_cpu_sysdev);

#ifdef CONFIG_GENERIC_CPU_VULNERABILITIES

ssize_t __weak cpu_show_meltdown(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_spectre_v1(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_spectre_v2(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_spec_store_bypass(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_l1tf(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_mds(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_itlb_multihit(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

ssize_t __weak cpu_show_tsx_async_abort(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}
ssize_t __weak cpu_show_srbds(struct sysdev_class *class, char *buf)
{
	return sprintf(buf, "Not affected\n");
}

static SYSDEV_CLASS_ATTR(meltdown, 0400, cpu_show_meltdown, NULL);
static SYSDEV_CLASS_ATTR(spectre_v1, 0400, cpu_show_spectre_v1, NULL);
static SYSDEV_CLASS_ATTR(spectre_v2, 0400, cpu_show_spectre_v2, NULL);
static SYSDEV_CLASS_ATTR(spec_store_bypass, 0400, cpu_show_spec_store_bypass, NULL);
static SYSDEV_CLASS_ATTR(l1tf, 0400, cpu_show_l1tf, NULL);
static SYSDEV_CLASS_ATTR(mds, 0400, cpu_show_mds, NULL);
static SYSDEV_CLASS_ATTR(itlb_multihit, 0400, cpu_show_itlb_multihit, NULL);
static SYSDEV_CLASS_ATTR(tsx_async_abort, 0400, cpu_show_tsx_async_abort, NULL);
static SYSDEV_CLASS_ATTR(srbds, 0400, cpu_show_srbds, NULL);

static struct attribute *cpu_root_vulnerabilities_attrs[] = {
	&attr_meltdown.attr,
	&attr_spectre_v1.attr,
	&attr_spectre_v2.attr,
	&attr_spec_store_bypass.attr,
	&attr_l1tf.attr,
	&attr_mds.attr,
	&attr_itlb_multihit.attr,
	&attr_tsx_async_abort.attr,
	&attr_srbds.attr,
	NULL
};

static const struct attribute_group cpu_root_vulnerabilities_group = {
	.name  = "vulnerabilities",
	.attrs = cpu_root_vulnerabilities_attrs,
};

static void __init cpu_register_vulnerabilities(void)
{
	if (sysfs_create_group(&cpu_sysdev_class.kset.kobj,
			       &cpu_root_vulnerabilities_group))
		pr_err("Unable to register CPU vulnerabilities\n");
}

#else
static inline void cpu_register_vulnerabilities(void) { }
#endif

int __init cpu_dev_init(void)
{
	int err;

	err = sysdev_class_register(&cpu_sysdev_class);
	if (!err)
		err = cpu_states_init();

#if defined(CONFIG_SCHED_MC) || defined(CONFIG_SCHED_SMT)
	if (!err)
		err = sched_create_sysfs_power_savings_entries(&cpu_sysdev_class);
#endif

	if (!err)
		cpu_register_vulnerabilities();

	return err;
}
