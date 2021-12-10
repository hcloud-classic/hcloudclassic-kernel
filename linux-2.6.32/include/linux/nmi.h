/*
 *  linux/include/linux/nmi.h
 */
#ifndef LINUX_NMI_H
#define LINUX_NMI_H

#include <linux/sched.h>
#include <asm/irq.h>

/**
 * touch_nmi_watchdog - restart NMI watchdog timeout.
 * 
 * If the architecture supports the NMI watchdog, touch_nmi_watchdog()
 * may be used to reset the timeout - for code which intentionally
 * disables interrupts for a long time. This call is stateless.
 */
#if defined(ARCH_HAS_NMI_WATCHDOG) || defined(CONFIG_HARDLOCKUP_DETECTOR)
#include <asm/nmi.h>
extern void touch_nmi_watchdog(void);
extern void acpi_nmi_disable(void);
extern void acpi_nmi_enable(void);
#else
static inline void touch_nmi_watchdog(void)
{
	touch_softlockup_watchdog();
}
static inline void acpi_nmi_disable(void) { }
static inline void acpi_nmi_enable(void) { }
#endif

#if defined(CONFIG_HARDLOCKUP_DETECTOR)
extern void watchdog_enable_hardlockup_detector(bool val);
extern bool watchdog_hardlockup_detector_is_enabled(void);
#else
static inline void watchdog_enable_hardlockup_detector(bool val)
{
}
static inline bool watchdog_hardlockup_detector_is_enabled(void)
{
	return true;
}
#endif

/*
 * Create trigger_all_cpu_backtrace() out of the arch-provided
 * base function. Return whether such support was available,
 * to allow calling code to fall back to some other mechanism:
 */
#ifdef arch_trigger_all_cpu_backtrace
static inline bool trigger_all_cpu_backtrace(void)
{
	arch_trigger_all_cpu_backtrace(true);

	return true;
}
static inline bool trigger_allbutself_cpu_backtrace(void)
{
	arch_trigger_all_cpu_backtrace(false);
	return true;
}
#else
static inline bool trigger_all_cpu_backtrace(void)
{
	return false;
}
static inline bool trigger_allbutself_cpu_backtrace(void)
{
	return false;
}
#endif

#ifdef CONFIG_LOCKUP_DETECTOR
int hw_nmi_is_cpu_stuck(struct pt_regs *);
u64 hw_nmi_get_sample_period(void);
extern int watchdog_enabled;
extern int sysctl_softlockup_all_cpu_backtrace;
extern int sysctl_hardlockup_all_cpu_backtrace;
struct ctl_table;
extern int proc_dowatchdog_enabled(struct ctl_table *, int ,
			void __user *, size_t *, loff_t *);
#endif

#endif
