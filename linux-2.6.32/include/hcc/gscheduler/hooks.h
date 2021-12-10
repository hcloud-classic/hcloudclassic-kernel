#ifndef __HCC_GSCHEDULER_HOOKS_H__
#define __HCC_GSCHEDULER_HOOKS_H__

#ifdef CONFIG_HCC_GSCHED
extern struct atomic_notifier_head kmh_calc_load;
extern struct atomic_notifier_head kmh_process_on;
extern struct atomic_notifier_head kmh_process_off;
#endif

#endif /* __HCC_GSCHEDULER_HOOKS_H__ */
