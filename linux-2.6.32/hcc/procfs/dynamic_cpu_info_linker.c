/** Dynamic CPU information management.
 *  @file dynamic_cpu_info_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/swap.h>
#include <linux/kernel_stat.h>
#include <linux/hardirq.h>

#include <hcc/cpu_id.h>
#include <hcc/workqueue.h>
#include <gdm/gdm.h>

#include <asm/cputime.h>

#include "dynamic_cpu_info_linker.h"
#include "static_cpu_info_linker.h"

#include <hcc/debug.h>

extern cputime64_t get_idle_time(int cpu);

struct gdm_set *dynamic_cpu_info_gdm_set;

/*****************************************************************************/
/*                                                                           */
/*                   DYNAMIC CPU INFO GDM IO FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

/****************************************************************************/

/* Init the dynamic cpu info IO linker */

static struct iolinker_struct dynamic_cpu_info_io_linker = {
	.default_owner = cpu_info_default_owner,
	.linker_name = "dyn_cpu_nfo",
	.linker_id = DYNAMIC_CPU_INFO_LINKER,
};

static void update_dynamic_cpu_info_worker(struct work_struct *data);
static DECLARE_DELAYED_WORK(update_dynamic_cpu_info_work,
			    update_dynamic_cpu_info_worker);

/** Update dynamic CPU informations for all local CPU.
 *  @author Innogrid HCC
 */
static void update_dynamic_cpu_info_worker(struct work_struct *data)
{
	hcc_dynamic_cpu_info_t *dynamic_cpu_info;
	int i, j, cpu_id;

	for_each_online_cpu(i) {
		cpu_id = hcc_cpu_id(i);
		dynamic_cpu_info =
			_gdm_grab_object(dynamic_cpu_info_gdm_set, cpu_id);

		/* Compute data for stat proc file */

		dynamic_cpu_info->stat = kstat_cpu(i);
		dynamic_cpu_info->stat.cpustat.idle =
			cputime64_add(dynamic_cpu_info->stat.cpustat.idle,
				      get_idle_time(i));
		dynamic_cpu_info->sum_irq = 0;
		dynamic_cpu_info->sum_irq += kstat_cpu_irqs_sum(i);
		dynamic_cpu_info->sum_irq += arch_irq_stat_cpu(i);

		dynamic_cpu_info->sum_softirq = 0;
		for (j = 0; j < NR_SOFTIRQS; j++) {
			unsigned int softirq_stat = kstat_softirqs_cpu(j, i);

			dynamic_cpu_info->per_softirq_sums[j] += softirq_stat;
			dynamic_cpu_info->sum_softirq += softirq_stat;
		}

		_gdm_put_object(dynamic_cpu_info_gdm_set, cpu_id);
	}

	queue_delayed_work(hcc_wq, &update_dynamic_cpu_info_work, HZ);
}

int dynamic_cpu_info_init(void)
{
	register_io_linker(DYNAMIC_CPU_INFO_LINKER,
			   &dynamic_cpu_info_io_linker);

	/* Create the CPU info container */

	dynamic_cpu_info_gdm_set =
		create_new_gdm_set(gdm_def_ns,
				    DYNAMIC_CPU_INFO_GDM_ID,
				    DYNAMIC_CPU_INFO_LINKER,
				    GDM_CUSTOM_DEF_OWNER,
				    sizeof(hcc_dynamic_cpu_info_t),
				    0);
	if (IS_ERR(dynamic_cpu_info_gdm_set))
		OOM;

	queue_delayed_work(hcc_wq, &update_dynamic_cpu_info_work, 0);
	return 0;
}
