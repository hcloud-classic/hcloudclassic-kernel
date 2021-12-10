/** Static CPU information management.
 *  @file static_cpu_info_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <hcc/cpu_id.h>
#include <asm/hcc/cpuinfo.h>
#include <asm/processor.h>
#include <linux/swap.h>

#include <gdm/gdm.h>

#include "static_cpu_info_linker.h"

#include <hcc/debug.h>

struct gdm_set *static_cpu_info_gdm_set;

/*****************************************************************************/
/*                                                                           */
/*                    STATIC CPU INFO GDM IO FUNCTIONS                      */
/*                                                                           */
/*****************************************************************************/

hcc_node_t cpu_info_default_owner(struct gdm_set *set,
					objid_t objid,
					const hcc_nodemask_t *nodes,
					int nr_nodes)
{
	return hcc_cpu_node(objid);
}

/****************************************************************************/

/* Init the cpu info IO linker */

static struct iolinker_struct static_cpu_info_io_linker = {
	.linker_name = "stat_cpu_info",
	.linker_id = STATIC_CPU_INFO_LINKER,
	.default_owner = cpu_info_default_owner
};

int static_cpu_info_init(void)
{
	hcc_static_cpu_info_t *static_cpu_info;
	int cpu_id, i;

	register_io_linker(STATIC_CPU_INFO_LINKER, &static_cpu_info_io_linker);

	/* Create the CPU info gdm set */

	static_cpu_info_gdm_set =
		create_new_gdm_set(gdm_def_ns,
				    STATIC_CPU_INFO_GDM_ID,
				    STATIC_CPU_INFO_LINKER,
				    GDM_CUSTOM_DEF_OWNER,
				    sizeof(hcc_static_cpu_info_t),
				    0);
	if (IS_ERR(static_cpu_info_gdm_set))
		OOM;

	for_each_online_cpu (i) {
		cpu_id = hcc_cpu_id(i);
		cpu_data(i).hcc_cpu_id = cpu_id;

		static_cpu_info =
			_gdm_grab_object(static_cpu_info_gdm_set, cpu_id);

		static_cpu_info->info = cpu_data(i);
#ifndef CONFIG_USERMODE
		static_cpu_info->info.cpu_khz = cpu_khz;
#endif

		_gdm_put_object(static_cpu_info_gdm_set, cpu_id);
	}

	return 0;
}
