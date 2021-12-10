/** Static node information management.
 *  @file static_node_info_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/swap.h>
#include <gdm/gdm.h>

#include "static_node_info_linker.h"

#include <hcc/debug.h>

struct gdm_set *static_node_info_gdm_set;

/*****************************************************************************/
/*                                                                           */
/*                     STATIC NODE INFO GDM IO FUNCTIONS                    */
/*                                                                           */
/*****************************************************************************/

hcc_node_t node_info_default_owner(struct gdm_set *set,
					 objid_t objid,
					 const hcc_nodemask_t *nodes,
					 int nr_nodes)
{
	return objid;
}

/****************************************************************************/

/* Init the static node info IO linker */

static struct iolinker_struct static_node_info_io_linker = {
	.default_owner = node_info_default_owner,
	.linker_name = "stat_node_nfo",
	.linker_id = STATIC_NODE_INFO_LINKER,
};

int static_node_info_init()
{
	hcc_static_node_info_t *static_node_info;

	register_io_linker(STATIC_NODE_INFO_LINKER,
			   &static_node_info_io_linker);

	/* Create the static node info gdm set */

	static_node_info_gdm_set =
		create_new_gdm_set(gdm_def_ns,
				    STATIC_NODE_INFO_GDM_ID,
				    STATIC_NODE_INFO_LINKER,
				    GDM_CUSTOM_DEF_OWNER,
				    sizeof(hcc_static_node_info_t),
				    0);
	if (IS_ERR(static_node_info_gdm_set))
		OOM;

	static_node_info = _gdm_grab_object(static_node_info_gdm_set,
					     hcc_node_id);

	static_node_info->nr_cpu = num_online_cpus();
	static_node_info->totalram = totalram_pages;
	static_node_info->totalhigh = totalhigh_pages;

	_gdm_put_object(static_node_info_gdm_set, hcc_node_id);

	return 0;
}
