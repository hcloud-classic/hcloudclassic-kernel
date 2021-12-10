/** Static CPU information management.
 *  @file static_cpu_info_linker.h
 *
 *  @author Innogrid HCC
 */

#ifndef STATIC_CPU_INFO_LINKER_H
#define STATIC_CPU_INFO_LINKER_H

#include <hcc/cpu_id.h>
#include <gdm/gdm.h>
#include <gdm/object_server.h>
#include <asm/hcc/cpuinfo.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Static CPU informations */

typedef struct {
	cpuinfo_t info;
} hcc_static_cpu_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct gdm_set *static_cpu_info_gdm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int static_cpu_info_init(void);

/** Helper function to get static CPU informations.
 *  @author Innogrid HCC
 *
 *  @param node_id   Id of the node hosting the CPU we want informations on.
 *  @param cpu_id    Id of the CPU we want informations on.
 *
 *  @return  Structure containing information on the requested CPU.
 */
static inline hcc_static_cpu_info_t *get_static_cpu_info(int node_id,
							 int cpu_id)
{
	return _fgdm_get_object(static_cpu_info_gdm_set,
				 __hcc_cpu_id(node_id, cpu_id),
				 GDM_NO_FREEZE|GDM_NO_FT_REQ);
}

hcc_node_t cpu_info_default_owner(struct gdm_set *set,
					objid_t objid,
					const hcc_nodemask_t *nodes,
					int nr_nodes);

#endif /* STATIC_CPU_INFO LINKER_H */
