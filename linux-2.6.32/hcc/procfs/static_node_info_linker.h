/** Static node informations management.
 *  @file static_node_info_linker.h
 *
 *  @author Innogrid HCC
 */

#ifndef STATIC_NODE_INFO_LINKER_H
#define STATIC_NODE_INFO_LINKER_H

#include <gdm/gdm.h>
#include <gdm/object_server.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Static node informations */

typedef struct {
	int nr_cpu;		/* Number of CPU on the node */
	unsigned long totalram;	/* Total usable main memory size */
	unsigned long totalhigh;	/* Total high memory size */
} hcc_static_node_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct gdm_set *static_node_info_gdm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int static_node_info_init(void);

/** Helper function to get static node informations.
 *  @author Innogrid HCC
 *
 *  @param node_id   Id of the node we want informations on.
 *
 *  @return  Structure containing information on the requested node.
 */
static inline hcc_static_node_info_t *get_static_node_info(int node_id)
{
	return _fgdm_get_object(static_node_info_gdm_set, node_id,
				 GDM_NO_FREEZE|GDM_NO_FT_REQ);
}

hcc_node_t node_info_default_owner(struct gdm_set *set,
					 objid_t objid,
					 const hcc_nodemask_t *nodes,
					 int nr_nodes);

#endif /* STATIC_NODE_INFO_LINKER_H */
