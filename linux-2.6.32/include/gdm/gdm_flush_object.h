/** GDM flush object.
 *  @file gdm_flush_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_FLUSH_OBJECT__
#define __GDM_FLUSH_OBJECT__

#include <gdm/gdm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Flush an object from local memory */
int gdm_flush_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid,
		      hcc_node_t dest);

int _gdm_flush_object(struct gdm_set *set, objid_t objid,
		       hcc_node_t dest);

#endif
