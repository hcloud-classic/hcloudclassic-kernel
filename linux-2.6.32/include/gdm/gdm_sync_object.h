/** GDM sync object.
 *  @file gdm_sync_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_SYNC_OBJECT__
#define __GDM_SYNC_OBJECT__

#include <gdm/gdm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Sync an object from local memory */
int gdm_sync_frozen_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			    objid_t objid);

int _gdm_sync_frozen_object(struct gdm_set *set, objid_t objid);

#endif
