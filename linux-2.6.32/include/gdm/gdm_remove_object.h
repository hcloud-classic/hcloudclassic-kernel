


/** GDM remove object.
 *  @file gdm_remove_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_REMOVE_OBJECT__
#define __GDM_REMOVE_OBJECT__

#include <gdm/gdm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Remove an object from a gdm set cluster wide */
int gdm_remove_object(struct gdm_ns *ns, gdm_set_id_t set_id,
		       objid_t objid);

int _gdm_remove_object(struct gdm_set *set, objid_t objid);

int gdm_remove_frozen_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			      objid_t objid);

int _gdm_remove_frozen_object(struct gdm_set *set, objid_t objid);

#endif
