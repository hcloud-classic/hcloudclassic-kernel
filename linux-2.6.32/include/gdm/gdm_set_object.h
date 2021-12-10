/** GDM set object.
 *  @file gdm_set_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_SET_OBJECT__
#define __GDM_SET_OBJECT__

#include <gdm/gdm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Set the initial value of an object. */
int _gdm_set_object_state(struct gdm_set *set, objid_t objid, void *object,
			   gdm_obj_state_t state);

int gdm_set_object_state(struct gdm_ns *ns, gdm_set_id_t set_id,
			  objid_t objid, void *object, gdm_obj_state_t state);

int _gdm_set_object(struct gdm_set *set, objid_t objid, void *object);

int gdm_set_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid,
		    void *object);

#endif
