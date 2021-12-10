/** GDM grab object.
 *  @file gdm_grab_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_GRAB_OBJECT__
#define __GDM_GRAB_OBJECT__

#include <gdm/gdm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Place a write copy of a given object in local physical memory. */
void *gdm_grab_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid);

void *_gdm_grab_object(struct gdm_set *set, objid_t objid);

void *__gdm_grab_object(struct gdm_set *set, struct gdm_obj *obj_entry,
			 objid_t objid);

/** Asynchronous version of the grab_object function. */
void *async_gdm_grab_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			     objid_t objid);

void *_async_gdm_grab_object(struct gdm_set *set, objid_t objid);

void *__async_gdm_grab_object(struct gdm_set *set,
			       struct gdm_obj *obj_entry, objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *gdm_grab_object_no_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
			     objid_t objid);

void *_gdm_grab_object_no_ft(struct gdm_set *set, objid_t objid);

void *__gdm_grab_object_no_ft(struct gdm_set *set,
			       struct gdm_obj *obj_entry, objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *async_gdm_grab_object_no_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
			     objid_t objid);

void *_async_gdm_grab_object_no_ft(struct gdm_set *set, objid_t objid);

void *__async_gdm_grab_object_no_ft(struct gdm_set *set,
				     struct gdm_obj *obj_entry,objid_t objid);

/** Prepare an object to be manually filled by the function called */
void *gdm_grab_object_manual_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
				 objid_t objid);

void *_gdm_grab_object_manual_ft(struct gdm_set *set, objid_t objid);

void *__gdm_grab_object_manual_ft(struct gdm_set *set,
				   struct gdm_obj *obj_entry,
				   objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *gdm_grab_object_no_lock(struct gdm_ns *ns, gdm_set_id_t set_id,
			       objid_t objid);

void *_gdm_grab_object_no_lock(struct gdm_set *set, objid_t objid);

void *__gdm_grab_object_no_lock(struct gdm_set *set,
				 struct gdm_obj *obj_entry, objid_t objid);

/** Place a existing copy of a given object in local physical memory. */
void *gdm_try_grab_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			   objid_t objid);

void *_gdm_try_grab_object(struct gdm_set *set, objid_t objid);

void *__gdm_try_grab_object(struct gdm_set *set,
			     struct gdm_obj *obj_entry, objid_t objid);

void *_gdm_grab_object_cow(struct gdm_set *set, objid_t objid);

/** Generic grab function with free use of GDM flags */
void *fgdm_grab_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			objid_t objid, int flags);

#endif
