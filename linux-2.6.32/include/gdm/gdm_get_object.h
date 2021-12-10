/** GDM get object.
 *  @file gdm_get_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_GET_OBJECT__
#define __GDM_GET_OBJECT__

#include <gdm/gdm_set.h>


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Place a read-only copy of a given object in local physical memory. */
void *gdm_get_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid);

void *_gdm_get_object(struct gdm_set *set, objid_t objid);



/** Asynchronous version of the get_object function. */
void *async_gdm_get_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			    objid_t objid);

void *_async_gdm_get_object(struct gdm_set *set, objid_t objid);



/** Place a existing copy of a given object in local physical memory. */
void *gdm_get_object_no_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
			    objid_t objid);

void *_gdm_get_object_no_ft(struct gdm_set *set, objid_t objid);



/** Prepare an object to be manually filled by the function called */
void *gdm_get_object_manual_ft(struct gdm_ns *ns, gdm_set_id_t set_id,
				objid_t objid);

void *_gdm_get_object_manual_ft(struct gdm_set *set, objid_t objid);



/** Place a existing copy of a given object in local physical memory. */
void *gdm_get_object_no_lock(struct gdm_ns *ns, gdm_set_id_t set_id,
			      objid_t objid);

void *_gdm_get_object_no_lock(struct gdm_set *set, objid_t objid);

/** Generic get functions with free use of GDM flags */
void *fgdm_get_object(struct gdm_ns *ns, gdm_set_id_t set_id,
		       objid_t objid, int flags);

void *_fgdm_get_object(struct gdm_set *set, objid_t objid, int flags);

#endif
