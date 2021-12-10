/** GDM find object.
 *  @file gdm_find_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_FIND_OBJECT__
#define __GDM_FIND_OBJECT__

#include <gdm/gdm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Check the presence of a given object in local physical memory. */
void *gdm_find_object (struct gdm_ns *ns, gdm_set_id_t set_id,
			objid_t objid);

void *_gdm_find_object (struct gdm_set *set, objid_t objid);

static inline void *_gdm_find_object_raw (struct gdm_set *set, objid_t objid)
{
	struct gdm_obj *obj_entry;
	void *obj = NULL;

	obj_entry = __get_gdm_obj_entry(set, objid);
	if (obj_entry) {
		obj = obj_entry->object;
		put_gdm_obj_entry(set, obj_entry, objid);
	}

	return obj;
}

#endif
