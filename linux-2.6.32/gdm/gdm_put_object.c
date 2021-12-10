/** GDM put object
 *  @file gdm_put_object.c
 *
 *  Implementation of GDM put object function.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/module.h>

#include <gdm/gdm.h>
#include "protocol_action.h"


/** Release an object which has been acquired by a get, grab or find.
 *  @author Innogrid HCC
 *
 *  @param set        GDM set hosting the object.
 *  @param obj_entry  Object entry of the object to put.
 *  @param objid      Identifier of the object to put.
 *
 *  @return           Pointer to the object if it is present in memory,
 *                    NULL otherwise.
 */
void _gdm_put_object(struct gdm_set *set,
		      objid_t objid)
{
	struct gdm_obj *obj_entry;
	int pending = 0;

	obj_entry = __get_gdm_obj_entry(set, objid);
	if (!obj_entry)
		return;

	/* The object is not frozen, nothing to do */
	if (atomic_read(&obj_entry->frozen_count) == 0)
		goto exit;

	gdm_io_put_object(obj_entry, set, objid);
	object_clear_frozen(obj_entry, set);
	if (TEST_OBJECT_PENDING(obj_entry)) {
		CLEAR_OBJECT_PENDING(obj_entry);
		pending = 1;
	}

exit:
	put_gdm_obj_entry(set, obj_entry, objid);
	if (pending)
		flush_gdm_event(set, objid);
}
EXPORT_SYMBOL(_gdm_put_object);



void gdm_put_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid)
{
	struct gdm_set *set;

	set = _find_get_gdm_set (ns, set_id);
	_gdm_put_object(set, objid);
	put_gdm_set(set);
}
EXPORT_SYMBOL(gdm_put_object);
