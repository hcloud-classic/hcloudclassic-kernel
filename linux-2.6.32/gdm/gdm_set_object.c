/** GDM set object
 *  @file gdm_set_object.c
 *
 *  Implementation of GDM set object function.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/module.h>

#include <gdm/gdm.h>
#include <gdm/object_server.h>
#include "protocol_action.h"


/** Set the initial value of an object.
 *  @author Innogrid HCC
 *
 *  @param set        GDM set hosting the object.
 *  @param obj_entry  Object entry of the object to set.
 *  @param objid      Identifier of the object to set.
 *  @param object     Object to store in the gdm set entry.
 *
 *  This function assumes that a call to gdm_*_object_manual_ft has been done
 *  before. A gdm_put_object must be done after.
 *
 *  @return        0 if everything OK, -1 otherwise.
 */
int _gdm_set_object_state(struct gdm_set *set,
			    objid_t objid,
			    void *object,
			    gdm_obj_state_t state)
{
	struct gdm_obj *obj_entry;

retry:
	obj_entry = __get_gdm_obj_entry(set, objid);

	BUG_ON(OBJ_STATE(obj_entry) != INV_OWNER);
	BUG_ON(!object_frozen(obj_entry, set));

	if (obj_entry->object != NULL) {
		gdm_io_remove_object_and_unlock(obj_entry, set, objid);
		printk ("Humf.... Can do really better !\n");
		goto retry;
	}

	obj_entry->object = object;
	atomic_inc(&set->nr_objects);
	ADD_TO_SET (COPYSET(obj_entry), hcc_node_id);
	gdm_insert_object (set, objid, obj_entry, state);
	put_gdm_obj_entry(set, obj_entry, objid);

	return 0;
}



int gdm_set_object_state(struct gdm_ns *ns, gdm_set_id_t set_id,
			  objid_t objid, void *object, gdm_obj_state_t state)
{
	struct gdm_set *set;
	int res;

	set = _find_get_gdm_set (ns, set_id);
	res = _gdm_set_object_state(set, objid, object, state);
	put_gdm_set(set);

	return res;
}



int _gdm_set_object(struct gdm_set *set, objid_t objid, void *object)
{
	return _gdm_set_object_state(set, objid, object, WRITE_OWNER);
}
EXPORT_SYMBOL(_gdm_set_object);

int gdm_set_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid,
		     void *object)
{
	struct gdm_set *set;
	int res;

	set = _find_get_gdm_set (ns, set_id);
	res = _gdm_set_object_state(set, objid, object, WRITE_OWNER);
	put_gdm_set(set);

	return res;
}
EXPORT_SYMBOL(gdm_set_object);
