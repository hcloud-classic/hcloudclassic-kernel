/** GDM sync object
 *  @file gdm_sync_object.c
 *
 *  Implementation of GDM sync object function.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/module.h>

#include <gdm/gdm.h>
#include <gdm/object_server.h>
#include "protocol_action.h"


/** Synchronize an object with its attached physical device.
 *  @author Innogrid HCC
 *
 *  @param set        GDM set hosting the object.
 *  @param obj_entry  Object entry of the object to sync.
 *  @param objid      Identifier of the object to sync.
 *  @param dest       Identifier of the node to send object to if needed.
 *  @return           0 if everything OK, -1 otherwise.
 */
int _gdm_sync_frozen_object(struct gdm_set *set,
			     objid_t objid)
{
	gdm_obj_state_t new_state = INV_COPY;
	struct gdm_obj *obj_entry;
	int res = -1;

	BUG_ON(!gdm_ft_linked(set));

	obj_entry = __get_gdm_obj_entry(set, objid);
	if (obj_entry == NULL)
		return -ENOENT;

	BUG_ON(!object_frozen(obj_entry, set));

	switch (OBJ_STATE(obj_entry)) {
	case WRITE_OWNER:
		new_state = READ_OWNER;
		break;

	case READ_OWNER:
	case READ_COPY:
		new_state = OBJ_STATE(obj_entry);
		break;

	default:
		STATE_MACHINE_ERROR(set->id, objid, obj_entry);
		break;
	}

	if (I_AM_DEFAULT_OWNER(set, objid)) {
		put_gdm_obj_entry(set, obj_entry, objid);
		res = gdm_io_sync_object(obj_entry, set, objid);
	}
	else
		request_sync_object_and_unlock(set, obj_entry, objid,
					       new_state);

	return res;
}
EXPORT_SYMBOL(_gdm_sync_frozen_object);

int gdm_sync_frozen_object(struct gdm_ns *ns, gdm_set_id_t set_id,
			    objid_t objid)
{
	struct gdm_set *set;
	int res;

	set = _find_get_gdm_set (ns, set_id);
	res = _gdm_sync_frozen_object(set, objid);
	put_gdm_set(set);

	return res;
}
EXPORT_SYMBOL(gdm_sync_frozen_object);
