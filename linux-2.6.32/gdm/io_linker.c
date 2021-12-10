/** GDM IO linker interface.
 *  @file io_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/hcc_flags.h>

#include <net/grpc/grpc.h>
#include <gdm/gdm.h>
#include <gdm/io_linker.h>


struct iolinker_struct *iolinker_list[MAX_IO_LINKER];

hcc_nodemask_t hcc_node_gdm_map;
hcc_node_t gdm_nb_nodes;


/*****************************************************************************/
/*                                                                           */
/*                     INSTANTIATE/UNINSTANTIATE FUNCTIONS                   */
/*                                                                           */
/*****************************************************************************/



/** Instantiate a gdm set with an IO linker.
 *  @author Innogrid HCC
 *
 *  @param set           Kddm set to instantiate.
 *  @param link          Node linked to the gdm set.
 *  @param iolinker_id   Id of the linker to link to the gdm set.
 *  @param private_data  Data used by the instantiator...
 *
 *  @return  Structure of the requested gdm set or NULL if not found.
 */
int gdm_io_instantiate (struct gdm_set * set,
			 hcc_node_t def_owner,
			 iolinker_id_t iolinker_id,
			 void *private_data,
			 int data_size,
			 int master)
{
	int err = 0;

	BUG_ON (set == NULL);
	BUG_ON (iolinker_id < 0 || iolinker_id >= MAX_IO_LINKER);
	BUG_ON (set->state != GDM_SET_LOCKED);

	while (iolinker_list[iolinker_id] == NULL) {
		WARNING ("Instantiate a gdm set with a not registered IO "
			 "linker (%d)... Retry in 1 second\n", iolinker_id);
		set_current_state (TASK_INTERRUPTIBLE);
		schedule_timeout (1 * HZ);
	}

	set->def_owner = def_owner;
	set->iolinker = iolinker_list[iolinker_id];

	if (data_size) {
		set->private_data = kmalloc (data_size, GFP_KERNEL);
		BUG_ON (set->private_data == NULL);
		memcpy (set->private_data, private_data, data_size);
		set->private_data_size = data_size;
	}
	else {
		set->private_data = NULL;
		set->private_data_size = 0;
	}

	if (set->iolinker->instantiate)
		err = set->iolinker->instantiate (set, private_data,
						  master);

	return err;
}



/** Uninstantiate a gdm set.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set to uninstantiate
 */
void gdm_io_uninstantiate (struct gdm_set * set,
                            int destroy)
{
	if (set->iolinker && set->iolinker->uninstantiate)
		set->iolinker->uninstantiate (set, destroy);

	if (set->private_data)
		kfree(set->private_data);
	set->private_data = NULL;
	set->iolinker = NULL;
}



/*****************************************************************************/
/*                                                                           */
/*                      MAIN IO LINKER INTERFACE FUNCTIONS                   */
/*                                                                           */
/*****************************************************************************/



/** Request an IO linker to allocate an object.
 *  @author Innogrid HCC
 *
 *  @param obj_entry    Object entry to export data from.
 *  @param set          Kddm Set the object belong to.
 */
int gdm_io_alloc_object (struct gdm_obj * obj_entry,
			  struct gdm_set * set,
			  objid_t objid)
{
	int r = 0;

	if (obj_entry->object != NULL)
		goto done;

	if (set->iolinker && set->iolinker->alloc_object)
		r = set->iolinker->alloc_object (obj_entry, set, objid);
	else {
		/* Default allocation function */
		obj_entry->object = kmalloc(set->obj_size, GFP_KERNEL);
		if (obj_entry->object == NULL)
			r = -ENOMEM;
	}

	if (obj_entry->object != NULL)
		atomic_inc(&set->nr_objects);

done:
	return r;
}



/** Request an IO linker to do an object first touch.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to first touch.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_first_touch_object (struct gdm_obj * obj_entry,
                                struct gdm_set * set,
                                objid_t objid,
				int flags)
{
	int res = 0 ;

	BUG_ON (obj_entry->object != NULL);
	BUG_ON (OBJ_STATE(obj_entry) != INV_FILLING);

	if (set->iolinker && set->iolinker->first_touch) {
		res = set->iolinker->first_touch (obj_entry, set,
						  objid, flags);
		if (obj_entry->object)
			atomic_inc(&set->nr_objects);
	}
	else
		res = gdm_io_alloc_object(obj_entry, set, objid);

	return res ;
}



/** Request an IO linker to insert an object in a gdm set.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to insert.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_insert_object (struct gdm_obj * obj_entry,
                           struct gdm_set * set,
                           objid_t objid)
{
	int res = 0;

	if (set->iolinker && set->iolinker->insert_object)
		res = set->iolinker->insert_object (obj_entry, set,
						    objid);

	return res;
}



/** Request an IO linker to put a gdm object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to put.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_put_object (struct gdm_obj * obj_entry,
                        struct gdm_set * set,
                        objid_t objid)
{
	int res = 0;

	ASSERT_OBJ_PATH_LOCKED(set, objid);

	if (set && set->iolinker->put_object)
		res = set->iolinker->put_object (obj_entry, set,
						 objid);

	return res;
}



/** Request an IO linker to invalidate an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to invalidate.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_invalidate_object (struct gdm_obj * obj_entry,
			       struct gdm_set * set,
			       objid_t objid)
{
	int res = 0;

	ASSERT_OBJ_PATH_LOCKED(set, objid);

	if (obj_entry->object) {
		if (set->iolinker && set->iolinker->invalidate_object) {
			res = set->iolinker->invalidate_object (obj_entry,
								set, objid);

			if (res != GDM_IO_KEEP_OBJECT)
				obj_entry->object = NULL;
		}

		if (obj_entry->object == NULL)
			atomic_dec(&set->nr_objects);
	}

	return res;
}



/** Request an IO linker to remove an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to remove.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_remove_object (void *object,
			   struct gdm_set * set,
			   objid_t objid)
{
	int res = 0;

	if (set->iolinker && set->iolinker->remove_object) {
		might_sleep();
		res = set->iolinker->remove_object (object, set, objid);
	}
	else
		/* Default free function */
		kfree (object);

	atomic_dec(&set->nr_objects);

	return res;
}

int gdm_io_remove_object_and_unlock (struct gdm_obj * obj_entry,
				      struct gdm_set * set,
				      objid_t objid)
{
	int res = 0;
	void *object;

	ASSERT_OBJ_PATH_LOCKED(set, objid);

	object = obj_entry->object;

	if (object == NULL) {
		put_gdm_obj_entry(set, obj_entry, objid);
		goto done;
	}

	obj_entry->object = NULL;
	put_gdm_obj_entry(set, obj_entry, objid);

	res = gdm_io_remove_object (object, set, objid);

done:
	return res;
}



/** Request an IO linker to sync an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_sync_object (struct gdm_obj * obj_entry,
                         struct gdm_set * set,
                         objid_t objid)
{
	int res = 0 ;

	if (set->iolinker && set->iolinker->sync_object)
		res = set->iolinker->sync_object (obj_entry, set, objid);
	else
		BUG();

	return res ;
}



/** Inform an IO linker that an object state has changed.
 *  @author Innogrid HCC
 *
 *  @param obj_entry    Object entry the object belong to.
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param new_state    New state for the object.
 */
int gdm_io_change_state (struct gdm_obj * obj_entry,
			  struct gdm_set * set,
			  objid_t objid,
			  gdm_obj_state_t new_state)
{
	if (set->iolinker && set->iolinker->change_state)
		set->iolinker->change_state (obj_entry, set, objid, new_state);

	return 0 ;
}



/** Request an IO linker to import data into an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to import data into.
 *  @param buffer       Buffer containing data to import.
 */
int gdm_io_import_object (struct grpc_desc *desc,
                           struct gdm_set *set,
                           struct gdm_obj *obj_entry,
                           objid_t objid,
			   int flags)
{
	struct iolinker_struct *io = set->iolinker;
	int res;

	BUG_ON (OBJ_STATE(obj_entry) != INV_FILLING);

	might_sleep();

	if (io && io->import_object)
		res = io->import_object(desc, set, obj_entry, objid, flags);
	else
		res = grpc_unpack(desc, 0, obj_entry->object, set->obj_size);

	return res;
}



/** Request an IO linker to export data from an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to export data from.
 *  @param desc		GRPC descriptor to export data on.
 */
int gdm_io_export_object (struct grpc_desc *desc,
			   struct gdm_set *set,
                           struct gdm_obj *obj_entry,
                           objid_t objid,
			   int flags)
{
	struct iolinker_struct *io = set->iolinker;
	int res;

	if (io && io->export_object)
		res = io->export_object(desc, set, obj_entry, objid, flags);
	else
		res = grpc_pack(desc, 0, obj_entry->object, set->obj_size);

	return res;
}

hcc_node_t __gdm_io_default_owner (struct gdm_set *set,
					  objid_t objid,
					  const hcc_nodemask_t *nodes,
					  int nr_nodes)
{
	switch (set->def_owner) {
	  case GDM_RR_DEF_OWNER:
		  if (likely(__hcc_node_isset(hcc_node_id, nodes)))
			  return __nth_hcc_node(objid % nr_nodes, nodes);
		  else
			  return hcc_node_id;

	  case GDM_UNIQUE_ID_DEF_OWNER:
		  return objid >> UNIQUE_ID_NODE_SHIFT;

	  case GDM_CUSTOM_DEF_OWNER:
		  return set->iolinker->default_owner (set, objid,
						       nodes, nr_nodes);

	  default:
		  return set->def_owner;
	}
}

hcc_node_t gdm_io_default_owner (struct gdm_set * set, objid_t objid)
{
	return __gdm_io_default_owner (set, objid,
					&hcc_node_gdm_map,
					gdm_nb_nodes);
}


/*****************************************************************************/
/*                                                                           */
/*                           IO LINKER INIT FUNCTIONS                        */
/*                                                                           */
/*****************************************************************************/



/** Register a new gdm set IO linker.
 *  @author Innogrid HCC
 *
 *  @param io_linker_id
 *  @param linker
 */
int register_io_linker (int linker_id,
                        struct iolinker_struct *io_linker)
{
	if(iolinker_list[linker_id] != NULL)
		return -1;

	iolinker_list[linker_id] = io_linker;

	return 0;
}



/** Initialise the IO linker array with existing linker
 */
void io_linker_init (void)
{
	int i;

	gdm_nb_nodes = hcc_nb_nodes;
	hcc_nodes_copy(hcc_node_gdm_map, hcc_node_online_map);

	for (i = 0; i < MAX_IO_LINKER; i++)
		iolinker_list[i] = NULL;
}



/** Initialise the IO linker array with existing linker
 */
void io_linker_finalize (void)
{
}
