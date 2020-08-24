#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <hcloud/sys/types.h>
#include <hcloud/hccinit.h>
#include <hcloud/hccflags.h>

#include <net/hccrpc/rpc.h>
#include <gdm/gdm.h>
#include <gdm/io_linker.h>


struct iolinker_struct *iolinker_list[MAX_IO_LINKER];

hccnodemask_t hccnode_gdm_map;
hcloud_node_t gdm_nb_nodes;


int gdm_io_instantiate (struct gdm_set * set,
			 hcloud_node_t def_owner,
			 iolinker_id_t iolinker_id,
			 void *private_data,
			 int data_size,
			 int master)
{
	int err = 0;

	BUG_ON (set == NULL);
	BUG_ON (iolinker_id < 0 || iolinker_id >= MAX_IO_LINKER);
	BUG_ON (set->state != gdm_SET_LOCKED);

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
