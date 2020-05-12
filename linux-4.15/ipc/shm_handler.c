#ifndef NO_SHM

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/shm.h>
#include <linux/msg.h>

#include "shm_handler.h"


int hcc_ipc_shm_newseg (struct ipc_namespace *ns, struct shmid_kernel *shp)
{
	shmid_object_t *shp_object;
	struct gdm_set *gdm;
	long *key_index;
	int index, err;

	BUG_ON(!shm_ids(ns).hccops);

	index = ipcid_to_idx(shp->shm_perm.id);

	shp_object = gdm_grab_object_manual_ft(
		shm_ids(ns).hccops->data_set, index);

	BUG_ON(shp_object);

	shp_object = kmem_cache_alloc(shmid_object_cachep, GFP_KERNEL);
	if (!shp_object) {
		err = -ENOMEM;
		goto err_put;
	}

	gdm = gdm_create_new_set (gdm_def_ns, 0, SHM_MEMORY_LINKER,
				     hcloud_node_id, PAGE_SIZE,
				     &shp->shm_perm.id, sizeof(int), 0);

	if (IS_ERR(gdm)) {
		err = PTR_ERR(gdm);
		goto err_put;
	}

	shp->shm_file->f_dentry->d_inode->i_mapping->gdm_set = gdm;
	shp->shm_file->f_op = &hcc_shm_file_operations;

	shp_object->set_id = gdm->id;

	shp_object->local_shp = shp;

	_set_object(shm_ids(ns).hccops->data_set, index, shp_object);

	if (shp->shm_perm.key != IPC_PRIVATE)
	{
		key_index = _grab_object(shm_ids(ns).hccops->key_set,
					      shp->shm_perm.key);
		*key_index = index;
		_put_object (shm_ids(ns).hccops->key_set,
				  shp->shm_perm.key);
	}

	shp->shm_perm.hccops = shm_ids(ns).hccops;

err_put:
	_put_object(shm_ids(ns).hccops->data_set, index);

	return 0;

}

void hcc_ipc_shm_rmkey(struct ipc_namespace *ns, key_t key)
{
	_remove_object(shm_ids(ns).hccops->key_set, key);
}


void hcc_ipc_shm_destroy(struct ipc_namespace *ns, struct shmid_kernel *shp)
{
	struct hcc_set *mm_set;
	int index;
	key_t key;

	index = ipcid_to_idx(shp->shm_perm.id);
	key = shp->shm_perm.key;

	mm_set = shp->shm_file->f_dentry->d_inode->i_mapping->hcc_set;

	if (key != IPC_PRIVATE) {
		_hcc_grab_object_no_ft(shm_ids(ns).hccops->key_hcc_set, key);
		_hcc_remove_frozen_object(shm_ids(ns).hccops->key_hcc_set, key);
	}

	local_shm_unlock(shp);

	_hcc_remove_frozen_object(shm_ids(ns).hccops->data_hcc_set, index);
	_destroy_hcc_set(mm_set);

	hcc_ipc_rmid(&shm_ids(ns), index);
}