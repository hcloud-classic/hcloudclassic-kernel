#ifndef NO_SHM

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/shm.h>
#include <linux/msg.h>

#include "shm_handler.h"


static struct kern_ipc_perm *hcb_ipc_shm_lock(struct ipc_ids *ids, int id)
{
	shmid_object_t *shp_object;
	struct shmid_kernel *shp;
	int index;

	rcu_read_lock();

	index = ipcid_to_idx(id);

	shp_object = _gdm_grab_object_no_ft(ids->hccops->data_gdm_set, index);

	if (!shp_object)
		goto error;

	shp = shp_object->local_shp;

	BUG_ON(!shp);

	mutex_lock(&shp->shm_perm.mutex);

	if (shp->shm_perm.deleted) {
		mutex_unlock(&shp->shm_perm.mutex);
		goto error;
	}

	return &(shp->shm_perm);

error:
	_gdm_put_object(ids->hccops->data_gdm_set, index);
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}



static void hcb_ipc_shm_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	_gdm_put_object(ipcp->hccops->data_gdm_set, index);

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}

static struct kern_ipc_perm *hcb_ipc_shm_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;
	int id = -1;

	key_index = _gdm_get_object_no_ft(ids->hccops->key_gdm_set, key);

	if (key_index)
		id = *key_index;

	_gdm_put_object(ids->hccops->key_gdm_set, key);

	if (id != -1)
		return hcb_ipc_shm_lock(ids, id);

	return NULL;
}


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