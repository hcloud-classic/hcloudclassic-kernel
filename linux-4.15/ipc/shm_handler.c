#ifndef NO_SHM

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/shm.h>
#include <linux/msg.h>

#include "shm_handler.h"



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