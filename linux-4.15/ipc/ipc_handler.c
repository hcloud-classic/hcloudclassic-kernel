#ifndef NO_IPC
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/msg.h>

struct ipc_namespace *find_get_hcc_ipcns(void)
{
	struct hcc_namespace *hcc_ns;
	struct ipc_namespace *ipc_ns;

	hcc_ns = find_get_hcc_ns();
	if (!hcc_ns)
		goto error;

	if (!hcc_ns->root_nsproxy.ipc_ns)
		goto error_ipcns;

	ipc_ns = get_ipc_ns(hcc_ns->root_nsproxy.ipc_ns);

	put_hcc_ns(hcc_ns);

	return ipc_ns;

error_ipcns:
	put_hcc_ns(hcc_ns);
error:
	return NULL;
}


int hcc_ipc_get_maxid(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map;
	int max_id;

	ipc_map = _get_object(ids->hccops->map_set, 0);
	max_id = ipc_map->alloc_map - 1;
	_put_object(ids->hccops->map_set, 0);

	return max_id;
}

int hcc_ipc_get_new_id(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i = 1, id = -1, offset;

	max_id = _grab_object(ids->hccops->map_set, 0);

	while (id == -1) {
		ipc_map = _grab_object(ids->hccops->map_set, i);

		if (ipc_map->alloc_map != ULONG_MAX) {
			offset = find_first_zero_bit(&ipc_map->alloc_map,
						     BITS_PER_LONG);

			if (offset < BITS_PER_LONG) {

				id = (i-1) * BITS_PER_LONG + offset;
				set_bit(offset, &ipc_map->alloc_map);
				if (id >= max_id->alloc_map)
					max_id->alloc_map = id + 1;
			}
		}

		_put_object(ids->hccops->map_set, i);
		i++;
	}

	_put_object(ids->hccops->map_set, 0);

	return id;
}


int hcc_ipc_get_this_id(struct ipc_ids *ids, int id)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i, offset, ret = 0;

	max_id = _grab_object(ids->hccops->map_set, 0);

	offset = id % BITS_PER_LONG;
	i = (id - offset)/BITS_PER_LONG +1;

	ipc_map = _grab_object(ids->hccops->map_set, i);

	if (test_and_set_bit(offset, &ipc_map->alloc_map)) {
		ret = -EBUSY;
		goto out_id_unavailable;
	}

	if (id >= max_id->alloc_map)
		max_id->alloc_map = id + 1;

out_id_unavailable:
	_put_object(ids->hccops->map_set, i);
	_put_object(ids->hccops->map_set, 0);

	return ret;
}

void hcc_ipc_rmid(struct ipc_ids* ids, int index)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i, offset;


	i = 1 + index / BITS_PER_LONG;
	offset = index % BITS_PER_LONG;

	ipc_map = _grab_object(ids->hccops->map_set, i);

	BUG_ON(!test_bit(offset, &ipc_map->alloc_map));

	clear_bit(offset, &ipc_map->alloc_map);

	_put_object(ids->hccops->map_set, i);

	/* Check if max_id must be adjusted */

	max_id = _grab_object(ids->hccops->map_set, 0);

	if (max_id->alloc_map != index + 1)
		goto done;

	for (; i > 0; i--) {

		ipc_map = _grab_object(ids->hccops->map_set, i);
		if (ipc_map->alloc_map != 0) {
			for (; offset >= 0; offset--) {
				if (test_bit (offset, &ipc_map->alloc_map)) {
					max_id->alloc_map = 1 + offset +
						(i - 1) * BITS_PER_LONG;
					_put_object(
						ids->hccops->map_set, i);
					goto done;
				}
			}
		}
		offset = 31;
		_put_object(ids->hccops->map_set, i);
	}

	max_id->alloc_map = 0;
done:
	_put_object(ids->hccops->map_set, 0);

	return;
}
static void do_cleanup_ipc_objects (unique_id_t set_id)
{
	ipcmap_object_t *ipc_map;

	ipc_map = _grab_object_no_ft(_def_ns, set_id, 0);
	if (ipc_map) {
		BUG_ON (ipc_map->alloc_map != 0);
		_remove_frozen_object(_def_ns, set_id, 0);
	}
	else
		_put_object(_def_ns, set_id, 0);
}

void cleanup_ipc_objects ()
{
	do_cleanup_ipc_objects (MSGMAP_HCC_ID);
	do_cleanup_ipc_objects (SEMMAP_HCC_ID);
	do_cleanup_ipc_objects (SHMMAP_HCC_ID);
}

static int ipc_procfs_start(void)
{
	int r;
	int err = -EINVAL;

	r = register_proc_service(KSYS_IPC_MSGQ_CHKPT, proc_msgq_chkpt);
	if (r != 0)
		goto err;

	r = register_proc_service(KSYS_IPC_MSGQ_RESTART, proc_msgq_restart);
	if (r != 0)
		goto unreg_msgq_chkpt;

	r = register_proc_service(KSYS_IPC_SEM_CHKPT, proc_sem_chkpt);
	if (r != 0)
		goto unreg_msgq_restart;

	r = register_proc_service(KSYS_IPC_SEM_RESTART, proc_sem_restart);
	if (r != 0)
		goto unreg_sem_chkpt;

	r = register_proc_service(KSYS_IPC_SHM_CHKPT, proc_shm_chkpt);
	if (r != 0)
		goto unreg_sem_restart;

	r = register_proc_service(KSYS_IPC_SHM_RESTART, proc_shm_restart);
	if (r != 0)
		goto unreg_shm_chkpt;

	return 0;

unreg_shm_chkpt:
	unregister_proc_service(KSYS_IPC_SHM_CHKPT);
unreg_sem_restart:
	unregister_proc_service(KSYS_IPC_SEM_RESTART);
unreg_sem_chkpt:
	unregister_proc_service(KSYS_IPC_SEM_CHKPT);
unreg_msgq_restart:
	unregister_proc_service(KSYS_IPC_MSGQ_RESTART);
unreg_msgq_chkpt:
	unregister_proc_service(KSYS_IPC_MSGQ_CHKPT);
err:
	return err;
}
#endif