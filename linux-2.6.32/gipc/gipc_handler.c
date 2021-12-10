/** Common code for IPC mechanism accross the cluster
 *  @file gipc_handler.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#ifndef NO_IPC

#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/msg.h>
#include <gdm/gdm.h>
#include <hcc/namespace.h>
#include <hcc/hcc_syscalls.h>
#include <hcc/hcc_services.h>
#include <hcc/procfs.h>
#include "gipc_checkpoint.h"
#include "gipcmap_io_linker.h"
#include "gipc_handler.h"
#include "util.h"
#include "hcc_msg.h"


struct ipc_namespace *find_get_hcc_gipcns(void)
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

/*****************************************************************************/
/*                                                                           */
/*                                KERNEL HOOKS                               */
/*                                                                           */
/*****************************************************************************/

int hcc_gipc_get_maxid(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map;
	int max_id;

	ipc_map = _gdm_get_object(ids->hcc_ops->map_gdm_set, 0);
	max_id = ipc_map->alloc_map - 1;
	_gdm_put_object(ids->hcc_ops->map_gdm_set, 0);

	return max_id;
}

int hcc_gipc_get_new_id(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i = 1, id = -1, offset;

	max_id = _gdm_grab_object(ids->hcc_ops->map_gdm_set, 0);

	while (id == -1) {
		ipc_map = _gdm_grab_object(ids->hcc_ops->map_gdm_set, i);

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

		_gdm_put_object(ids->hcc_ops->map_gdm_set, i);
		i++;
	}

	_gdm_put_object(ids->hcc_ops->map_gdm_set, 0);

	return id;
}

int hcc_gipc_get_this_id(struct ipc_ids *ids, int id)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i, offset, ret = 0;

	max_id = _gdm_grab_object(ids->hcc_ops->map_gdm_set, 0);

	offset = id % BITS_PER_LONG;
	i = (id - offset)/BITS_PER_LONG +1;

	ipc_map = _gdm_grab_object(ids->hcc_ops->map_gdm_set, i);

	if (test_and_set_bit(offset, &ipc_map->alloc_map)) {
		ret = -EBUSY;
		goto out_id_unavailable;
	}

	if (id >= max_id->alloc_map)
		max_id->alloc_map = id + 1;

out_id_unavailable:
	_gdm_put_object(ids->hcc_ops->map_gdm_set, i);
	_gdm_put_object(ids->hcc_ops->map_gdm_set, 0);

	return ret;
}

void hcc_gipc_rmid(struct ipc_ids* ids, int index)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i, offset;

	/* Clear the corresponding entry in the bit field */

	i = 1 + index / BITS_PER_LONG;
	offset = index % BITS_PER_LONG;

	ipc_map = _gdm_grab_object(ids->hcc_ops->map_gdm_set, i);

	BUG_ON(!test_bit(offset, &ipc_map->alloc_map));

	clear_bit(offset, &ipc_map->alloc_map);

	_gdm_put_object(ids->hcc_ops->map_gdm_set, i);

	/* Check if max_id must be adjusted */

	max_id = _gdm_grab_object(ids->hcc_ops->map_gdm_set, 0);

	if (max_id->alloc_map != index + 1)
		goto done;

	for (; i > 0; i--) {

		ipc_map = _gdm_grab_object(ids->hcc_ops->map_gdm_set, i);
		if (ipc_map->alloc_map != 0) {
			for (; offset >= 0; offset--) {
				if (test_bit (offset, &ipc_map->alloc_map)) {
					max_id->alloc_map = 1 + offset +
						(i - 1) * BITS_PER_LONG;
					_gdm_put_object(
						ids->hcc_ops->map_gdm_set, i);
					goto done;
				}
			}
		}
		offset = 31;
		_gdm_put_object(ids->hcc_ops->map_gdm_set, i);
	}

	max_id->alloc_map = 0;
done:
	_gdm_put_object(ids->hcc_ops->map_gdm_set, 0);

	return;
}

/*****************************************************************************/

int proc_msgq_chkpt(void *arg)
{
	int r;
	int args[2];
	int msgqid, fd;

	if (copy_from_user((void *) args, arg, 2*sizeof(int))) {
		PANIC("cannot set the arg of proc_msgq_checkpoint system call\n");
		return -EINVAL;
	}

	msgqid = args[0];
	fd = args[1];

	r = sys_msgq_checkpoint(msgqid, fd);

	return r;
}

int proc_msgq_restart(void *arg)
{
	int r;
	int fd;

	if (copy_from_user(&fd, arg, sizeof(int))) {
		PANIC("cannot set the arg of proc_msgq_restart system call\n");
		return -EINVAL;
	}

	r = sys_msgq_restart(fd);

	return r;
}

int proc_sem_chkpt(void *arg)
{
	int r;
	int args[2];
	int semid, fd;

	if (copy_from_user((void *) args, arg, 2*sizeof(int))) {
		PANIC("cannot set the arg of proc_sem_checkpoint system call\n");
		return -EINVAL;
	}

	semid = args[0];
	fd = args[1];

	r = sys_sem_checkpoint(semid, fd);

	return r;
}

int proc_sem_restart(void *arg)
{
	int r;
	int fd;

	if (copy_from_user(&fd, arg, sizeof(int))) {
		PANIC("cannot set the arg of proc_sem_restart system call\n");
		return -EINVAL;
	}

	r = sys_sem_restart(fd);

	return r;
}

int proc_shm_chkpt(void *arg)
{
	int r;
	int args[2];
	int shmid, fd;

	if (copy_from_user((void *) args, arg, 2*sizeof(int))) {
		PANIC("cannot set the arg of proc_shm_checkpoint system call\n");
		return -EINVAL;
	}

	shmid = args[0];
	fd = args[1];

	r = sys_shm_checkpoint(shmid, fd);

	return r;
}

int proc_shm_restart(void *arg)
{
	int r;
	int fd;

	if (copy_from_user(&fd, arg, sizeof(int))) {
		PANIC("cannot set the arg of proc_shm_restart system call\n");
		return -EINVAL;
	}

	r = sys_shm_restart(fd);

	return r;
}


static void do_cleanup_ipc_objects (unique_id_t set_id)
{
	ipcmap_object_t *ipc_map;

	ipc_map = gdm_grab_object_no_ft(gdm_def_ns, set_id, 0);
	if (ipc_map) {
		BUG_ON (ipc_map->alloc_map != 0);
		gdm_remove_frozen_object(gdm_def_ns, set_id, 0);
	}
	else
		gdm_put_object(gdm_def_ns, set_id, 0);
}



/* Get rid of possible conflicting objects before node addition.
 */
void cleanup_ipc_objects ()
{
	do_cleanup_ipc_objects (MSGMAP_GDM_ID);
	do_cleanup_ipc_objects (SEMMAP_GDM_ID);
	do_cleanup_ipc_objects (SHMMAP_GDM_ID);
}


/*****************************************************************************/
/*                                                                           */
/*                              INITIALIZATION                               */
/*                                                                           */
/*****************************************************************************/



static int ipc_procfs_start(void)
{
	int r;
	int err = -EINVAL;

	r = register_proc_service(HCC_SYS_IPC_MSGQ_CHKPT, proc_msgq_chkpt);
	if (r != 0)
		goto err;

	r = register_proc_service(HCC_SYS_IPC_MSGQ_RESTART, proc_msgq_restart);
	if (r != 0)
		goto unreg_msgq_chkpt;

	r = register_proc_service(HCC_SYS_IPC_SEM_CHKPT, proc_sem_chkpt);
	if (r != 0)
		goto unreg_msgq_restart;

	r = register_proc_service(HCC_SYS_IPC_SEM_RESTART, proc_sem_restart);
	if (r != 0)
		goto unreg_sem_chkpt;

	r = register_proc_service(HCC_SYS_IPC_SHM_CHKPT, proc_shm_chkpt);
	if (r != 0)
		goto unreg_sem_restart;

	r = register_proc_service(HCC_SYS_IPC_SHM_RESTART, proc_shm_restart);
	if (r != 0)
		goto unreg_shm_chkpt;

	return 0;

unreg_shm_chkpt:
	unregister_proc_service(HCC_SYS_IPC_SHM_CHKPT);
unreg_sem_restart:
	unregister_proc_service(HCC_SYS_IPC_SEM_RESTART);
unreg_sem_chkpt:
	unregister_proc_service(HCC_SYS_IPC_SEM_CHKPT);
unreg_msgq_restart:
	unregister_proc_service(HCC_SYS_IPC_MSGQ_RESTART);
unreg_msgq_chkpt:
	unregister_proc_service(HCC_SYS_IPC_MSGQ_CHKPT);
err:
	return err;
}

void ipc_procfs_exit(void)
{
	unregister_proc_service(HCC_SYS_IPC_MSGQ_CHKPT);
	unregister_proc_service(HCC_SYS_IPC_MSGQ_RESTART);
	unregister_proc_service(HCC_SYS_IPC_SEM_CHKPT);
	unregister_proc_service(HCC_SYS_IPC_SEM_RESTART);
	unregister_proc_service(HCC_SYS_IPC_SHM_CHKPT);
	unregister_proc_service(HCC_SYS_IPC_SHM_RESTART);
}

void ipc_handler_init(void)
{
	ipc_procfs_start();
}

void ipc_handler_finalize(void)
{
	ipc_procfs_exit();
}

#endif
