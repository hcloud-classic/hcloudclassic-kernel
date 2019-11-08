#ifndef NO_MSG
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/syscalls.h>
#include "util.h"
#include "msg_handler.h"



struct msghccops {
	struct hccipc_ops hccops;
	struct master_set *master_set;
};


struct master_set *hccipc_ops_master_set(struct hccipc_ops *ipcops)
{
	struct msghccops *msgops;

	msgops = container_of(ipcops, struct msghccops, hccops);

	return msgops->master_set;
}
static struct kern_ipc_perm *kcb_ipc_msg_lock(struct ipc_ids *ids, int id)
{
	msq_object_t *msq_object;
	struct msg_queue *msq;
	int index;

	rcu_read_lock();

	index = ipcid_to_idx(id);

	msq_object = _grab_object_no_ft(ids->hccops->data_set, index);

	if (!msq_object)
		goto error;

	msq = msq_object->local_msq;

	BUG_ON(!msq);

	mutex_lock(&msq->q_perm.mutex);

	if (msq->q_perm.deleted) {
		mutex_unlock(&msq->q_perm.mutex);
		goto error;
	}

	return &(msq->q_perm);

error:
	_put_object(ids->hccops->data_set, index);
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}

static void kcb_ipc_msg_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	_put_object(ipcp->hccops->data_set, index);

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}

static struct kern_ipc_perm *kcb_ipc_msg_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;
	int id = -1;

	key_index = _get_object_no_ft(ids->ops->key_set, key);

	if (key_index)
		id = *key_index;

	_put_object(ids->ops->key_set, key);

	if (id != -1)
		return kcb_ipc_msg_lock(ids, id);

	return NULL;
}

int hcc_ipc_msg_newque(struct ipc_namespace *ns, struct msg_queue *msq)
{
	struct_set *master_set;
	msq_object_t *msq_object;
	hcc_node_t *master_node;
	long *key_index;
	int index, err = 0;

	BUG_ON(!msg_ids(ns).hccops);

	index = ipcid_to_idx(msq->q_perm.id);

	msq_object = _grab_object_manual_ft(
		msg_ids(ns).hccops->data_set, index);

	BUG_ON(msq_object);

	msq_object = kmem_cache_alloc(msq_object_cachep, GFP_KERNEL);
	if (!msq_object) {
		err = -ENOMEM;
		goto err_put;
	}

	msq_object->local_msq = msq;
	msq_object->local_msq->is_master = 1;
	msq_object->mobile_msq.q_perm.id = -1;

	_set_object(msg_ids(ns).hccops->data_set, index, msq_object);

	if (msq->q_perm.key != IPC_PRIVATE)
	{
		key_index = _grab_object(msg_ids(ns).hccops->key_set,
					      msq->q_perm.key);
		*key_index = index;
		_put_object(msg_ids(ns).hccops->key_set,
				 msq->q_perm.key);
	}

	master_set = hccipc_ops_master_set(msg_ids(ns).hccops);

	master_node = _grab_object(master_set, index);
	*master_node = hcc_node_id;

	msq->q_perm.hccops = msg_ids(ns).hccops;

	_put_object(master_set, index);

err_put:
	_put_object(msg_ids(ns).hccops->data_set, index);

	return err;
}



void hcc_ipc_msg_freeque(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp)
{
	int index;
	key_t key;
	struct master_set *master_set;
	struct msg_queue *msq = container_of(ipcp, struct msg_queue, q_perm);

	index = ipcid_to_idx(msq->q_perm.id);
	key = msq->q_perm.key;

	if (key != IPC_PRIVATE) {
		_grab_object_no_ft(ipcp->hccops->key_set, key);
		_remove_frozen_object(ipcp->hccops->key_set, key);
	}

	master_set = hccipc_ops_master_set(ipcp->hccops);

	_grab_object_no_ft(master_set, index);
	_remove_frozen_object(master_set, index);

	local_msg_unlock(msq);

	_remove_frozen_object(ipcp->hccops->data_set, index);

	hcc_ipc_rmid(&msg_ids(ns), index);
}

#endif