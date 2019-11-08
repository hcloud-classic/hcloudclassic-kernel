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

#endif