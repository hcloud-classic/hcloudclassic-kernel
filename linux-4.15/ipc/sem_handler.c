struct semhccops {
    /*Semaphore operation struct*/
	struct hccipc_ops hcc_ops;
	/* unique_id generator for sem_undo_list identifier */
	unique_id_root_t undo_list_unique_id_root;
};


static struct kern_ipc_perm *hcc_ipc_sem_lock(struct ipc_ids *ids, int id)
{
	semarray_object_t *sem_object;
	struct sem_array *sma;
	int index ;

	rcu_read_lock();

	index = ipcid_to_idx(id);

	if (!sem_object)
		goto error;

	sma = sem_object->local_sem;

	BUG_ON(!sma);

	mutex_lock(&sma->sem_perm.mutex);

	if (sma->sem_perm.deleted) {
		mutex_unlock(&sma->sem_perm.mutex);
		goto error;
	}

	return &(sma->sem_perm);

error:
	rcu_read_unlock();

	return ERR_PTR(-EINVAL);
}

static void hcc_ipc_sem_unlock(struct kern_ipc_perm *ipcp)
{
	int index, deleted = 0;

	index = ipcid_to_idx(ipcp->id);

	if (ipcp->deleted)
		deleted = 1;

	if (!deleted)
		mutex_unlock(&ipcp->mutex);

	rcu_read_unlock();
}


static struct kern_ipc_perm *kcb_ipc_sem_findkey(struct ipc_ids *ids, key_t key)
{
	long *key_index;

// Key intdex search
	// key_index = ;

	if (key_index)
		id = *key_index;

	if (id != -1)
		return hcc_ipc_sem_lock(ids, id);

	return NULL;
}