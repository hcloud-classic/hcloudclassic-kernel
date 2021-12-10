/*
 *  HCC/modules/ipc/msg_io_linker.c
 *
 *  GDM IPC msg_queue id Linker.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/shm.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include <linux/ipc.h>
#include <net/grpc/grpc.h>
#include <gdm/gdm.h>

#include "gipc_handler.h"
#include "msg_io_linker.h"
#include "util.h"
#include "hcc_msg.h"

struct kmem_cache *msq_object_cachep;

/** Create a local instance of a remotly existing IPC message queue.
 *
 *  @author Innogrid HCC
 */
static struct msg_queue *create_local_msq(struct ipc_namespace *ns,
					  struct msg_queue *received_msq)
{
	struct msg_queue *msq;
	int retval;

	msq = ipc_rcu_alloc(sizeof(*msq));
	if (!msq)
		return ERR_PTR(-ENOMEM);

	*msq = *received_msq;
	retval = security_msg_queue_alloc(msq);
	if (retval) {
		ipc_rcu_putref(msq, ipc_rcu_free);
		goto out;
	}

	/*
	 * ipc_reserveid() locks msq
	 */
	retval = local_ipc_reserveid(&msg_ids(ns), &msq->q_perm, ns->msg_ctlmni);
	if (retval) {
		ipc_rcu_putref(msq, msg_rcu_free);
		goto out;
	}

	msq->is_master = 0;
	INIT_LIST_HEAD(&msq->q_messages);
	INIT_LIST_HEAD(&msq->q_receivers);
	INIT_LIST_HEAD(&msq->q_senders);

	msq->q_perm.hcc_ops = msg_ids(ns).hcc_ops;
	local_msg_unlock(msq);

	return msq;

out:
	return ERR_PTR(retval);
}

/** Remove a local instance of a removed IPC message queue.
 *
 *  @author Innogrid HCC
 */
static void delete_local_msq(struct ipc_namespace *ns, struct msg_queue *local_msq)
{
	struct msg_queue *msq;

	msq = local_msq;

	ipc_rmid(&msg_ids(ns), &msq->q_perm);

	local_msg_unlock(msq);

	ipc_rcu_putref(msq, msg_rcu_free);
}

/** Update a local instance of a remotly existing IPC message queue.
 *
 *  @author Innogrid HCC
 */
static void update_local_msq (struct msg_queue *local_msq,
			      struct msg_queue *received_msq)
{
	/* local_msq->q_perm = received_msq->q_perm;*/
	local_msq->q_stime = received_msq->q_stime;
	local_msq->q_rtime = received_msq->q_rtime;
	local_msq->q_ctime = received_msq->q_ctime;
	local_msq->q_cbytes = received_msq->q_cbytes;
	local_msq->q_qnum = received_msq->q_qnum;
	local_msq->q_qbytes = received_msq->q_qbytes;
	local_msq->q_lspid = received_msq->q_lspid;
	local_msq->q_lrpid = received_msq->q_lrpid;

	/* Do not modify the list_head else you will loose
	   information on master node */
}

/*****************************************************************************/
/*                                                                           */
/*                         MSQID GDM IO FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/



int msq_alloc_object (struct gdm_obj * obj_entry,
		      struct gdm_set * set,
		      objid_t objid)
{
	msq_object_t *msq_object;

	msq_object = kmem_cache_alloc(msq_object_cachep, GFP_KERNEL);
	if (!msq_object)
		return -ENOMEM;

	msq_object->local_msq = NULL;
	obj_entry->object = msq_object;

	return 0;
}



/** Handle a gdm set msq_queue id first touch
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Kddm object descriptor.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int msq_first_touch (struct gdm_obj * obj_entry,
		     struct gdm_set * set,
		     objid_t objid,
		     int flags)
{
	BUG(); // I should never get here !

	return 0;
}



/** Insert a new msg_queue id in local structures.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to insert.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to insert.
 */
int msq_insert_object (struct gdm_obj * obj_entry,
		       struct gdm_set * set,
		       objid_t objid)
{
	msq_object_t *msq_object;
	struct msg_queue *msq;
	int r = 0;

	msq_object = obj_entry->object;
	BUG_ON(!msq_object);

	/* Regular case, the kernel msg_queue struct is already allocated */
	if (msq_object->local_msq) {
		if (msq_object->mobile_msq.q_perm.id != -1)
			update_local_msq(msq_object->local_msq,
					 &msq_object->mobile_msq);

	} else {
		struct ipc_namespace *ns;

		ns = find_get_hcc_gipcns();
		BUG_ON(!ns);

		/* This is the first time the object is inserted locally. We need
		 * to allocate kernel msq structures.
		 */
		msq = create_local_msq(ns, &msq_object->mobile_msq);
		msq_object->local_msq = msq;

		if (IS_ERR(msq)) {
			r = PTR_ERR(msq);
			BUG();
		}

		put_ipc_ns(ns);
	}

	return r;
}



/** Invalidate a gdm object msqid.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set       Kddm set descriptor
 *  @param  objid     Id of the object to invalidate
 */
int msq_invalidate_object (struct gdm_obj * obj_entry,
			   struct gdm_set * set,
			   objid_t objid)
{
	return GDM_IO_KEEP_OBJECT;
}



/** Handle a msg queue remove.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to remove.
 *  @param  set       Kddm set descriptor.
 *  @param  padeid    Id of the object to remove.
 */
int msq_remove_object(void *object, struct gdm_set *set, objid_t objid)
{
	msq_object_t *msq_object;
	struct msg_queue *msq;
	struct ipc_namespace *ns;

	ns = find_get_hcc_gipcns();
	BUG_ON(!ns);

	msq_object = object;
	if (msq_object) {
		msq = msq_object->local_msq;
		local_msg_lock(ns, msq->q_perm.id);
		if (msq->is_master)
			local_master_freeque(ns, &msq->q_perm);
		else
			delete_local_msq(ns, msq);

		kmem_cache_free (msq_object_cachep, msq_object);
	}

	put_ipc_ns(ns);

	return 0;
}



/** Export an object
 *  @author Innogrid HCC
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int msq_export_object (struct grpc_desc *desc,
		       struct gdm_set *set,
		       struct gdm_obj *obj_entry,
		       objid_t objid,
		       int flags)
{
	msq_object_t *msq_object;
	int r;

	msq_object = obj_entry->object;
	msq_object->mobile_msq = *msq_object->local_msq;

	r = grpc_pack(desc, 0, msq_object, sizeof(msq_object_t));

	return r;
}



/** Import an object
 *  @author Innogrid HCC
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int msq_import_object (struct grpc_desc *desc,
		       struct gdm_set *set,
		       struct gdm_obj *obj_entry,
		       objid_t objid,
		       int flags)
{
	msq_object_t *msq_object, buffer;
	struct msg_queue *msq;
	int r;

	msq_object = obj_entry->object;

	r = grpc_unpack(desc, 0, &buffer, sizeof(msq_object_t));
	if (r)
		goto error;

	msq_object->mobile_msq = buffer.mobile_msq;

	if (msq_object->local_msq) {
		msq = msq_object->local_msq;
	}

error:
	return r;
}



/****************************************************************************/

/* Init the msg queue id IO linker */

struct iolinker_struct msq_linker = {
	first_touch:       msq_first_touch,
	remove_object:     msq_remove_object,
	invalidate_object: msq_invalidate_object,
	insert_object:     msq_insert_object,
	linker_name:       "msg_queue",
	linker_id:         MSG_LINKER,
	alloc_object:      msq_alloc_object,
	export_object:     msq_export_object,
	import_object:     msq_import_object
};



/*****************************************************************************/
/*                                                                           */
/*                  MSG QUEUE KEY GDM IO FUNCTIONS                          */
/*                                                                           */
/*****************************************************************************/

/* Init the msg queue key IO linker */

struct iolinker_struct msqkey_linker = {
	linker_name:       "msqkey",
	linker_id:         MSGKEY_LINKER,
};

/*****************************************************************************/
/*                                                                           */
/*                  MSG MASTER GDM IO FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/

/* Init the msg master node IO linker */

struct iolinker_struct msqmaster_linker = {
	linker_name:       "msqmaster",
	linker_id:         MSGMASTER_LINKER,
};
