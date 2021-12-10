/** GDM set interface.
 *  @file gdm_set.c
 *
 *  Implementation of GDM set manipulation functions.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <linux/hcc_hashtable.h>
#include <linux/unique_id.h>

#include "process.h"
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>

#include <gdm/gdm.h>
#include <gdm/gdm_set.h>
#include <gdm/name_space.h>
#include <gdm/gdm_tree.h>
#include "protocol_action.h"
#include "procfs.h"

struct kmem_cache *gdm_set_cachep;
extern struct kmem_cache *gdm_tree_cachep;
extern struct kmem_cache *gdm_tree_lvl_cachep;

static struct lock_class_key obj_lock_key[NR_OBJ_ENTRY_LOCKS];


/** Alloc a new GDM set id.
 *  @author Innogrid HCC
 *
 *  @param ns     Name space to create the set id in.
 *
 *  @return   A newly allocated GDM set id.
 */
static inline gdm_set_id_t alloc_new_gdm_set_id (struct gdm_ns *ns)
{
	return get_unique_id (&ns->gdm_set_unique_id_root);
}



/** Alloc a new GDM set structure.
 *  @author Innogrid HCC
 *
 *  @param ns     Name space to create the set in.
 *
 *  @return   A newly allocated GDM set structure.
 */
static inline struct gdm_set *alloc_gdm_set_struct (struct gdm_ns *ns,
						      gdm_set_id_t set_id,
						      int init_state)
{
	struct gdm_set *gdm_set;

	gdm_set = kmem_cache_alloc (gdm_set_cachep, GFP_ATOMIC);
	if (gdm_set == NULL) {
		gdm_set = ERR_PTR(-ENOMEM);
		goto err;
	}

	/* Make minimal initialisation */

	memset (gdm_set, 0, sizeof(struct gdm_set));
	gdm_set->state = init_state;
	gdm_set->id = set_id;
	gdm_set->ns = ns;
	gdm_set->flags = 0;
	init_waitqueue_head (&gdm_set->create_wq);
	init_waitqueue_head (&gdm_set->frozen_wq);
	spin_lock_init(&gdm_set->lock);
	atomic_set(&gdm_set->count, 1);
	INIT_LIST_HEAD(&gdm_set->event_list);
	spin_lock_init(&gdm_set->event_lock);

err:
	return gdm_set;
}



/** Make full gdm set initialization
 *  @author Innogrid HCC
 */
int init_gdm_set (struct gdm_set *set,
		   gdm_set_id_t set_id,
		   struct gdm_set_ops *set_ops,
		   void *tree_init_data,
		   unsigned long flags,
		   hcc_node_t def_owner,
		   int obj_size)
{
	int i, err = -ENOMEM;

	set->ops = set_ops;

	spin_lock_init(&set->table_lock);

	for (i = 0; i < NR_OBJ_ENTRY_LOCKS; i++) {
		spin_lock_init(&set->obj_lock[i]);
		lockdep_set_class(&set->obj_lock[i], &obj_lock_key[i]);
	}

	set->id = set_id;
	set->obj_size = obj_size;
	set->flags |= flags;
	set->def_owner = def_owner;
	set->ra_window_size = DEFAULT_READAHEAD_WINDOW_SIZE;
	set->state = GDM_SET_LOCKED;
	atomic_set (&set->nr_objects, 0);
	atomic_set (&set->nr_masters, 0);
	atomic_set (&set->nr_copies, 0);
	atomic_set (&set->nr_entries, 0);
	set->get_object_counter = 0;
	set->grab_object_counter = 0;
	set->remove_object_counter = 0;
	set->flush_object_counter = 0;
	set->private = NULL;

	set->obj_set = set->ops->obj_set_alloc(set, tree_init_data);
	if (!set->obj_set)
		goto exit;

	/* create /proc/hcc/gdm_set entry. */
	set->procfs_entry = create_gdm_proc(set->id);

	err = 0;
exit:
	return err;
}


static int __free_gdm_obj_entry(unsigned long index,
				 void *data,
				 void *priv_data)
{
	put_obj_entry_count((struct gdm_set *)priv_data,
			      (struct gdm_obj *)data, index);

	return 0;
}

/** Free a gdm set structure. */

void free_gdm_set_struct(struct gdm_set * gdm_set)
{
	{   /// JUST FOR DEBUGGING: BEGIN
		struct gdm_set *_gdm_set;
		_gdm_set = _local_get_gdm_set(gdm_set->ns,
						gdm_set->id);
		BUG_ON (_gdm_set != NULL);
	}   /// JUST FOR DEBUGGING: END

	/*** Free object struct and objects content ***/

	gdm_set->ops->obj_set_free(gdm_set->obj_set, __free_gdm_obj_entry,
				    gdm_set);

	/*** Get rid of the IO linker ***/

	gdm_io_uninstantiate(gdm_set, 0);

	if (gdm_set->procfs_entry)
		remove_gdm_proc(gdm_set->procfs_entry);

	/*** Finally, we are done... The gdm set is free ***/

	kmem_cache_free(gdm_set_cachep, gdm_set);
}



void put_gdm_set(struct gdm_set *set)
{
	if (atomic_dec_and_test(&set->count))
		free_gdm_set_struct(set);
}
EXPORT_SYMBOL(put_gdm_set);


/** Find a GDM set structure from its id.
 *  @author Innogrid HCC
 *
 *  @param ns            Name space to search the set in.
 *  @param set_id        Identifier of the requested gdm set.
 *  @param init_state    Initial state of the set.
 *  @param flags         Identify extra actions to cary out on the look-up.
 *
 *  @return  Structure of the requested GDM set.
 *           NULL if the set does not exist.
 */
struct gdm_set *_generic_local_get_gdm_set(struct gdm_ns *ns,
					     gdm_set_id_t set_id,
					     int init_state,
					     int flags)
{
	struct gdm_set *gdm_set;

	if (!(flags & GDM_LOCK_FREE))
		down (&ns->table_sem);
	gdm_set = __hashtable_find (ns->gdm_set_table, set_id);

	if ( (gdm_set != NULL) && (flags & GDM_CHECK_UNIQUE)) {
		gdm_set = ERR_PTR(-EEXIST);
		goto found;
	}

	if ( (gdm_set == NULL) && (flags & GDM_ALLOC_STRUCT)) {
		gdm_set = alloc_gdm_set_struct(ns, set_id, init_state);
		__hashtable_add (ns->gdm_set_table, set_id, gdm_set);
	}

	if (likely(gdm_set != NULL))
		atomic_inc(&gdm_set->count);

found:
	if (!(flags & GDM_LOCK_FREE))
		up (&ns->table_sem);

	return gdm_set;
}



/** Find a GDM set structure from its id.
 *  @author Innogrid HCC
 *
 *  @param ns_id         Name space id to search the set in.
 *  @param set_id        Identifier of the requested gdm set.
 *  @param flags         Identify extra actions to cary out on the look-up.
 *
 *  @return  Structure of the requested GDM set.
 *           NULL if the set does not exist.
 */
struct gdm_set *generic_local_get_gdm_set(int ns_id,
					    gdm_set_id_t set_id,
					    int init_state,
					    int flags)
{
	struct gdm_ns *ns;
	struct gdm_set *gdm_set;

	ns = gdm_ns_get (ns_id);
	if (ns == NULL)
		return ERR_PTR(-EINVAL);
	gdm_set = _generic_local_get_gdm_set(ns , set_id, init_state, flags);
	gdm_ns_put (ns);

	return gdm_set;
}



/** Try to find the given set on a remote node and create a local instance
 *  @author Innogrid HCC
 *
 *  @param gdm_set   Struct of the gdm set to lookup.
 *
 *  @return  Structure of the requested gdm set or NULL if not found.
 */
int find_gdm_set_remotely(struct gdm_set *gdm_set)
{
	hcc_node_t gdm_set_mgr_node_id ;
	gdm_id_msg_t gdm_id;
	msg_gdm_set_t *msg;
	int msg_size;
	int err = -ENOMEM;
	struct grpc_desc* desc;
	struct gdm_set_ops *set_ops = NULL;
	void *tree_init_data = NULL;
	int free_init_data = 1;

	gdm_set_mgr_node_id = GDM_SET_MGR(gdm_set);

	gdm_id.set_id = gdm_set->id;
	gdm_id.ns_id = gdm_set->ns->id;

	desc = grpc_begin(REQ_GDM_SET_LOOKUP, gdm_set_mgr_node_id);
	grpc_pack_type(desc, gdm_id);

	msg_size = sizeof(msg_gdm_set_t) + MAX_PRIVATE_DATA_SIZE;

	msg = kmalloc(msg_size, GFP_KERNEL);
	if (msg == NULL)
		OOM;

	grpc_unpack(desc, 0, msg, msg_size);

	if (msg->gdm_set_id != GDM_SET_UNUSED) {
		set_ops = hcc_syms_import (msg->set_ops);
	tree_init_data = set_ops->import(desc, &free_init_data);
	}

	grpc_end(desc, 0);

	if (msg->gdm_set_id == GDM_SET_UNUSED) {
		err = -ENOENT;
		goto check_err;
	}

	BUG_ON(msg->gdm_set_id != gdm_set->id);

	err = init_gdm_set(gdm_set, gdm_set->id, set_ops, tree_init_data,
			    msg->flags, msg->link, msg->obj_size);

	if (tree_init_data && free_init_data)
		kfree(tree_init_data);

	if (err != 0)
		goto check_err;

	err = gdm_io_instantiate(gdm_set, msg->link, msg->linker_id,
				  msg->private_data, msg->data_size, 0);

check_err:
	kfree(msg);

	spin_lock(&gdm_set->lock);

	if (err == 0)
		gdm_set->state = GDM_SET_READY;
	else
		gdm_set->state = GDM_SET_INVALID;

	wake_up(&gdm_set->create_wq);

	spin_unlock(&gdm_set->lock);

	return err;
}



/** Return a pointer to the given gdm_set. */

struct gdm_set *__find_get_gdm_set(struct gdm_ns *ns,
				     gdm_set_id_t set_id,
				     int flags)
{
	struct gdm_set *gdm_set;

	flags |= GDM_ALLOC_STRUCT;
	gdm_set = _generic_local_get_gdm_set(ns, set_id,
					       GDM_SET_NEED_LOOKUP, flags);
	if (unlikely(IS_ERR(gdm_set)))
		return gdm_set;

	/* If the gdm set has been found INVALID earlier, we have to check if
	 * it is still invalid... So, we force a new remote gdm set lookup.
	 */
	spin_lock(&gdm_set->lock);

	if (gdm_set->state == GDM_SET_INVALID)
		gdm_set->state = GDM_SET_NEED_LOOKUP;

	goto check_no_lock;

recheck_state:
	spin_lock(&gdm_set->lock);

check_no_lock:
	/* If GDM frozen, sleep until it is no more frozen */
	if (!(flags & GDM_LOCK_FREE) && gdm_frozen(gdm_set)) {
		spin_unlock(&gdm_set->lock);
		wait_event (gdm_set->frozen_wq, (!gdm_frozen(gdm_set)));
		goto recheck_state;
	}
	/* Make sure we only use bypass_frozen when GDM are frozen (i.e.
	   ghotplug cases) */
	BUG_ON ((flags & GDM_LOCK_FREE) && !gdm_frozen(gdm_set));

	switch (gdm_set->state) {
	  case GDM_SET_READY:
		  spin_unlock(&gdm_set->lock);
		  break;

	  case GDM_SET_NEED_LOOKUP:
		  /* The gdm set structure has just been allocated or
		   * a remote lookup has been forced.
		   */
		  gdm_set->state = GDM_SET_LOCKED;
		  spin_unlock(&gdm_set->lock);
		  find_gdm_set_remotely(gdm_set);
		  goto recheck_state;

	  case GDM_SET_UNINITIALIZED:
	  case GDM_SET_INVALID:
		  spin_unlock(&gdm_set->lock);
		  gdm_set = NULL;
		  break;

	  case GDM_SET_LOCKED:
		  sleep_on_and_spin_unlock(&gdm_set->create_wq,
					   &gdm_set->lock);
		  goto recheck_state;

	  default:
		  BUG();
	}

	return gdm_set;
}
EXPORT_SYMBOL(_find_get_gdm_set);


struct gdm_set *find_get_gdm_set(int ns_id,
				   gdm_set_id_t set_id)
{
	struct gdm_ns *ns;
	struct gdm_set *gdm_set;

	ns = gdm_ns_get (ns_id);

	gdm_set = _find_get_gdm_set(ns, set_id);

	gdm_ns_put(ns);

	return gdm_set;
}
EXPORT_SYMBOL(find_get_gdm_set);



/** High level function to create a new gdm set.
 *  @author Innogrid HCC
 *
 *  @param ns             Name space to create a new set in.
 *  @param set_id         Id of the gdm set to create. 0 -> auto attribution.
 *  @param order          Order of the number of objects storable in the set.
 *  @param linker_id      Id of the IO linker to link the gdm set with.
 *  @param def_owner      Default owner node.
 *  @param obj_size       Size of objects stored in the gdm set.
 *  @param private_data   Data used by the instantiator.
 *  @param data_size      Size of private data.
 *  @param flags          Kddm set flags.
 *
 *  @return      A newly created gdm set if everything is ok.
 *               Negative value otherwise
 */
struct gdm_set *__create_new_gdm_set(struct gdm_ns *ns,
				       gdm_set_id_t set_id,
				       struct gdm_set_ops *set_ops,
				       void *tree_init_data,
				       iolinker_id_t linker_id,
				       hcc_node_t def_owner,
				       int obj_size,
				       void *private_data,
				       unsigned long data_size,
				       unsigned long flags)
{
	struct gdm_set *gdm_set;
	int err = -EINVAL;

	if (data_size > MAX_PRIVATE_DATA_SIZE)
		goto error;

	if (set_id == 0)
		set_id = alloc_new_gdm_set_id(ns);

	gdm_set = _local_get_alloc_unique_gdm_set(ns, set_id,
						    GDM_SET_UNINITIALIZED);
	if (IS_ERR(gdm_set))
		goto error;

	err = init_gdm_set(gdm_set, set_id, set_ops, tree_init_data,
			    flags, def_owner, obj_size);
	if (err)
		goto error;

	err = gdm_io_instantiate(gdm_set, def_owner, linker_id,
				  private_data, data_size, 1);
	if (err)
		goto error;

	spin_lock(&gdm_set->lock);

	gdm_set->state = GDM_SET_READY;
	wake_up(&gdm_set->create_wq);

	spin_unlock(&gdm_set->lock);

	put_gdm_set(gdm_set);

	goto exit;

error:
	gdm_set = ERR_PTR(err);
exit:
	return gdm_set;
}
EXPORT_SYMBOL(__create_new_gdm_set);


static void do_freeze_gdm_set(void *_set, void *_data)
{
	struct gdm_set *set = _set;

	spin_lock(&set->lock);

	BUG_ON (gdm_frozen(set));
	set_gdm_frozen(set);
	freeze_gdm_event(set);

	spin_unlock(&set->lock);
}

static void do_unfreeze_gdm_set(void *_set, void *_data)
{
	struct gdm_set *set = _set;

	spin_lock(&set->lock);

	BUG_ON (!gdm_frozen(set));

	unfreeze_gdm_event(set);
	clear_gdm_frozen(set);

	wake_up(&set->frozen_wq);

	spin_unlock(&set->lock);
}

void freeze_gdm(void)
{
	down (&gdm_def_ns->table_sem);
	__hashtable_foreach_data(gdm_def_ns->gdm_set_table,
				 do_freeze_gdm_set, NULL);
}

void unfreeze_gdm(void)
{
	__hashtable_foreach_data(gdm_def_ns->gdm_set_table,
				 do_unfreeze_gdm_set, NULL);
	up (&gdm_def_ns->table_sem);
}


/*****************************************************************************/
/*                                                                           */
/*                              REQUEST HANDLERS                             */
/*                                                                           */
/*****************************************************************************/

/** gdm set lookup handler.
 *  @author Innogrid HCC
 *
 *  @param sender    Identifier of the remote requesting machine.
 *  @param msg       Identifier of the gdm set to lookup for.
 */
int handle_req_gdm_set_lookup(struct grpc_desc* desc,
			       void *_msg, size_t size)
{
	gdm_id_msg_t gdm_id = *((gdm_id_msg_t *) _msg);
	struct gdm_set *gdm_set;
	msg_gdm_set_t *msg;
	int msg_size = sizeof(msg_gdm_set_t);

	BUG_ON(!hcc_node_online(grpc_desc_get_client(desc)));

	gdm_set = local_get_gdm_set(gdm_id.ns_id, gdm_id.set_id);

	if (gdm_set)
		msg_size += gdm_set->private_data_size;

	/* Prepare the gdm set creation message */

	msg = kmalloc(msg_size, GFP_KERNEL);
	if (msg == NULL)
		OOM;

	if (gdm_set == NULL || gdm_set->state != GDM_SET_READY) {
		msg->gdm_set_id = GDM_SET_UNUSED;
		goto done;
	}

	msg->gdm_set_id = gdm_id.set_id;
	msg->linker_id = gdm_set->iolinker->linker_id;
	msg->flags = gdm_set->flags;
	msg->link = gdm_set->def_owner;
	msg->obj_size = gdm_set->obj_size;
	msg->data_size = gdm_set->private_data_size;
	msg->set_ops = hcc_syms_export (gdm_set->ops);
	memcpy(msg->private_data, gdm_set->private_data, gdm_set->private_data_size);

done:
	grpc_pack(desc, 0, msg, msg_size);
	if (msg->gdm_set_id != GDM_SET_UNUSED)
		gdm_set->ops->export(desc, gdm_set);

	kfree(msg);

	if (gdm_set)
		put_gdm_set(gdm_set);

	return 0;
}



/** gdm set destroy handler.
 *  @author Innogrid HCC
 *
 *  @param sender    Identifier of the remote requesting machine.
 *  @param msg       Identifier of the gdm set to destroy.
 */
static inline
int __handle_req_gdm_set_destroy(hcc_node_t sender,
				void *msg)
{
	gdm_id_msg_t gdm_id = *((gdm_id_msg_t *) msg);
	struct gdm_ns *ns;
	struct gdm_set *gdm_set;

	BUG_ON(!hcc_node_online(sender));

	/* Remove the gdm set from the name space */

	ns = gdm_ns_get (gdm_id.ns_id);
	if (ns == NULL)
		return -EINVAL;

	down (&ns->table_sem);
	gdm_set = __hashtable_remove(ns->gdm_set_table, gdm_id.set_id);
	up (&ns->table_sem);

	gdm_ns_put (ns);

	if (gdm_set == NULL)
		return -EINVAL;

	/* Free the gdm set structure */

	put_gdm_set(gdm_set);

	return 0;
}

int handle_req_gdm_set_destroy(struct grpc_desc* desc,
				void *msg, size_t size){
	return __handle_req_gdm_set_destroy(grpc_desc_get_client(desc), msg);
}

/*****************************************************************************/
/*                                                                           */
/*                INTERFACE FUNCTIONS FOR DISTRIBUTED ACTIONS                */
/*                                                                           */
/*****************************************************************************/


/* High level function to destroy a gdm set. */

int _destroy_gdm_set(struct gdm_set * gdm_set)
{
	gdm_id_msg_t gdm_id;

	gdm_id.set_id = gdm_set->id;
	gdm_id.ns_id = gdm_set->ns->id;

	grpc_async_m(REQ_GDM_SET_DESTROY, &hcc_node_online_map,
		    &gdm_id, sizeof(gdm_id_msg_t));
	return 0;
}
EXPORT_SYMBOL(_destroy_gdm_set);

int destroy_gdm_set(struct gdm_ns *ns, gdm_set_id_t set_id)
{
	struct gdm_set * gdm_set;
	int r;

	gdm_set = _find_get_gdm_set(ns, set_id);
	if (gdm_set == NULL)
		return -EINVAL;
	r = _destroy_gdm_set(gdm_set);

	put_gdm_set(gdm_set);
	return r;
}
EXPORT_SYMBOL(destroy_gdm_set);

/*****************************************************************************/
/*                                                                           */
/*                               INIT / FINALIZE                             */
/*                                                                           */
/*****************************************************************************/



void __gdm_set_destroy(void *_gdm_set,
			void *dummy)
{
	struct gdm_set *gdm_set = _gdm_set;
	gdm_id_msg_t gdm_id;

	gdm_id.ns_id = gdm_set->ns->id;
	gdm_id.set_id = gdm_set->id;

	handle_req_gdm_set_destroy(0, &gdm_id, sizeof(gdm_id));
}



/* GDM set mecanisms initialisation.*/

void gdm_set_init()
{
	struct grpc_synchro* gdm_server;

	printk ("GDM set init\n");

	gdm_server = grpc_synchro_new(1, "gdm server", 0);

	gdm_set_cachep = KMEM_CACHE(gdm_set, SLAB_PANIC);

	gdm_tree_cachep = KMEM_CACHE(gdm_tree, SLAB_PANIC);

	gdm_tree_lvl_cachep = KMEM_CACHE(gdm_tree_lvl, SLAB_PANIC);

	__grpc_register(REQ_GDM_SET_LOOKUP,
		       GRPC_TARGET_NODE, GRPC_HANDLER_KTHREAD_VOID,
		       gdm_server, handle_req_gdm_set_lookup, 0);

	__grpc_register(REQ_GDM_SET_DESTROY,
		       GRPC_TARGET_NODE, GRPC_HANDLER_KTHREAD_VOID,
		       gdm_server, handle_req_gdm_set_destroy, 0);

	printk ("GDM set init : done\n");
}



void gdm_set_finalize()
{
}
