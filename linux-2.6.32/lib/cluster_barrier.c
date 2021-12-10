/** Cluster wide barrier
 *  @file cluster_barrier.c
 *
 *  Implementation of a cluster wide barrier.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/cluster_barrier.h>
#include <linux/hcc_hashtable.h>
#include <linux/unique_id.h>
#include <net/grpc/grpc.h>

#include <hcc/types.h>
#include <hcc/ghotplug.h>
#include <hcc/hcc_init.h>

#define TABLE_SIZE 128

static unique_id_root_t barrier_id_root;
static hashtable_t *barrier_table;

struct barrier_id {
	unique_id_t id;
	int toggle;
};



/*****************************************************************************/
/*                                                                           */
/*                             INTERFACE FUNCTIONS                           */
/*                                                                           */
/*****************************************************************************/


struct cluster_barrier *alloc_cluster_barrier(unique_id_t key)
{
	struct cluster_barrier *barrier;
	int r, i;

	if (!key)
		key = get_unique_id(&barrier_id_root);

	if (hashtable_find (barrier_table, key))
		return ERR_PTR(-EEXIST);

	barrier = kmalloc (sizeof(struct cluster_barrier), GFP_KERNEL);
	if (!barrier)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < 2; i++) {
		hcc_nodes_clear (barrier->core[i].nodes_in_barrier);
		hcc_nodes_clear (barrier->core[i].nodes_to_wait);
		init_waitqueue_head(&barrier->core[i].waiting_tsk);
		barrier->core[i].in_barrier = 0;
	}
	spin_lock_init(&barrier->lock);
	barrier->id.key = key;
	barrier->id.toggle = 0;

	r = hashtable_add (barrier_table, barrier->id.key, barrier);
	if (r) {
		kfree (barrier);
		return ERR_PTR(r);
	}

	return barrier;
}

void free_cluster_barrier(struct cluster_barrier *barrier)
{
	hashtable_remove (barrier_table, barrier->id.key);

	kfree(barrier);
}

int cluster_barrier(struct cluster_barrier *barrier,
		    hcc_nodemask_t *nodes,
		    hcc_node_t master)
{
	struct cluster_barrier_core *core_bar;
	struct cluster_barrier_id id;
	struct grpc_desc *desc;
	int err = 0;

	BUG_ON (!__hcc_node_isset(hcc_node_id, nodes));
	BUG_ON (!__hcc_node_isset(master, nodes));

	spin_lock(&barrier->lock);
	barrier->id.toggle = (barrier->id.toggle + 1) % 2;
	id = barrier->id;
	core_bar = &barrier->core[id.toggle];
	if (core_bar->in_barrier)
		err = -EBUSY;
	core_bar->in_barrier = 1;
	spin_unlock(&barrier->lock);
	if (err)
		return err;

	desc = grpc_begin(GRPC_ENTER_BARRIER, master);

	grpc_pack_type (desc, id);
	grpc_pack(desc, 0, nodes, sizeof(hcc_nodemask_t));

	grpc_end(desc, 0);

	/* Wait for the barrier to complete */

	wait_event (core_bar->waiting_tsk, (core_bar->in_barrier == 0));

	return 0;
}

/*****************************************************************************/
/*                                                                           */
/*                              REQUEST HANDLERS                             */
/*                                                                           */
/*****************************************************************************/


static int handle_enter_barrier(struct grpc_desc* desc,
				void *_msg, size_t size)
{
	struct cluster_barrier_id *id = ((struct cluster_barrier_id *) _msg);
	struct cluster_barrier_core *core_bar;
	struct cluster_barrier *barrier;
	hcc_nodemask_t nodes;

	grpc_unpack(desc, 0, &nodes, sizeof(hcc_nodemask_t));

	barrier = hashtable_find (barrier_table, id->key);
	BUG_ON(!barrier);

	core_bar = &barrier->core[id->toggle];

	if (hcc_nodes_empty(core_bar->nodes_to_wait)) {
		hcc_nodes_copy(core_bar->nodes_in_barrier, nodes);
		hcc_nodes_copy(core_bar->nodes_to_wait, nodes);
	}
	else
		BUG_ON(!hcc_nodes_equal(core_bar->nodes_in_barrier, nodes));

	hcc_node_clear(desc->client, core_bar->nodes_to_wait);

	if (hcc_nodes_empty(core_bar->nodes_to_wait)) {
                grpc_async_m(GRPC_EXIT_BARRIER, &core_bar->nodes_in_barrier,
			    id, sizeof (struct cluster_barrier_id));
	}

	return 0;
}


static int handle_exit_barrier(struct grpc_desc* desc,
			       void *_msg, size_t size)
{
	struct cluster_barrier_id *id = ((struct cluster_barrier_id *) _msg);
	struct cluster_barrier_core *core_bar;
	struct cluster_barrier *barrier;

	barrier = hashtable_find (barrier_table, id->key);
	BUG_ON(!barrier);

	core_bar = &barrier->core[id->toggle];
	core_bar->in_barrier = 0;

	wake_up (&core_bar->waiting_tsk);

	return 0;
}


/*****************************************************************************/
/*                                                                           */
/*                               INIT / FINALIZE                             */
/*                                                                           */
/*****************************************************************************/

static int barrier_notification(struct notifier_block *nb,
				ghotplug_event_t event,
				void *data)
{
	switch(event){
	case GHOTPLUG_NOTIFY_ADD:
		grpc_enable(GRPC_ENTER_BARRIER);
		grpc_enable(GRPC_EXIT_BARRIER);
		break;

	case GHOTPLUG_NOTIFY_REMOVE:
		/* TODO */
		break;

	case GHOTPLUG_NOTIFY_FAIL:
		/* TODO */
		break;

	default:
		BUG();
	}

	return NOTIFY_OK;
}

void init_cluster_barrier(void)
{
	init_and_set_unique_id_root(&barrier_id_root, CLUSTER_BARRIER_MAX);
	barrier_table = hashtable_new(TABLE_SIZE);

	grpc_register_int (GRPC_ENTER_BARRIER, handle_enter_barrier, 0);
	grpc_register_int (GRPC_EXIT_BARRIER, handle_exit_barrier, 0);

	register_ghotplug_notifier(barrier_notification, GHOTPLUG_PRIO_BARRIER);
}
