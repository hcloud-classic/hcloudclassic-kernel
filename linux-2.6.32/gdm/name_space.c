/** GDM name space interface.
 *  @file name_space.c
 *
 *  Implementation of GDM name space manipulation functions.
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/hcc_hashtable.h>
#include <linux/module.h>

#include <gdm/gdm.h>
#include <gdm/name_space.h>

struct gdm_ns *gdm_def_ns;
EXPORT_SYMBOL(gdm_def_ns);

struct radix_tree_root gdm_ns_tree;
static DEFINE_RWLOCK(ns_tree_lock);
struct kmem_cache *gdm_ns_cachep;



static inline void free_gdm_ns_entry(struct gdm_ns *ns)
{
	{   /// JUST FOR DEBUGGING: BEGIN
		struct gdm_ns *_ns;

		read_lock_irq(&ns_tree_lock);
		_ns = radix_tree_lookup(&gdm_ns_tree, ns->id);
		read_unlock_irq(&ns_tree_lock);

		BUG_ON (_ns != NULL);
	}   /// JUST FOR DEBUGGING: END

	hashtable_free(ns->gdm_set_table);
	kmem_cache_free(gdm_ns_cachep, ns);
}



void gdm_ns_put(struct gdm_ns *ns)
{
	if (atomic_dec_and_test(&ns->count))
		free_gdm_ns_entry(ns);
}



struct gdm_ns * create_gdm_ns(int ns_id,
				void *private,
				struct gdm_ns_ops *ops)

{
	struct gdm_ns *ns;
	int error;

	ns = kmem_cache_alloc (gdm_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		return NULL;

	ns->private = private;
	ns->ops = ops;
	ns->id = ns_id;
	init_MUTEX(&ns->table_sem);
	ns->gdm_set_table = hashtable_new(GDM_SET_HASH_TABLE_SIZE);
	init_and_set_unique_id_root(&ns->gdm_set_unique_id_root, MIN_GDM_ID);
	atomic_set(&ns->count, 1);

	error = radix_tree_preload(GFP_KERNEL);
	if (likely(error == 0)) {
		write_lock_irq(&ns_tree_lock);
		error = radix_tree_insert(&gdm_ns_tree, ns_id, ns);
		if (unlikely(error))
			free_gdm_ns_entry(ns);

		write_unlock_irq(&ns_tree_lock);
		radix_tree_preload_end();
	}

	if (error)
		ns = ERR_PTR(error);

	return ns;
}



int remove_gdm_ns(int ns_id)
{
	struct gdm_ns *ns;

	write_lock_irq(&ns_tree_lock);
	ns = radix_tree_delete(&gdm_ns_tree, ns_id);
	write_unlock_irq(&ns_tree_lock);

	if (ns == NULL)
		return -EINVAL;

	gdm_ns_put (ns);

	return 0;
}



struct gdm_ns *gdm_ns_get(int ns_id)
{
	struct gdm_ns *ns;

	read_lock_irq(&ns_tree_lock);
	ns = radix_tree_lookup(&gdm_ns_tree, ns_id);
	if (ns)
		atomic_inc(&ns->count);
	read_unlock_irq(&ns_tree_lock);

	return ns;
}



/*****************************************************************************/
/*                                                                           */
/*                               INIT / FINALIZE                             */
/*                                                                           */
/*****************************************************************************/



void gdm_ns_init(void)
{
	gdm_ns_cachep = KMEM_CACHE(gdm_ns, SLAB_PANIC);

	INIT_RADIX_TREE(&gdm_ns_tree, GFP_ATOMIC);

	gdm_def_ns = create_gdm_ns (GDM_DEF_NS_ID, NULL, NULL);

	BUG_ON(IS_ERR(gdm_def_ns));
}



void gdm_ns_finalize(void)
{
}
