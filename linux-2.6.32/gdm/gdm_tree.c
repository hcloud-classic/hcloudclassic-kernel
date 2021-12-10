/** GDM tree management.
 *  @file gdm_tree.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/mm.h>

#include <net/grpc/grpc.h>
#include <gdm/gdm_tree.h>
#include <gdm/gdm_types.h>
#include <gdm/object.h>

struct kmem_cache *gdm_tree_cachep;
struct kmem_cache *gdm_tree_lvl_cachep;

int _2levels_gdm_tree = _2LEVELS_GDM_TREE;
int _nlevels_gdm_tree = _NLEVELS_GDM_TREE;
void *_2levels_gdm_tree_init_data = (void*)&_2levels_gdm_tree;
void *_nlevels_gdm_tree_init_data = (void*)&_nlevels_gdm_tree;



/*****************************************************************************/
/*                                                                           */
/*                              HELPER FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



static inline int lvl_bits(struct gdm_tree *tree, int level)
{
	if (level < tree->nr_level - 1 || !tree->bit_size_last)
		return tree->bit_size;
	return tree->bit_size_last;
}

static inline int lvl_shift(struct gdm_tree *tree, int level)
{
	return (tree->nr_level - 1 - level) * tree->bit_size;
}

static inline unsigned long
lvl_sub_index(struct gdm_tree *tree, int level, unsigned long index)
{
	int bits = lvl_bits(tree, level);

	return (index >> lvl_shift(tree, level)) & ((1UL << bits) - 1UL);
}



/*****************************************************************************/
/*                                                                           */
/*                               CORE TREE CODE                              */
/*                                                                           */
/*****************************************************************************/



/** Lookup for a data in a gdm tree.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to lookup.
 *
 *  @return The data if found.
 *          NULL if the data is not found.
 */
static void *gdm_tree_lookup (struct gdm_tree *tree,
			       unsigned long index)
{
	struct gdm_tree_lvl *cur_level;
	int sub_index, i;

	BUG_ON (tree == NULL);

	if (tree->lvl1 == NULL)
		return NULL;

	cur_level = tree->lvl1;

	for (i = 0; i < tree->nr_level; i++) {
		sub_index = lvl_sub_index(tree, i, index);
		cur_level = cur_level->sub_lvl[sub_index];
		if (cur_level == NULL)
			break;
	}

	return cur_level;
}



/** Lookup for a data in a gdm tree and allocated slots if needed.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to lookup.
 *
 *  @return The address of the slot hosting the data.
 *          If the data does not exist, an empty slot is allocated.
 */
static void **gdm_tree_lookup_slot (struct gdm_tree *tree,
				     unsigned long index,
				     int flags)
{
	struct gdm_tree_lvl *cur_level, *prev_level;
	int sub_index, nr_entries, i;
	void *data;

	BUG_ON (tree == NULL);

	prev_level = NULL;
	cur_level = tree->lvl1;
	sub_index = 0;

	for (i = 0; i < tree->nr_level; i++) {
		if (cur_level == NULL) {
			nr_entries = 1UL << lvl_bits(tree, i);

			cur_level = kmem_cache_alloc (gdm_tree_lvl_cachep,
						      GFP_ATOMIC);
			cur_level->sub_lvl = kmalloc(
				sizeof(struct gdm_tree_lvl *) * nr_entries,
				GFP_ATOMIC);
			cur_level->nr_obj = 0;

			memset(cur_level->sub_lvl, 0,
			       sizeof(struct gdm_tree_lvl *) * nr_entries);

			if (i == 0)
				tree->lvl1 = cur_level;
			else {
			        prev_level->sub_lvl[sub_index] = cur_level;
				prev_level->nr_obj++;
			}
		}
		sub_index = lvl_sub_index(tree, i, index);

		prev_level = cur_level;
		cur_level = cur_level->sub_lvl[sub_index];
	}

	data = prev_level->sub_lvl[sub_index];
	if ((flags & GDM_TREE_ADD_ENTRY) && (data == NULL))
		prev_level->nr_obj++;

	return (void **)&(prev_level->sub_lvl[sub_index]);
}



/** Lookup for a data in a gdm tree and allocated slots if needed.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to lookup.
 *
 *  @return The address of the slot hosting the data.
 *          If the data does not exist, an empty slot is allocated.
 */
static void *__gdm_tree_remove (struct gdm_tree *tree,
				 struct gdm_tree_lvl *cur_level,
				 int level,
				 unsigned long index,
				 int *_sub_level_freed)
{
	struct gdm_tree_lvl *sub_level;
	int sub_index, sub_level_freed = 0;
	void *data;

	sub_index = lvl_sub_index(tree, level, index);

	if ((level + 1) == tree->nr_level) {
		data = cur_level->sub_lvl[sub_index];
		goto free_sub_level_slot;
	}

	sub_level = cur_level->sub_lvl[sub_index];
	if (sub_level == NULL)
		return NULL;

	data = __gdm_tree_remove(tree, sub_level, level+1, index,
				  &sub_level_freed);
	if (sub_level_freed)
		goto free_sub_level_slot;
	return data;

free_sub_level_slot:
	cur_level->sub_lvl[sub_index] = NULL;
	cur_level->nr_obj--;
	if (cur_level->nr_obj == 0) {
		kfree (cur_level->sub_lvl);
		kmem_cache_free(gdm_tree_lvl_cachep, cur_level);
		*_sub_level_freed = 1;
	}
	return data;
}



/** Remove a data from a gdm tree.
 *  @param tree      The tree to lookup in.
 *  @param index     The index of the data to remove.
 */
static void *gdm_tree_remove(struct gdm_tree *tree,
			      unsigned long index)
{
	void *data;
	int sub_level_freed = 0;

	data = __gdm_tree_remove(tree, tree->lvl1, 0, index,
				  &sub_level_freed);

	if (sub_level_freed)
		tree->lvl1 = NULL;

	return data;
}



static void __gdm_tree_for_each_level(struct gdm_tree *tree,
				       struct gdm_tree_lvl *cur_level,
				       int level,
				       int index,
				       int free,
				       int(*f)(unsigned long, void*, void*),
				       void *priv)
{
	int i;
	struct gdm_tree_lvl *sub_level;
	unsigned long index_gap = 1UL << lvl_shift(tree, level);

	for (i = 0; i < (1UL << lvl_bits(tree, level)); i++) {
		sub_level = cur_level->sub_lvl[i];
		if (sub_level != NULL) {
			if ((level + 1) == tree->nr_level)
				f(index, sub_level, priv);
			else
				__gdm_tree_for_each_level(tree, sub_level,
							   level+1, index,
							   free, f, priv);
		}
		index += index_gap ;
	}
	if (free) {
		kfree (cur_level->sub_lvl);
		kmem_cache_free(gdm_tree_lvl_cachep, cur_level);
	}
}

static inline void __gdm_tree_for_each(struct gdm_tree *tree,
					int free,
					int(*f)(unsigned long, void*, void*),
					void *priv)
{
	if (tree->lvl1 == NULL)
		return;
	__gdm_tree_for_each_level(tree, tree->lvl1, 0, 0, free, f, priv);
}



/** Executes a function for each data in a tree.
 *  @param tree      The tree.
 *  @param f         The function to execute for each data.
 *  @param priv      Private data passed to the function.
 */
static void gdm_tree_for_each(struct gdm_tree *tree,
			       int(*f)(unsigned long, void*, void*),
			       void *priv)
{
	__gdm_tree_for_each(tree, 0, f, priv);
}



/** Alloc a GDM tree.
 *  @param tree_type   The tree type :)
 *
 *  @return   A newly allocated tree.
 */
static void *gdm_tree_alloc (struct gdm_set *set, void *data)
{
	struct gdm_tree *tree;
	int width, bit_size;
	int tree_type = *((int*)data);

	tree = kmem_cache_alloc (gdm_tree_cachep, GFP_KERNEL);
	if (tree == NULL)
		return NULL;

	tree->lvl1 = NULL;
	tree->tree_type = tree_type;

	switch (tree_type) {
	case _2LEVELS_GDM_TREE:
		width = 20;
		bit_size = 10;
		break;

	case _NLEVELS_GDM_TREE:
		width = BITS_PER_LONG;
		bit_size = 8;
		break;

	default:
		  printk ("Unknown GDM tree type %d\n", tree_type);
		  BUG();
	}
	tree->bit_width = width;
	tree->max_data = (-1UL) >> (BITS_PER_LONG - width);
	tree->bit_size = bit_size;
	tree->nr_level = width / bit_size;
	if (width % bit_size) {
		tree->bit_size_last = width % bit_size;
		tree->nr_level++;
	} else
		tree->bit_size_last = 0;

	return tree;
}



/** Delete a GDM tree.
 *  @param tree_type   The tree to delete.
 *  @param f           A function to call on each found data.
 *  @param priv        Private data passed to the function.
 */
static void gdm_tree_free (void *tree,
			    int (*f)(unsigned long, void *data, void *priv),
			    void *priv)
{
	__gdm_tree_for_each(tree, 1, f, priv);

	kmem_cache_free(gdm_tree_cachep, tree);
}



/*****************************************************************************/
/*                                                                           */
/*                             GDM SET OPERATIONS                           */
/*                                                                           */
/*****************************************************************************/



static struct gdm_obj *gdm_tree_lookup_obj_entry (struct gdm_set *set,
						    objid_t objid)
{
	struct gdm_obj *obj_entry;

	spin_lock (&set->table_lock);
	obj_entry = gdm_tree_lookup(set->obj_set, objid);
	spin_unlock (&set->table_lock);

	return obj_entry;
}



static struct gdm_obj *gdm_tree_get_obj_entry (struct gdm_set *set,
						 objid_t objid,
						 struct gdm_obj *new_obj)
{
	struct gdm_obj **obj_ptr, *obj_entry;

	spin_lock (&set->table_lock);

	obj_ptr = (struct gdm_obj **)gdm_tree_lookup_slot(set->obj_set,
					    objid, GDM_TREE_ADD_ENTRY);

	if (*obj_ptr == NULL)
		*obj_ptr = new_obj;

	obj_entry = *obj_ptr;
	spin_unlock (&set->table_lock);
	return obj_entry;
}



static void gdm_tree_remove_obj_entry (struct gdm_set *set,
					objid_t objid)
{
	spin_lock (&set->table_lock);
	gdm_tree_remove (set->obj_set, objid);
	spin_unlock (&set->table_lock);
}



static void gdm_tree_for_each_obj_entry(struct gdm_set *set,
					 int(*f)(unsigned long, void *, void*),
					 void *data)
{
	spin_lock (&set->table_lock);
	gdm_tree_for_each(set->obj_set, f, data);
	spin_unlock (&set->table_lock);
}



static void gdm_tree_export (struct grpc_desc* desc, struct gdm_set *set)
{
	struct gdm_tree *tree = set->obj_set;

	grpc_pack_type(desc, tree->tree_type);
}



static void *gdm_tree_import (struct grpc_desc* desc, int *free_data)
{
	int *tree_type;

	tree_type = kmalloc (sizeof (int), GFP_KERNEL);
	*free_data = 1;

	grpc_unpack(desc, 0, tree_type, sizeof (int));
	return tree_type;
}



struct gdm_set_ops gdm_tree_set_ops = {
	obj_set_alloc:       gdm_tree_alloc,
	obj_set_free:        gdm_tree_free,
	lookup_obj_entry:    gdm_tree_lookup_obj_entry,
	get_obj_entry:       gdm_tree_get_obj_entry,
	remove_obj_entry:    gdm_tree_remove_obj_entry,
	for_each_obj_entry:  gdm_tree_for_each_obj_entry,
	export:              gdm_tree_export,
	import:              gdm_tree_import,
};
