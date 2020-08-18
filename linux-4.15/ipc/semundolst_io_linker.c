#include <linux/sem.h>
#include <linux/lockdep.h>
#include <linux/security.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <net/hccrpc/rpc.h>
#include <gdm/gdm.h>

#include "semundolst_io_linker.h"


static inline void __undolist_remove(struct semundo_list_object *undo_list)
{
	struct semundo_id *id, *next;

	if (undo_list) {
		for (id = undo_list->list; id; id = next) {
			next = id->next;
			kfree(id);
		}
		undo_list->list = NULL;
	}
}

static inline struct semundo_list_object * __undolist_alloc(void)
{
	struct semundo_list_object *undo_list;

	undo_list = kzalloc(sizeof(struct semundo_list_object), GFP_KERNEL);
	if (!undo_list)
		return ERR_PTR(-ENOMEM);

	return undo_list;
}


int undolist_alloc_object (struct gdm_obj * obj_entry,
			   struct gdm_set * set,
			   objid_t objid)
{
	struct semundo_list_object *undo_list;

	undo_list = __undolist_alloc();
	if (IS_ERR(undo_list))
		return PTR_ERR(undo_list);

	obj_entry->object = undo_list;
	return 0;
}

int undolist_first_touch (struct gdm_obj * obj_entry,
			  struct gdm_set * set,
			  objid_t objid,
			  int flags)
{
	BUG();
	return -EINVAL;
}


int undolist_remove_object (void *object,
			    struct gdm_set * set,
			    objid_t objid)
{
	struct semundo_list_object *undo_list;
	undo_list = object;

	__undolist_remove(undo_list);
	kfree(undo_list);
	object = NULL;

	return 0;
}

int undolist_invalidate_object (struct gdm_obj * obj_entry,
				struct gdm_set * set,
				objid_t objid)
{
	struct semundo_list_object *undo_list;
	undo_list = obj_entry->object;

	__undolist_remove(undo_list);
	obj_entry->object = NULL;

	return 0;
}

int undolist_export_object (struct rpc_desc *desc,
			    struct gdm_set *set,
			    struct gdm_obj *obj_entry,
			    objid_t objid,
			    int flags)
{
	struct semundo_list_object *undo_list;
	struct semundo_id *un;
	int nb_semundo = 0, r;

	undo_list = obj_entry->object;

	r = rpc_pack_type(desc, *undo_list);
	if (r)
		goto error;

	/* counting number of semundo to send */
	for (un = undo_list->list; un;  un = un->next)
		nb_semundo++;

	r = rpc_pack_type(desc, nb_semundo);

	BUG_ON(nb_semundo != atomic_read(&undo_list->semcnt));

	/* really sending the semundo identifier */
	for (un = undo_list->list; un;  un = un->next) {
		r = rpc_pack_type(desc, *un);
		if (r)
			goto error;
	}
error:
	return r;
}

int undolist_import_object (struct rpc_desc *desc,
			    struct gdm_set *set,
			    struct gdm_obj *obj_entry,
			    objid_t objid,
			    int flags)
{
	struct semundo_list_object *undo_list;
	struct semundo_id *un, *prev = NULL;
	int nb_semundo = 0, i=0, r;

	undo_list = obj_entry->object;

	r = rpc_unpack_type(desc, *undo_list);
	if (r)
		goto error;

	r = rpc_unpack_type(desc, nb_semundo);
	if (r)
		goto error;

	BUG_ON(nb_semundo != atomic_read(&undo_list->semcnt));

	for (i=0; i < nb_semundo; i++) {
		un = kmalloc(sizeof(struct semundo_id), GFP_KERNEL);
		if (!un) {
			r = -ENOMEM;
			goto error;
		}

		r = rpc_unpack_type(desc, *un);
		if (r)
			goto error;

		un->next = NULL;
		if (prev)
			prev->next = un;
		else
			undo_list->list = un;
		prev = un;
	}
error:
	return r;
}