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

int undolist_first_touch (struct kddm_obj * obj_entry,
			  struct kddm_set * set,
			  objid_t objid,
			  int flags)
{
	BUG();
	return -EINVAL;
}
