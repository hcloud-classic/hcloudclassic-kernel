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
