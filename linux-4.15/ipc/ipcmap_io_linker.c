#define MODULE_NAME "IPC map linker  "
#include "ipcmap_io_linker.h"

struct kmem_cache *ipcmap_object_cachep;

/*****************************************************************************/
/*                                                                           */
/*                           SHMID master IO FUNCTIONS                         */
/*                                                                           */
/*****************************************************************************/

int ipcmap_alloc_object (struct master_obj * obj_entry,
			 struct master_set * set,
			 objid_t objid)
{
	obj_entry->object = kmem_cache_alloc(ipcmap_object_cachep, GFP_KERNEL);
	if (obj_entry->object == NULL)
		return -ENOMEM;
	return 0;
}

int ipcmap_remove_object (void *object,
			  struct master_set * set,
			  objid_t objid)
{
	kmem_cache_free (ipcmap_object_cachep, object);
	return 0;
}
