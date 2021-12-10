/** GDM IPC allocation bitmap Linker.
 *  @file gipcmap_io_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#define MODULE_NAME "IPC map linker  "
#include <gdm/gdm.h>
#include "gipcmap_io_linker.h"

struct kmem_cache *ipcmap_object_cachep;

/*****************************************************************************/
/*                                                                           */
/*                           SHMID GDM IO FUNCTIONS                         */
/*                                                                           */
/*****************************************************************************/

int ipcmap_alloc_object (struct gdm_obj * obj_entry,
			 struct gdm_set * set,
			 objid_t objid)
{
	obj_entry->object = kmem_cache_alloc(ipcmap_object_cachep, GFP_KERNEL);
	if (obj_entry->object == NULL)
		return -ENOMEM;
	return 0;
}

int ipcmap_remove_object (void *object,
			  struct gdm_set * set,
			  objid_t objid)
{
	kmem_cache_free (ipcmap_object_cachep, object);
	return 0;
}

/** First touch a gdm ipcmap object.
 *  @author Innogrid HCC
 *
 *  @param  obj_entr  Descriptor of the object to invalidate.
 *  @param  set       GDM descriptor
 *  @param  objid     Id of the object to invalidate
 */
int ipcmap_first_touch_object (struct gdm_obj * obj_entry,
			       struct gdm_set * set,
			       objid_t objid,
			       int flags)
{
	ipcmap_object_t *info;

	info = kmem_cache_alloc(ipcmap_object_cachep, GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->alloc_map = 0;

	obj_entry->object = info;
	return 0;
}

/** Invalidate a GDM ipcmap object.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the object to invalidate.
 *  @param  set        GDM descriptor
 *  @param  objid      Id of the object to invalidate
 */
int ipcmap_invalidate_object (struct gdm_obj * obj_entry,
			      struct gdm_set * set,
			      objid_t objid)
{
	kmem_cache_free (ipcmap_object_cachep, obj_entry->object);
	return 0;
}

/****************************************************************************/

/* Init the shm info IO linker */

struct iolinker_struct ipcmap_linker = {
	first_touch:       ipcmap_first_touch_object,
	alloc_object:      ipcmap_alloc_object,
	remove_object:     ipcmap_remove_object,
	invalidate_object: ipcmap_invalidate_object,
	linker_name:       "ipcmap",
	linker_id:         IPCMAP_LINKER,
};
