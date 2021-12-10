/** GDM memory IO linker.
 *  @file memory_io_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/string.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/rmap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/mm_inline.h>
#include <asm/tlbflush.h>

#include <net/grpc/grpc.h>
#include <gdm/gdm.h>
#include <hcc/page_table_tree.h>

#include "memory_io_linker.h"
#include "memory_int_linker.h"

/*****************************************************************************/
/*                                                                           */
/*                       MEMORY GDM SET IO FUNCTIONS                       */
/*                                                                           */
/*****************************************************************************/

/** Allocate an object
 *  @author Innogrid HCC
 */
int memory_alloc_object (struct gdm_obj * obj_entry,
			 struct gdm_set * set,
			 objid_t objid)
{
	struct page *page = alloc_page (GFP_HIGHUSER);

	if (!page)
		return -ENOMEM;

	obj_entry->object = page;

	return 0;
}

/** Import an object
 *  @author Innogrid HCC
 *
 *  @param  object    The object to import data in.
 *  @param  buffer    Data to import in the object.
 */
int memory_import_object (struct grpc_desc *desc,
			  struct gdm_set *set,
			  struct gdm_obj *obj_entry,
			  objid_t objid,
			  int flags)
{
	struct page *page = obj_entry->object;
	char *data;

	data = (char *)kmap(page);
	grpc_unpack(desc, 0, data, PAGE_SIZE);
	kunmap(page);

//	copy_buff_to_highpage ((struct page *) obj_entry->object, buffer);
	return 0;
}

/** Export an object
 *  @author Innogrid HCC
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  object    The object to export data from.
 */
int memory_export_object (struct grpc_desc *desc,
			  struct gdm_set *set,
			  struct gdm_obj *obj_entry,
			  objid_t objid,
			  int flags)
{
	struct page *page = (struct page *)obj_entry->object;
	char *data;

	data = (char *)kmap_atomic(page, KM_USER0);
	grpc_pack(desc, 0, data, PAGE_SIZE);
	kunmap_atomic(data, KM_USER0);

//	copy_highpage_to_buff (buffer, (struct page *) obj_entry->object);
	return 0;
}

/** Handle a gdm set memory page first touch
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Kddm Set page descriptor.
 *  @param  set        Kddm Set descriptor
 *  @param  objid      Id of the page to create.
 *
 *  @return  0 if everything is ok. Negative value otherwise.
 */
int memory_first_touch (struct gdm_obj * obj_entry,
                        struct gdm_set * set,
                        objid_t objid,
			int flags)
{
	int res = 0;
	struct page *page;

	if (!obj_entry->object) {
		page = alloc_page (GFP_HIGHUSER | __GFP_ZERO);

		if (!page)
			res = -ENOMEM;
//		else
//			page->obj_entry = obj_entry;

		obj_entry->object = page;
	}

	return res;
}

/** Insert a new gdm set page in the file cache.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Descriptor of the page to insert.
 *  @param  set        Kddm Set descriptor
 *  @param  padeid     Id of the page to insert.
 */
int memory_insert_page (struct gdm_obj * obj_entry,
                        struct gdm_set * set,
                        objid_t objid)
{
	struct page *page;

	page = obj_entry->object;

	return 0;
}

/** Invalidate a gdm set memory page.
 *  @author Innogrid HCC
 *
 *  @param  set      Kddm Set descriptor
 *  @param  objid    Id of the page to invalidate
 */
int memory_invalidate_page (struct gdm_obj * obj_entry,
                            struct gdm_set * set,
                            objid_t objid)
{
	if (obj_entry->object) {
		struct page *page = (struct page *) obj_entry->object;

		BUG_ON(swap_pte_page(page));

		/* Invalidate page table entry */
		gdm_pt_invalidate (set, objid, obj_entry, page);

		ClearPageMigratable(page);

		/* Free the page */
		page_cache_release(page);
	}

	return 0;
}

void memory_change_state (struct gdm_obj * obj_entry,
			  struct gdm_set * set,
			  objid_t objid,
			  gdm_obj_state_t state)
{
	struct page *page = obj_entry->object;

	if (!page)
		return ;

	/* If the page is not mapped, we have nothing to do */
	if (swap_pte_page(page))
		return;

	/* Page to be swap are no more mapped. Nothing to do here. */
	if (PageSwapCache(page))
		return;

	switch (state) {
	  case READ_COPY :
	  case READ_OWNER :
		  wait_lock_page(page);

		  if (page_mapped(page)) {
			  BUG_ON ((page->mapping == NULL) &&
				  (page != ZERO_PAGE(NULL)));

			  SetPageToSetReadOnly(page);
			  try_to_unmap(page, TTU_UNMAP);
			  ClearPageToSetReadOnly(page);
		  }

		  unlock_page(page);
		  break ;

	  default:
		  break ;
	}
}

/** Handle a gdm set memory page remove.
 *  @author Innogrid HCC
 *
 *  @param  set      Kddm Set descriptor
 *  @param  padeid   Id of the page to remove
 */
int memory_remove_page (void *object,
                        struct gdm_set * set,
                        objid_t objid)
{
	struct page *page = (struct page *) object;
	struct gdm_obj *obj_entry;
	swp_entry_t entry;

	if (!page)
		return 0;

	if (swap_pte_page(page)) {
		entry = get_swap_entry_from_page(page);
		free_swap_and_cache(entry);
	}
	else {
		obj_entry = page->obj_entry;

		/* Invalidate page table entry */
		gdm_pt_invalidate (set, objid, obj_entry, page);

		ClearPageMigratable(page);

		/* Free the page */
		free_page_and_swap_cache(page);
	}

	return 0;
}

/****************************************************************************/

/* Init the memory IO linker */

struct iolinker_struct memory_linker = {
	first_touch:       memory_first_touch,
	remove_object:     memory_remove_page,
	invalidate_object: memory_invalidate_page,
	change_state:      memory_change_state,
	insert_object:     memory_insert_page,
	linker_name:       "mem ",
	linker_id:         MEMORY_LINKER,
	alloc_object:      memory_alloc_object,
	export_object:     memory_export_object,
	import_object:     memory_import_object,
};
