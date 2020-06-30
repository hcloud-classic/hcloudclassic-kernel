#include <linux/mm.h>
#include <linux/shm.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/string.h>
#include <linux/rmap.h>
#include <linux/pagemap.h>
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/mm_inline.h>
#include <linux/kernel.h>
#include <linux/swap.h>
#include <gdm/gdm.h>
#include "hccshm.h"
#include "ipc_handler.h"



int shm_memory_insert_page(struct gdm_obj *objEntry, struct gdm_set *gdm,
			   objid_t objid)
{
	struct page *page;
	struct shmid_kernel *shp;
	struct address_space *mapping = NULL;
	int ret, shm_id;
	struct ipc_namespace *ns;

	ns = find_get_hcc_ipcns();
	BUG_ON(!ns);

	shm_id = *(int *) gdm->private_data;

	shp = local_shm_lock(ns, shm_id);

	if (IS_ERR(shp)) {
		ret = PTR_ERR(shp);
		goto error;
	}

	mapping = shp->shm_file->f_dentry->d_inode->i_mapping;

	local_shm_unlock(shp);

	page = objEntry->object;
	page->index = objid;
	ret = add_to_page_cache_lru(page, mapping, objid, GFP_ATOMIC);
	if (ret) {
		printk("shm_memory_insert_page: add_to_page_cache_lru returns %d\n",
		       ret);
		BUG();
	}
	unlock_page(page);

error:
	put_ipc_ns(ns);

	return ret;
}



int shm_memory_invalidate_page (struct gdm_obj * objEntry,
				struct gdm_set * gdm,
				objid_t objid)
{
	int res ;

	if (objEntry->object) {
		struct page *page = (struct page *) objEntry->object;

		BUG_ON (page->mapping == NULL);
		BUG_ON (TestSetPageLocked(page));

		SetPageToInvalidate(page);
		res = try_to_unmap(page, 0);

		ClearPageToInvalidate(page);
		remove_from_page_cache (page);

		if (PageDirty(page)) {
			printk ("Check why the page is dirty...\n");
			ClearPageDirty(page);
		}
		unlock_page(page);

		if (TestClearPageLRU(page))
			del_page_from_lru(page_zone(page), page);

		page_cache_release (page);

#ifdef IPCDEBUG_PAGEALLOC
		int extra_count = 0;

		if (PageInVec(page))
			extra_count = 1;

		BUG_ON (page_mapcount(page) != 0);

		if ((page_count (page) != objEntry->countx + extra_count)) {
			WARNING ("Hum... page %p (%ld;%ld) has count %d;%d "
				 "(against %d)\n", page, gdm->id, objid,
				 page_count (page), page_mapcount(page),
				 objEntry->countx + extra_count);
		}

		if (PageActive(page)) {
			WARNING ("Hum. page %p (%ld;%ld) has Active bit set\n",
				 page, gdm->id, objid);
			while (1)
				schedule();
		}
#endif
	}

	return 0;
}
int shm_memory_remove_page (void *object,
			    struct gdm_set * set,
			    objid_t objid)
{
	if (object)
		page_cache_release ((struct page *) object);

	return 0;
}



struct iolinker_struct shm_memory_linker = {
	first_touch:       memory_first_touch,
	remove_object:     shm_memory_remove_page,
	invalidate_object: shm_memory_invalidate_page,
	change_state:      memory_change_state,
	insert_object:     shm_memory_insert_page,
	linker_name:       "shm",
	linker_id:         SHM_MEMORY_LINKER,
	alloc_object:      memory_alloc_object,
	export_object:     memory_export_object,
	import_object:     memory_import_object
};

int shmem_memory_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct inode *inode = vma->vm_file->f_dentry->d_inode;
	struct page *page;
	struct gdm_set *gdm;
	unsigned long address;
	objid_t objid;
	int write_access = vmf->flags & FAULT_FLAG_WRITE;

	address = (unsigned long)(vmf->virtual_address) & PAGE_MASK;

	gdm = inode->i_mapping->gdm_set;

	BUG_ON(!gdm);
	objid = vma->vm_pgoff + (address - vma->vm_start) / PAGE_SIZE;

	if (write_access)
		page = gdm_grab_object(gdm_def_ns, gdm->id, objid);
	else
		page = gdm_get_object(gdm_def_ns, gdm->id, objid);

	page_cache_get(page);

	if (!page->mapping) {
		printk ("Hum... NULL mapping in shmem_memory_nopage\n");
		page->mapping = inode->i_mapping;
	}

	map_gdm_page (vma, address, page, write_access);
	ClearPageMigratable(page);

	inc_mm_counter(vma->vm_mm, file_rss);
	page_add_file_rmap(page);

	gdm_put_object (gdm_def_ns, gdm->id, objid);

	vmf->page = page;
	return 0;
}

struct page *shmem_memory_wppage (struct vm_area_struct *vma,
				  unsigned long address,
				  struct page *old_page)
{
	struct inode *inode = vma->vm_file->f_dentry->d_inode;
	struct page *page;
	struct gdm_set *gdm;
	objid_t objid;

	BUG_ON(!vma);

	gdm = inode->i_mapping->gdm_set;

	BUG_ON(!gdm);
	objid = vma->vm_pgoff + (address - vma->vm_start) / PAGE_SIZE;

	page = gdm_grab_object (gdm_def_ns, gdm->id, objid);

	if (!page->mapping)
		page->mapping = inode->i_mapping;

	map_gdm_page (vma, address, page, 1);

	if (page != old_page) {
		page_add_file_rmap(page);
		page_cache_get(page);
	}

	gdm_put_object (gdm_def_ns, gdm->id, objid);

	return page;
}


struct vm_operations_struct hcc_shmem_vm_ops = {
	fault:	shmem_memory_fault,
	wppage:	shmem_memory_wppage,
};


static int hcc_shmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct shm_file_data *sfd;

	BUG_ON(!file->private_data); 

	sfd = shm_file_data(file);
#ifdef CONFIG_HCC_DEBUG
	{
		struct ipc_namespace *ns;

		ns = find_get_hcc_ipcns();
		BUG_ON(!ns);

		BUG_ON(sfd->ns != ns);

		put_ipc_ns(ns);
	}
#endif
        file_accessed(file);
	vma->vm_ops = &hcc_shmem_vm_ops;
	vma->vm_flags |= VM_GDM;

	return 0;
}


struct file_operations hcc_shm_file_operations = {
	.mmap = hcc_shmem_mmap,
};
