/** MM Struct Linker.
 *  @file mm_struct_io_linker.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/rmap.h>
#include <net/grpc/grpc.h>
#include <gdm/gdm.h>

#include "mm_struct.h"
#include "vma_struct.h"



/*****************************************************************************/
/*                                                                           */
/*                       MM_STRUCT GDM SET IO FUNCTIONS                     */
/*                                                                           */
/*****************************************************************************/



int mm_alloc_object (struct gdm_obj *obj_entry,
		     struct gdm_set *set,
		     objid_t objid)
{
	obj_entry->object = NULL;
	return 0;
}



int mm_first_touch (struct gdm_obj *obj_entry,
		    struct gdm_set *set,
		    objid_t objid,
		    int flags)
{
	/* Should never be called */
	BUG();

	return 0;
}



int mm_remove_object (void *object,
		      struct gdm_set *set,
		      objid_t objid)
{
	struct mm_struct *mm = object;

	/* Ensure that no thread uses this signal_struct copy */
	down_write(&mm->remove_sem);
	up_write(&mm->remove_sem);

	/* Take the mmap_sem to avoid race condition with clean_up_mm_struct */

	atomic_inc(&mm->mm_count);
	down_write(&mm->mmap_sem);

	mmput(mm);

	up_write(&mm->mmap_sem);

	mm->mm_id = 0;

	mmdrop(mm);

	return 0;
}



/** Export an MM struct
 *  @author Innogrid HCC
 *
 *  @param  buffer    Buffer to export object data in.
 *  @param  obj_entry  Object entry of the object to export.
 */
int mm_export_object (struct grpc_desc *desc,
		      struct gdm_set *set,
		      struct gdm_obj *obj_entry,
		      objid_t objid,
		      int flags)
{
	struct mm_struct *mm;
	hcc_syms_val_t unmap_id, get_unmap_id, get_unmap_exec_id;

	mm = obj_entry->object;

	hcc_node_set (desc->client, mm->copyset);

	grpc_pack(desc, 0, &mm->mm_id, sizeof(unique_id_t));
	grpc_pack(desc, 0, &mm->anon_vma_gdm_id, sizeof(unique_id_t));
	grpc_pack(desc, 0, &mm->context.vdso, sizeof(void*));
	grpc_pack(desc, 0, &mm->copyset, sizeof(hcc_nodemask_t));

	get_unmap_exec_id = hcc_syms_export(mm->get_unmapped_exec_area);
	BUG_ON(mm->get_unmapped_exec_area && get_unmap_exec_id == HCC_SYMS_UNDEF);
	grpc_pack_type(desc, get_unmap_exec_id);

	get_unmap_id = hcc_syms_export(mm->get_unmapped_area);
	BUG_ON(mm->get_unmapped_area && get_unmap_id == HCC_SYMS_UNDEF);
	grpc_pack_type(desc, get_unmap_id);

	unmap_id = hcc_syms_export(mm->unmap_area);
	BUG_ON(mm->unmap_area && unmap_id == HCC_SYMS_UNDEF);
	grpc_pack_type(desc, unmap_id);

	return 0;
}



/** Import an MM struct
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  Object entry of the object to import.
 *  @param  _buffer   Data to import in the object.
 */
int mm_import_object (struct grpc_desc *desc,
		      struct gdm_set *_set,
		      struct gdm_obj *obj_entry,
		      objid_t objid,
		      int flags)
{
	struct mm_struct *mm;
	hcc_syms_val_t unmap_id, get_unmap_id, get_unmap_exec_id;
	struct gdm_set *set;
	unique_id_t mm_id, gdm_id;
	void *context_vdso;
	int r;

	mm = obj_entry->object;

	r = grpc_unpack (desc, 0, &mm_id, sizeof(unique_id_t));
	if (r)
		return r;

	r = grpc_unpack (desc, 0, &gdm_id, sizeof(unique_id_t));
	if (r)
		return r;

	r = grpc_unpack (desc, 0, &context_vdso, sizeof(void*));
	if (r)
		return r;

	if (mm == NULL) {
		/* First import */
		set = _find_get_gdm_set(gdm_def_ns, gdm_id);
		BUG_ON (set == NULL);

		mm = set->obj_set;
		mm->mm_id = mm_id;
		atomic_inc(&mm->mm_users);
		obj_entry->object = mm;
		put_gdm_set(set);
		mm->context.vdso = context_vdso;
	}

	r = grpc_unpack(desc, 0, &mm->copyset, sizeof(hcc_nodemask_t));
	if (r)
		return r;

	r = grpc_unpack_type(desc, get_unmap_exec_id);
	if (r)
		return r;
	mm->get_unmapped_exec_area = hcc_syms_import (get_unmap_exec_id);

	r = grpc_unpack_type(desc, get_unmap_id);
	if (r)
		return r;
	mm->get_unmapped_area = hcc_syms_import (get_unmap_id);

	r = grpc_unpack_type(desc, unmap_id);
	if (r)
		return r;
	mm->unmap_area = hcc_syms_import (unmap_id);

	return 0;
}



/****************************************************************************/

/* Init the mm_struct IO linker */

struct iolinker_struct mm_struct_io_linker = {
	alloc_object:      mm_alloc_object,
	first_touch:       mm_first_touch,
	export_object:     mm_export_object,
	import_object:     mm_import_object,
	remove_object:     mm_remove_object,
	linker_name:       "MM ",
	linker_id:         MM_STRUCT_LINKER,
};
