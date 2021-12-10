/** Distributed management of the MM structure.
 *  @file mm_struct.h
 *
 *  @author Innogrid HCC.
 */


#ifndef MM_STRUCT_H
#define MM_STRUCT_H

#include <gdm/gdm_get_object.h>
#include <gdm/gdm_grab_object.h>
#include <gdm/gdm_put_object.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern struct gdm_set *mm_struct_gdm_set;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/


int reinit_mm(struct mm_struct *mm);


int init_anon_vma_gdm_set(struct task_struct *tsk,
			   struct mm_struct *mm);

struct mm_struct *hcc_dup_mm(struct task_struct *tsk,struct mm_struct *src_mm);

static inline struct mm_struct *hcc_get_mm(unique_id_t mm_id)
{
	if (mm_id)
		return _gdm_get_object (mm_struct_gdm_set, mm_id);
	else
		return NULL;
}

static inline struct mm_struct *hcc_grab_mm(unique_id_t mm_id)
{
	if (mm_id)
		return _gdm_grab_object (mm_struct_gdm_set, mm_id);
	else
		return NULL;
}

void kcb_mm_get(struct mm_struct *mm);

static inline void hcc_put_mm(unique_id_t mm_id)
{
	if (mm_id)
		_gdm_put_object (mm_struct_gdm_set, mm_id);
}

void create_mm_struct_object(struct mm_struct *mm);

void mm_struct_finalize (void);
void mm_struct_init (void);

#endif // MM_STRUCT_H
