#ifndef __GDM_INFO_H__
#define __GDM_INFO_H__

extern int (*hcc_copy_gdm_info)(unsigned long clone_flags,
				struct task_struct * tsk);

extern struct kmem_cache *gdm_info_cachep;

#endif /* __GDM_INFO_H__ */
