/** Implementation of GDM mobility mechanisms.
 *  @file mobility.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 *
 *  Implementation of functions used to migrate, duplicate and checkpoint
 *  process GDM related structures.
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <gdm/gdm_types.h>

#include <hcc/ghost.h>
#include <hcc/action.h>


int initialize_gdm_info_struct (struct task_struct *task);
extern struct kmem_cache *gdm_info_cachep;



/*****************************************************************************/
/*                                                                           */
/*                              EXPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



/** Export a GDM info structure
 *  @author Innogrid HCC
 *
 *  @param ghost    Ghost where data should be stored.
 *  @param tsk      The task to ghost the GDM info struct for.
 *
 *  @return  0 if everything was OK.
 *           Negative value otherwise.
 */
int export_gdm_info_struct (struct gpm_action *action,
			     ghost_t *ghost,
			     struct task_struct *tsk)
{
	int r = 0;

	BUG_ON (tsk->gdm_info == NULL);

	switch (action->type) {
	  case GPM_REMOTE_CLONE:
		  /* */
		  break;

	  case GPM_CHECKPOINT:
	  case GPM_MIGRATE:
		  r = ghost_write (ghost, tsk->gdm_info,
				   sizeof(struct gdm_info_struct));
		  break;

	  default:
		  break;
	}

	return r;
}



/*****************************************************************************/
/*                                                                           */
/*                              IMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



int import_gdm_info_struct (struct gpm_action *action,
			     ghost_t *ghost,
			     struct task_struct *tsk)
{
	struct gdm_info_struct *gdm_info;
	int r;

	switch (action->type) {
	  case GPM_REMOTE_CLONE:
		  r = initialize_gdm_info_struct (tsk);
		  break;

	  case GPM_CHECKPOINT:
	  case GPM_MIGRATE:
		  r = -ENOMEM;
		  gdm_info = kmem_cache_alloc(gdm_info_cachep,
					       GFP_KERNEL);

		  if (!gdm_info)
			break;

		  r = ghost_read (ghost, gdm_info,
				  sizeof(struct gdm_info_struct));
		  if (r) {
			kmem_cache_free(gdm_info_cachep, gdm_info);
			break;
		  }

		  gdm_info->wait_obj = NULL;

		  tsk->gdm_info = gdm_info;

		  break;

	  default:
		  BUG();
		  r = -EINVAL;
	}

	return r;
}



/*****************************************************************************/
/*                                                                           */
/*                            UNIMPORT FUNCTIONS                             */
/*                                                                           */
/*****************************************************************************/



void unimport_gdm_info_struct (struct task_struct *tsk)
{
	kmem_cache_free (gdm_info_cachep, tsk->gdm_info);
}
