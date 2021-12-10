/** GDM interface.
 *  @file gdm.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM__
#define __GDM__

#include <gdm/gdm_types.h>
#include <gdm/io_linker.h>
#include <gdm/object.h>
#include <gdm/gdm_set.h>
#include <gdm/gdm_find_object.h>
#include <gdm/gdm_put_object.h>
#include <gdm/gdm_get_object.h>
#include <gdm/gdm_grab_object.h>
#include <gdm/gdm_set_object.h>
#include <gdm/gdm_flush_object.h>
#include <gdm/gdm_remove_object.h>
#include <gdm/gdm_sync_object.h>

#include <hcc/debug.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                             MACRO CONSTANTS                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Print an error message concerning a problem in the state machine */
#define STATE_MACHINE_ERROR(set_id, objid, obj_entry) \
{ \
  if (OBJ_STATE_INDEX(OBJ_STATE(obj_entry)) < NB_OBJ_STATE) \
    PANIC ("Receive a object on %s object (%ld;%ld) \n", \
	   STATE_NAME(OBJ_STATE(obj_entry)), set_id, objid) ; \
  else \
    PANIC( "Object (%ld;%ld) : unknown object state\n", set_id, objid) ; \
}



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern event_counter_t total_get_object_counter;
extern event_counter_t total_grab_object_counter;
extern event_counter_t total_remove_object_counter;
extern event_counter_t total_flush_object_counter;



/*********************** GDM set Counter tools ************************/

int initialize_gdm_info_struct (struct task_struct *task);


static inline void inc_get_object_counter(struct gdm_set *set)
{
	total_get_object_counter++;
	set->get_object_counter++;
	if (!current->gdm_info)
		initialize_gdm_info_struct(current);
	current->gdm_info->get_object_counter++;
}

static inline void inc_grab_object_counter(struct gdm_set *set)
{
	total_grab_object_counter++;
	set->grab_object_counter++;
	if (!current->gdm_info)
		initialize_gdm_info_struct(current);
	current->gdm_info->grab_object_counter++;
}

static inline void inc_remove_object_counter(struct gdm_set *set)
{
	total_remove_object_counter++;
	set->remove_object_counter++;
	if (!current->gdm_info)
		initialize_gdm_info_struct(current);
	current->gdm_info->remove_object_counter++;
}

static inline void inc_flush_object_counter(struct gdm_set *set)
{
	total_flush_object_counter++;
	set->flush_object_counter++;
	if (!current->gdm_info)
		initialize_gdm_info_struct(current);
	current->gdm_info->flush_object_counter++;
}

#endif
