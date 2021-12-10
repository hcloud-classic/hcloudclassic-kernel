/** DVFS mobililty interface
 *  @file mobility.h
 *
 *  Definition of DVFS mobility function interface.
 *  @author Innogrid HCC
 */

#ifndef __MOBILITY_H__
#define __MOBILITY_H__

#include <hcc/ghost_types.h>
#include <linux/hcc_hashtable.h>

struct gpm_action;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct dvfs_mobility_operations {
  int (*file_export) (struct gpm_action *,
		      ghost_t *, struct task_struct *, int, struct file *);
  int (*file_import) (struct gpm_action *,
		      ghost_t *, struct task_struct *, struct file **);
};

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int dvfs_mobility_init(void) ;

void dvfs_mobility_finalize (void) ;

#endif // __MOBILITY_H__
