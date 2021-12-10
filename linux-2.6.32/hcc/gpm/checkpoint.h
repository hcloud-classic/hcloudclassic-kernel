/**
 *  Process checkpoint interface.
 *  @file checkpoint.h
 *
 *  Definition of process checkpointing interface.
 *  @author Innogrid HCC
 */

#ifndef __CHECKPOINT_H__
#define __CHECKPOINT_H__

#include <linux/types.h>

struct task_struct;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int can_be_checkpointed(struct task_struct *task_to_checkpoint);

#endif /* __CHECKPOINT_H__ */
