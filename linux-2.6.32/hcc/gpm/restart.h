/**
 *  Process restart interface.
 *  @file restart.h
 *
 *  Definition of process restart interface.
 *  @author Innogrid HCC
 */

#ifndef __RESTART_H__
#define __RESTART_H__

#include <linux/types.h>

struct task_struct;
struct app_struct;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct task_struct *restart_process(struct app_struct *app, pid_t pid,
				    int flags);

#endif /* __RESTART_H__ */
