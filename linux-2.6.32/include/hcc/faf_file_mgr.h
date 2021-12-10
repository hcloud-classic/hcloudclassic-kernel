/** Global management of faf files interface.
 *  @file faf_file_mgr.h
 *
 *  @author Innogrid HCC
 */
#ifndef __FAF_FILE_MGR__
#define __FAF_FILE_MGR__

#include <hcc/action.h>
#include <hcc/ghost.h>

struct grpc_desc;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct dvfs_mobility_operations dvfs_mobility_faf_ops;
extern struct kmem_cache *faf_client_data_cachep;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct file *create_faf_file_from_hcc_desc(struct task_struct *task,
					   void *_desc);

int get_faf_file_hcc_desc(struct file *file, void **desc, int *desc_size);

/* file will be faffed if not already */
int send_faf_file_desc(struct grpc_desc *desc, struct file *file);

/* file must be already faffed */
int __send_faf_file_desc(struct grpc_desc *desc, struct file *file);

struct file *rcv_faf_file_desc(struct grpc_desc *desc);

#endif // __FAF_FILE_MGR__
