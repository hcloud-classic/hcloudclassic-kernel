#ifndef HCC_PROCFS_H
#define HCC_PROCFS_H

#include <hcc/sys/types.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int hcc_procfs_init(void);
int hcc_procfs_finalize(void);

int create_proc_node_info(hcc_node_t node);
int remove_proc_node_info(hcc_node_t node);

#endif /* HCC_PROCFS_H */
