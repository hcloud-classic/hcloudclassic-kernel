/** GDM SHM Memory Linker.
 *  @file shm_memory_linker.h
 *
 *  Link GDM and Linux SHM memory system.
 *  @author Innogrid HCC
 */

#ifndef __SHM_MEMORY_LINKER__
#define __SHM_MEMORY_LINKER__


/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct vm_operations_struct _hcc_shmem_vmops;
extern struct file_operations hcc_shm_file_operations;

#endif
