#ifndef GDM_PROC_H

#define GDM_PROC_H

#ifdef __KERNEL__

#include <linux/proc_fs.h>
#include <hcc/hcc_services.h>
#include <gdm/gdm_types.h>

#endif // __KERNEL__



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/




/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#ifdef __KERNEL__

int procfs_gdm_init (void);
int procfs_gdm_finalize (void);


/** Create a /proc/hcc/gdm/<set_id> directory and sub-directories.
 *  @author Innogrid HCC
 *
 *  @param set_id   Id of the gdm set to create a proc entry for.
 *
 *  @return proc_fs entry created.
 */
struct proc_dir_entry *create_gdm_proc (gdm_set_id_t set_id);



/** Remove a /proc/hcc/gdm/<set_id> directory and sub-directories.
 *  @author Innogrid HCC
 *
 *  @param proc_entry    Struct of the proc entry to destroy.
 */
void remove_gdm_proc (struct proc_dir_entry *proc_entry);


#endif /* __KERNEL__ */

#endif /* GDM_PROC_H */
