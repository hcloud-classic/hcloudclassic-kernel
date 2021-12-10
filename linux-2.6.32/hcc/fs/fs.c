/** Kerfs module initialization.
 *  @file module.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 *
 *  Implementation of functions used to initialize and finalize the
 *  kerfs module.
 */
#include <linux/module.h>
#include <linux/proc_fs.h>

#include <gdm/gdm.h>
#include <hcc/file.h>
#include "file_struct_io_linker.h"
#ifdef CONFIG_HCC_GPM
#include "mobility.h"
#include <hcc/regular_file_mgr.h>
#endif
#ifdef CONFIG_HCC_FAF
#include "faf/faf_internal.h"
#endif


/** Initialisation of the DVFS module.
 *  @author Innogrid HCC
 *
 *  Start DVFS server.
 */
int init_dvfs (void)
{
	printk ("DVFS initialisation : start\n");

	dvfs_file_cachep = kmem_cache_create("dvfs_file",
					     sizeof(struct dvfs_file_struct),
					     0, SLAB_PANIC, NULL);

	register_io_linker (DVFS_FILE_STRUCT_LINKER,
			    &dvfs_file_struct_io_linker);

#ifdef CONFIG_HCC_GPM
	dvfs_mobility_init();
#endif
#ifdef CONFIG_HCC_FAF
	faf_init();
#endif
	dvfs_file_init();

	printk ("DVFS initialisation done\n");

	return 0;
}



/** Cleanup of the DVFS module.
 *  @author Innogrid HCC
 *
 *  Kill DVFS server.
 */
void cleanup_dvfs (void)
{
	printk ("DVFS termination : start\n");

#ifdef CONFIG_HCC_FAF
	faf_finalize() ;
#endif
	dvfs_file_finalize();
#ifdef CONFIG_HCC_GPM
	dvfs_mobility_finalize();
#endif
	printk ("DVFS termination done\n");
}
