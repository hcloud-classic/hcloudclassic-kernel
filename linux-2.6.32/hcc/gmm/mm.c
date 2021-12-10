/** GMM module initialization.
 *  @file mm.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 *
 *  Implementation of functions used to initialize and finalize the
 *  gmm module.
 */

#include <linux/mm.h>
#include <asm/mman.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <hcc/hcc_syms.h>
#include <hcc/gmm.h>
#include <hcc/ghotplug.h>
#include <hcc/page_table_tree.h>
#include <gdm/gdm.h>
#include "mm_struct.h"
#include "memory_int_linker.h"
#include "memory_io_linker.h"
#include "mm_struct_io_linker.h"
#include "mm_server.h"
#include "injection.h"


/** Initialisation of the DSM module.
 *  @author Innogrid HCC
 *
 *  Start object server, object manager and gdm set manager threads.
 *  Register gmm services in the /proc/hcc/services.
 */
int init_gmm(void)
{
	printk("GMM initialisation : start\n");

	hcc_syms_register (HCC_SYMS_VM_OPS_NULL, &null_vm_ops);
	hcc_syms_register (HCC_SYMS_VM_OPS_FILE_GENERIC, (void *)&generic_file_vm_ops);
	special_mapping_vm_ops_hcc_syms_register ();
	hcc_syms_register (HCC_SYMS_VM_OPS_MEMORY_GDM_VMOPS,
			  &anon_memory_gdm_vmops);

	hcc_syms_register (HCC_SYMS_ARCH_UNMAP_AREA, arch_unmap_area);
	hcc_syms_register (HCC_SYMS_ARCH_UNMAP_AREA_TOPDOWN,
			  arch_unmap_area_topdown);
	hcc_syms_register (HCC_SYMS_ARCH_GET_UNMAP_AREA, arch_get_unmapped_area);
	hcc_syms_register (HCC_SYMS_ARCH_GET_UNMAP_AREA_TOPDOWN,
			  arch_get_unmapped_area_topdown);
	hcc_syms_register (HCC_SYMS_ARCH_GET_UNMAP_EXEC_AREA, arch_get_unmapped_exec_area);

	hcc_syms_register (HCC_SYMS_GDM_PT_OPS, &gdm_pt_set_ops);

	register_io_linker (MEMORY_LINKER, &memory_linker);
	register_io_linker (MM_STRUCT_LINKER, &mm_struct_io_linker);

	mm_struct_init ();
	mm_server_init();
	mm_injection_init();

	printk ("GMM initialisation done\n");

	return 0;
}



/** Cleanup of the DSM module.
 *  @author Innogrid HCC
 *
 *  Kill object manager, object server and gdm set manager threads.
 */
void cleanup_gmm (void)
{
	printk ("GMM termination : start\n");

	mm_injection_finalize();
	mm_server_finalize();
	mm_struct_finalize();

	hcc_syms_unregister (HCC_SYMS_VM_OPS_FILE_GENERIC);
	special_mapping_vm_ops_hcc_syms_unregister ();
	hcc_syms_unregister (HCC_SYMS_VM_OPS_MEMORY_GDM_VMOPS);
	hcc_syms_unregister (HCC_SYMS_ARCH_UNMAP_AREA);
	hcc_syms_unregister (HCC_SYMS_ARCH_UNMAP_AREA_TOPDOWN);
	hcc_syms_unregister (HCC_SYMS_ARCH_GET_UNMAP_AREA);
	hcc_syms_unregister (HCC_SYMS_ARCH_GET_UNMAP_AREA_TOPDOWN);
	hcc_syms_unregister (HCC_SYMS_ARCH_GET_UNMAP_EXEC_AREA);

	printk ("GMM termination done\n");
}
