/** Dynamic node informations management.
 *  @file dynamic_node_info_linker.h
 *
 *  @author Innogrid HCC
 */

#ifndef DYNAMIC_NODE_INFO_LINKER_H
#define DYNAMIC_NODE_INFO_LINKER_H

#include <linux/hardirq.h>
#include <linux/procfs_internal.h>
#include <hcc/sys/types.h>
#include <gdm/gdm.h>
#include <gdm/object_server.h>
#include <asm/hcc/meminfo.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Node related informations */

typedef struct {
	struct timespec idletime;
	struct timespec uptime;
	unsigned long avenrun[3];	/* Load averages */
	int last_pid;
	int nr_threads;
	unsigned long nr_running;
	unsigned long long nr_context_switches;
	unsigned long jif;
	unsigned long total_forks;
	unsigned long nr_iowait;
	u64 arch_irq;

	/* Dynamic memory informations */

	unsigned long totalram;
	unsigned long freeram;
	unsigned long bufferram;
	unsigned long totalhigh;
	unsigned long freehigh;
	unsigned long totalswap;
	unsigned long freeswap;

	unsigned long nr_pages[NR_LRU_LISTS - LRU_BASE];
	unsigned long nr_mlock;
	unsigned long nr_file_pages;
	unsigned long nr_file_dirty;
	unsigned long nr_writeback;
	unsigned long nr_anon_pages;
	unsigned long nr_file_mapped;
	unsigned long nr_page_table_pages;
	unsigned long nr_slab_reclaimable;
	unsigned long nr_slab_unreclaimable;
	unsigned long nr_unstable_nfs;
	unsigned long nr_bounce;
	unsigned long nr_writeback_temp;

	unsigned long quicklists;

	struct vmalloc_info vmi;
	unsigned long vmalloc_total;

	unsigned long allowed;
	unsigned long commited;

	unsigned long swapcache_pages;

	unsigned long nr_huge_pages;
	unsigned long free_huge_pages;
	unsigned long resv_huge_pages;
	unsigned long surplus_huge_pages;

	hcc_arch_meminfo_t arch_meminfo;
} hcc_dynamic_node_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct gdm_set *dynamic_node_info_gdm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int dynamic_node_info_init(void);

/** Helper function to get dynamic node informations.
 *  @author Innogrid HCC
 *
 *  @param node_id   Id of the node we want informations on.
 *
 *  @return  Structure containing information on the requested node.
 */
static inline
hcc_dynamic_node_info_t *get_dynamic_node_info(hcc_node_t nodeid)
{
	return _fgdm_get_object(dynamic_node_info_gdm_set, nodeid,
				 GDM_NO_FREEZE|GDM_NO_FT_REQ);
}

#endif /* DYNAMIC_NODE_INFO_LINKER_H */
