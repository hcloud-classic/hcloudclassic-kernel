/** Dynamic per CPU informations management.
 *  @file dynamic_cpu_info_linker.h
 *
 *  @author Innogrid HCC
 */

#ifndef DYNAMIC_CPU_INFO_LINKER_H
#define DYNAMIC_CPU_INFO_LINKER_H

#include <linux/irqnr.h>
#include <linux/kernel_stat.h>
#include <hcc/cpu_id.h>
#include <gdm/gdm.h>
#include <gdm/object_server.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/* Dynamic CPU informations */

typedef struct {
	struct kernel_stat stat;
	u64 sum_irq;
	u64 sum_softirq;
	unsigned int per_softirq_sums[NR_SOFTIRQS];
} hcc_dynamic_cpu_info_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/

extern struct gdm_set *dynamic_cpu_info_gdm_set;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int dynamic_cpu_info_init(void);

/** Helper function to get dynamic CPU info
 *  @author Innogrid HCC
 *
 *  @param node_id   Id of the node hosting the CPU we want informations on.
 *  @param cpu_id    Id of the CPU we want informations on.
 *
 *  @return  Structure containing information on the requested CPU.
 */
static inline hcc_dynamic_cpu_info_t *get_dynamic_cpu_info(int node_id,
							   int cpu_id)
{
	return _fgdm_get_object(dynamic_cpu_info_gdm_set,
				 __hcc_cpu_id(node_id, cpu_id),
				 GDM_NO_FREEZE|GDM_NO_FT_REQ);
}

#endif /* DYNAMIC_CPU_INFO LINKER_H */
