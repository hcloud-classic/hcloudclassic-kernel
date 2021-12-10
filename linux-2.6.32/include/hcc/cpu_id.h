#ifndef __KHCC_CPU_ID_H__
#define __KHCC_CPU_ID_H__

#include <linux/threads.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>

static inline int __hcc_cpu_id(hcc_node_t node, int cpu_id)
{
	return node * NR_CPUS + cpu_id;
}

static inline int hcc_cpu_id(int local_cpu_id)
{
	return __hcc_cpu_id(hcc_node_id, local_cpu_id);
}

static inline int hcc_cpu_is_local(int hcc_cpu_id)
{
	int min_local_cpu = hcc_node_id * NR_CPUS;

	return hcc_cpu_id >= min_local_cpu
		&& hcc_cpu_id < min_local_cpu + NR_CPUS;
}

static inline hcc_node_t hcc_cpu_node(int hcc_cpu_id)
{
	return hcc_cpu_id / NR_CPUS;
}

static inline int local_cpu_id(int hcc_cpu_id)
{
	return hcc_cpu_id % NR_CPUS;
}

#endif /* __KHCC_CPU_ID_H__ */
