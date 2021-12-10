#ifndef __HCC_MONITOR_MEM_PROBE_H__
#define __HCC_MONITOR_MEM_PROBE_H__

#define MEM_PROBE_NAME "mem_probe"

typedef struct mem_probe_data {
	unsigned long ram_free;
	unsigned long ram_total;
} mem_probe_data_t;

#endif /* __HCC_MONITOR_MEM_PROBE_H__ */
