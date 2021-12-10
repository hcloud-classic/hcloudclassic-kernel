#include <linux/module.h>

#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>
#include <hcc/ghotplug.h>

hcc_nodemask_t hcc_node_possible_map;
hcc_nodemask_t hcc_node_present_map;
hcc_nodemask_t hcc_node_online_map;
EXPORT_SYMBOL(hcc_node_online_map);

struct universe_elem universe[HCC_MAX_NODES];

void hcc_node_arrival(hcc_node_t nodeid)
{
	printk("hcc_node_arrival: nodeid = %d\n", nodeid);
	set_hcc_node_present(nodeid);
	hcc_node_reachable(nodeid);
#ifdef CONFIG_HCC_GHOTPLUG
	universe[nodeid].state = 1;
#endif
}

void hcc_node_departure(hcc_node_t nodeid)
{
	printk("hcc_node_departure: nodeid = %d\n", nodeid);
#ifdef CONFIG_HCC_GHOTPLUG
	universe[nodeid].state = 0;
#endif
	clear_hcc_node_present(nodeid);
	hcc_node_unreachable(nodeid);
}

void init_node_discovering(void)
{
	int i;

	hcc_nodes_setall(hcc_node_possible_map);
	hcc_nodes_clear(hcc_node_present_map);
	hcc_nodes_clear(hcc_node_online_map);
	
#ifdef CONFIG_HCC_GHOTPLUG
	for (i = 0; i < HCC_MAX_NODES; i++) {
		universe[i].state = 0;
		universe[i].subid = -1;
	}
#endif

	if (ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID)) {
#ifdef CONFIG_HCC_GHOTPLUG
		universe[hcc_node_id].state = 1;
#endif
		set_hcc_node_present(hcc_node_id);
	}
}
