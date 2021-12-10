/** Initilize the tool module.
 *  @file hcc_tools.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <asm/uaccess.h>

#include <hcc/procfs.h>
#include <hcc/hcc_syscalls.h>
#include <hcc/hcc_services.h>

static int tools_proc_nb_max_nodes(void* arg)
{
	int r, v = HCC_MAX_NODES;

	r = 0;
	
	if(copy_to_user((void*)arg, (void*)&v, sizeof(v)))
		r = -EFAULT;

	return r;
}

static int tools_proc_nb_max_clusters(void* arg)
{
	int r, v = HCC_MAX_CLUSTERS;

	r = 0;

	if(copy_to_user((void*)arg, (void*)&v, sizeof(v)))
		r = -EFAULT;

	return r;
}

static int tools_proc_node_id(void *arg)
{
        int node_id = hcc_node_id;
        int r = 0;

        if (copy_to_user((void *)arg, (void *)&node_id, sizeof(int)))
                r = -EFAULT;

        return r;
}

static int tools_proc_nodes_count(void *arg)
{
        int nb_nodes = num_online_hcc_nodes();
        int r = 0;

        if (copy_to_user((void *)arg, (void *)&nb_nodes, sizeof(int)))
                r = -EFAULT;

        return r;
}

int init_tools(void)
{
	int error;

	if ((error = hcc_proc_init()))
		goto ErrorProc;
	if ((error = hcc_syscalls_init()))
		goto ErrorSys;

	error = register_proc_service(HCC_SYS_NB_MAX_NODES, tools_proc_nb_max_nodes);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}

	error = register_proc_service(HCC_SYS_NB_MAX_CLUSTERS, tools_proc_nb_max_clusters);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}

	error = register_proc_service(HCC_SYS_GET_NODE_ID, tools_proc_node_id);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}

	error = register_proc_service(HCC_SYS_GET_NODES_COUNT, tools_proc_nodes_count);
	if (error != 0) {
		error = -EINVAL;
		goto Error;
	}
	
	printk("HCC tools - init module\n");
 Done:
	return error;

	hcc_syscalls_finalize();
 ErrorSys:
	hcc_proc_finalize();
 ErrorProc:
 Error:
	goto Done;
}
EXPORT_SYMBOL(init_tools);

void cleanup_tools(void)
{
	hcc_syscalls_finalize();
#ifdef CONFIG_HCC
	hcc_proc_finalize();
#endif

	printk("iluvatar - end module\n");
}
