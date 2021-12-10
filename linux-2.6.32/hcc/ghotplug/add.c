/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#define MODULE_NAME "Hotplug"

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/hcc_hashtable.h>
#include <linux/uaccess.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/ghotplug.h>
#include <hcc/namespace.h>
#include <hcc/hcc_nodemask.h>

#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>
#include <hcc/hcc_syscalls.h>
#include <hcc/hcc_services.h>

#include "ghotplug_internal.h"

int __nodes_add(struct ghotplug_context *ctx)
{
	ghotplug_add_notify(ctx, GHOTPLUG_NOTIFY_ADD);
	return 0;
}

static void handle_node_add(struct grpc_desc *grpc_desc, void *data, size_t size)
{
	struct ghotplug_context *ctx;
	struct hcc_namespace *ns = find_get_hcc_ns();
	char *page;
	int ret;

	BUG_ON(!ns);
	ctx = ghotplug_ctx_alloc(ns);
	put_hcc_ns(ns);
	if (!ctx) {
		printk("hcc: [ADD] Failed to add nodes!\n");
		return;
	}
	ctx->node_set = *(struct ghotplug_node_set *)data;

	__nodes_add(ctx);

	ghotplug_ctx_put(ctx);

	page = (char *)__get_free_page(GFP_KERNEL);
	if (page) {
		ret = hcc_nodelist_scnprintf(page, PAGE_SIZE, hcc_node_online_map);
		BUG_ON(ret >= PAGE_SIZE);
		printk("HCC is running on %d nodes: %s\n",
		       num_online_hcc_nodes(), page);
		free_page((unsigned long)page);
	} else {
		printk("HCC is running on %d nodes\n", num_online_hcc_nodes());
	}
}

static int do_nodes_add(struct ghotplug_context *ctx)
{
	char *page;
	hcc_node_t node;
	int ret;

	page = (char *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	ret = hcc_nodelist_scnprintf(page, PAGE_SIZE, ctx->node_set.v);
	BUG_ON(ret >= PAGE_SIZE);
	printk("hcc: [ADD] Adding nodes %s ...\n", page);

	free_page((unsigned long)page);

	/*
	 * Send request to all new members
	 * Current limitation: only not-started nodes can be added to a
	 * running cluster (ie: a node can't move from a subcluster to another one)
	 */
	ret = do_cluster_start(ctx);
	if (ret) {
		printk(KERN_ERR "hcc: [ADD] Adding nodes failed! err=%d\n",
		       ret);
		return ret;
	}

	/* Send request to all members of the current cluster */
	for_each_online_hcc_node(node)
		grpc_async(NODE_ADD, node, &ctx->node_set, sizeof(ctx->node_set));

	printk("hcc: [ADD] Adding nodes succeeded.\n");

	return ret;
}

static int nodes_add(void __user *arg)
{
	struct __ghotplug_node_set __node_set;
	struct ghotplug_context *ctx;
	int err;

	if (copy_from_user(&__node_set, arg, sizeof(struct __ghotplug_node_set)))
		return -EFAULT;

	ctx = ghotplug_ctx_alloc(current->nsproxy->hcc_ns);
	if (!ctx)
		return -ENOMEM;

	ctx->node_set.subclusterid = __node_set.subclusterid;
	err = hcc_nodemask_copy_from_user(&ctx->node_set.v, &__node_set.v);
	if (err)
		goto out;

	err = -EPERM;
	if (ctx->node_set.subclusterid != hcc_subsession_id)
		goto out;

	if (!hcc_node_online(hcc_node_id))
		goto out;

	err = -ENONET;
	if (!hcc_nodes_subset(ctx->node_set.v, hcc_node_present_map))
		goto out;

	err = -EPERM;
	if (hcc_nodes_intersects(ctx->node_set.v, hcc_node_online_map))
		goto out;

	err = do_nodes_add(ctx);

out:
	ghotplug_ctx_put(ctx);

	return err;
}

int ghotplug_add_init(void)
{
	grpc_register_void(NODE_ADD, handle_node_add, 0);

	register_proc_service(HCC_SYS_GHOTPLUG_ADD, nodes_add);
	return 0;
}

void ghotplug_add_cleanup(void)
{
}
