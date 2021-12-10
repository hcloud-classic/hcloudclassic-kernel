/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/workqueue.h>
#include <linux/slab.h>

#include <hcc/ghotplug.h>
#include <hcc/namespace.h>
#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>

#include "ghotplug_internal.h"

struct workqueue_struct *hcc_ha_wq;

struct ghotplug_context *ghotplug_ctx_alloc(struct hcc_namespace *ns)
{
	struct ghotplug_context *ctx;

	BUG_ON(!ns);
	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	get_hcc_ns(ns);
	ctx->ns = ns;
	kref_init(&ctx->kref);

	return ctx;
}

void ghotplug_ctx_release(struct kref *kref)
{
	struct ghotplug_context *ctx;

	ctx = container_of(kref, struct ghotplug_context, kref);
	put_hcc_ns(ctx->ns);
	kfree(ctx);
}

int init_ghotplug(void)
{
	hcc_ha_wq = create_workqueue("hccHA");
	BUG_ON(hcc_ha_wq == NULL);

	ghotplug_hooks_init();

	ghotplug_add_init();
#ifdef CONFIG_HCC_GHOTPLUG_DEL
	ghotplug_remove_init();
#endif
	ghotplug_failure_init();
	ghotplug_cluster_init();
	ghotplug_namespace_init();
	ghotplug_membership_init();

	return 0;
};

void cleanup_ghotplug(void)
{
};
