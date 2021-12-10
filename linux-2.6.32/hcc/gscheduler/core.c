/*
 *  hcc/gscheduler/core.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/configfs.h>
#include <hcc/ghotplug.h>
#include <hcc/gscheduler/process_set.h>

#include "internal.h"

static struct config_item_type hcc_gscheduler_type = {
	.ct_owner = THIS_MODULE,
};

struct configfs_subsystem hcc_gscheduler_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "hcc_gscheduler",
			.ci_type = &hcc_gscheduler_type,
		}
	}
};

static int add(struct ghotplug_context *ctx)
{
	return global_config_add(ctx);
}

static int ghotplug_notifier(struct notifier_block *nb,
			    ghotplug_event_t event,
			    void *data)
{
	struct ghotplug_context *ctx;
	int err;

	switch(event){
	case GHOTPLUG_NOTIFY_ADD:
		ctx = data;
		err = add(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

static int post_add(struct ghotplug_context *ctx)
{
	int err;

	err = gscheduler_post_add(ctx);
	if (err)
		return err;
	return global_config_post_add(ctx);
}

static int post_ghotplug_notifier(struct notifier_block *nb,
				 ghotplug_event_t event,
				 void *data)
{
	struct ghotplug_context *ctx;
	int err;

	switch(event){
	case GHOTPLUG_NOTIFY_ADD:
		ctx = data;
		err = post_add(ctx);
		break;
	default:
		err = 0;
		break;
	}

	if (err)
		return notifier_from_errno(err);
	return NOTIFY_OK;
}

int init_gscheduler(void)
{
	int ret;
	struct config_group **defs = NULL;

	/* per task informations framework */
	ret = hcc_gsched_info_start();
	if (ret)
		goto err_hcc_gsched_info;

	/* initialize global mechanisms to replicate configfs operations */
	ret = global_lock_start();
	if (ret)
		goto err_global_lock;
	ret = string_list_start();
	if (ret)
		goto err_string_list;
	ret = global_config_start();
	if (ret)
		goto err_global_config;
	ret = remote_pipe_start();
	if (ret)
		goto err_remote_pipe;

	/* initialize and register configfs subsystem. */
	config_group_init(&hcc_gscheduler_subsys.su_group);
	mutex_init(&hcc_gscheduler_subsys.su_mutex);

	/* add probes, sched_policies to gscheduler. */
	defs = kcalloc(3, sizeof (struct config_group *), GFP_KERNEL);

	if (defs == NULL) {
		printk(KERN_ERR "[%s] error: cannot allocate memory!\n",
			"gscheduler_module_init");
		ret = -ENOMEM;
		goto err_kcalloc;
	}

	/* initialize probes and scheduling policies subgroup. */
	defs[0] = gscheduler_probe_start();
	defs[1] = gscheduler_start();
	defs[2] = NULL;

	if (defs[0]==NULL || defs[1]==NULL) {
		printk(KERN_ERR "[%s] error: Could not initialize one of the"
			" subgroups!\n", __PRETTY_FUNCTION__);
		ret = -EFAULT;
		goto err_init;
	}

	hcc_gscheduler_subsys.su_group.default_groups = defs;

	ret = configfs_register_subsystem(&hcc_gscheduler_subsys);

	if (ret) {
		printk(KERN_ERR "[%s] error %d: cannot register subsystem!\n",
			__PRETTY_FUNCTION__, ret);
		goto err_register;
	}

	ret = register_ghotplug_notifier(ghotplug_notifier,
					GHOTPLUG_PRIO_SCHED);
	if (ret)
		goto err_ghotplug;

	ret = register_ghotplug_notifier(post_ghotplug_notifier,
					GHOTPLUG_PRIO_SCHED_POST);
	if (ret)
		goto err_ghotplug;

	printk(KERN_INFO "gscheduler initialization succeeded!\n");
	return 0;

err_ghotplug:

	configfs_unregister_subsystem(&hcc_gscheduler_subsys);
err_register:

err_init:
	if (defs[1])
		gscheduler_exit();
	if (defs[0])
		gscheduler_probe_exit();
	kfree(defs);
err_kcalloc:

	remote_pipe_exit();
err_remote_pipe:

	global_config_exit();
err_global_config:

	string_list_exit();
err_string_list:

	global_lock_exit();
err_global_lock:

	hcc_gsched_info_exit();
err_hcc_gsched_info:

	return ret;
}

void cleanup_gscheduler(void)
{
}
