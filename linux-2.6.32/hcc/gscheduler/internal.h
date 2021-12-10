#ifndef __GSCHEDULER_INTERNAL_H__
#define __GSCHEDULER_INTERNAL_H__

#include <linux/configfs.h>

struct ghotplug_context;

#define PROBES_NAME "probes"
#define GSCHEDULERS_NAME "gschedulers"

extern struct configfs_subsystem hcc_gscheduler_subsys;

struct global_config_attrs;

struct global_config_item_operations {
	struct configfs_item_operations config;
	struct global_config_attrs *(*global_attrs)(struct config_item *item);
};

extern struct global_config_item_operations probe_source_global_item_ops;
extern struct global_config_item_operations probe_global_item_ops;
extern struct global_config_item_operations port_global_item_ops;
extern struct global_config_item_operations policy_global_item_ops;
extern struct global_config_item_operations process_set_global_item_ops;
extern struct global_config_item_operations gscheduler_global_item_ops;

/**
 * Checks that item is a probe source subdir of a probe.
 * @author Innogrid HCC
 *
 * @param item		pointer to the config_item to check
 */
int is_gscheduler_probe_source(struct config_item *item);

struct gscheduler_policy;
struct gscheduler_policy *gscheduler_policy_new(const char *name);
void gscheduler_policy_drop(struct gscheduler_policy *policy);

static inline int nr_def_groups(struct config_group *def_groups[])
{
	int n = 0;
	if (def_groups)
		while (def_groups[n])
			n++;
	return n;
}

/* Subsystems initializers / cleaners */

int hcc_gsched_info_start(void);
void hcc_gsched_info_exit(void);

int global_lock_start(void);
void global_lock_exit(void);

int string_list_start(void);
void string_list_exit(void);

int global_config_start(void);
void global_config_exit(void);
int global_config_add(struct ghotplug_context *ctx);
int global_config_post_add(struct ghotplug_context *ctx);

int remote_pipe_start(void);
void remote_pipe_exit(void);

struct config_group *gscheduler_probe_start(void);
void gscheduler_probe_exit(void);

struct config_group *gscheduler_start(void);
void gscheduler_exit(void);
int gscheduler_post_add(struct ghotplug_context *ctx);

#endif /* __GSCHEDULER_INTERNAL_H__ */
