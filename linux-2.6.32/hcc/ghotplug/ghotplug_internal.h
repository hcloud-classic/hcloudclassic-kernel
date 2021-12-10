#ifndef __GHOTPLUG_INTERNAL__
#define __GHOTPLUG_INTERNAL__

extern struct kobject *hcc_ghotplugsys;

extern struct workqueue_struct *hcc_ha_wq;

extern struct work_struct fail_work;

int hooks_start(void);
void hooks_stop(void);

struct ghotplug_context;

int do_cluster_start(struct ghotplug_context *ctx);
int __nodes_add(struct ghotplug_context *ctx);

int repair_monitor(void);
void update_heartbeat(void);

int hcc_nodemask_copy_from_user(hcc_nodemask_t *dst, __hcc_nodemask_t *from);

int hcc_set_cluster_creator(void __user *arg);

int heartbeat_init(void);
int ghotplug_add_init(void);
int ghotplug_remove_init(void);
int ghotplug_failure_init(void);
int ghotplug_hooks_init(void);
int ghotplug_cluster_init(void);
int ghotplug_namespace_init(void);

int ghotplug_membership_init(void);
void ghotplug_membership_cleanup(void);

#endif
