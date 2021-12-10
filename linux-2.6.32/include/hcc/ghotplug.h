#ifndef __GHOTPLUG__
#define __GHOTPLUG__

#include <linux/kref.h>
#include <hcc/hcc_nodemask.h>

enum {
	GHOTPLUG_PRIO_SCHED_POST,
	GHOTPLUG_PRIO_MEMBERSHIP_ONLINE, // should be done after distributed services management
	GHOTPLUG_PRIO_SCHED,
	GHOTPLUG_PRIO_GPM,
	GHOTPLUG_PRIO_PROCFS,
	GHOTPLUG_PRIO_GDM,
	GHOTPLUG_PRIO_BARRIER,
	GHOTPLUG_PRIO_GRPC,
	GHOTPLUG_PRIO_MEMBERSHIP_PRESENT,
	GHOTPLUG_PRIO_MAX // must be the last one
};

typedef enum {
	GHOTPLUG_NOTIFY_ADD,
	GHOTPLUG_NOTIFY_REMOVE,
	GHOTPLUG_NOTIFY_REMOVE_LOCAL, // node side: local operations
	GHOTPLUG_NOTIFY_REMOVE_ADVERT, // cluster side
	GHOTPLUG_NOTIFY_REMOVE_DISTANT, // node side: remote operations
	GHOTPLUG_NOTIFY_REMOVE_ACK, // cluster side
	GHOTPLUG_NOTIFY_FAIL,
} ghotplug_event_t;

enum {
	GHOTPLUG_NODE_INVALID,
	GHOTPLUG_NODE_POSSIBLE,
	GHOTPLUG_NODE_PRESENT,
	GHOTPLUG_NODE_ONLINE
};

struct ghotplug_node_set {
	int subclusterid;
	hcc_nodemask_t v;
};

struct ghotplug_context {
	struct hcc_namespace *ns;
	struct ghotplug_node_set node_set;
	struct kref kref;
};

struct notifier_block;

struct ghotplug_context *ghotplug_ctx_alloc(struct hcc_namespace *ns);
void ghotplug_ctx_release(struct kref *kref);

static inline void ghotplug_ctx_get(struct ghotplug_context *ctx)
{
	kref_get(&ctx->kref);
}

static inline void ghotplug_ctx_put(struct ghotplug_context *ctx)
{
	kref_put(&ctx->kref, ghotplug_ctx_release);
}

int register_ghotplug_notifier(int (*notifier_call)(struct notifier_block *, ghotplug_event_t, void *),
			      int priority);

struct ghotplug_node_set;
int ghotplug_add_notify(struct ghotplug_context *ctx, ghotplug_event_t event);
int ghotplug_remove_notify(struct ghotplug_node_set *nodes_set,
			  ghotplug_event_t event);
int ghotplug_failure_notify(struct ghotplug_node_set *nodes_set,
			   ghotplug_event_t event);

void hook_register(void *hk, void *f);

struct universe_elem {
	int state;
	int subid;
};
extern struct universe_elem universe[HCC_MAX_NODES];

void hcc_node_reachable(hcc_node_t nodeid);
void hcc_node_unreachable(hcc_node_t nodeid);

void hcc_node_arrival(hcc_node_t nodeid);
void hcc_node_departure(hcc_node_t nodeid);

#endif
