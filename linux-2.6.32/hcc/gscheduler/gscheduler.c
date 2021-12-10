/*
 *  hcc/gscheduler/gscheduler.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/configfs.h>
#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/err.h>
#include <hcc/hcc_flags.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/ghotplug.h>
#include <hcc/gscheduler/policy.h>
#include <hcc/gscheduler/process_set.h>
#include <hcc/gscheduler/global_config.h>

#include "internal.h"

/*
 * Structure representing a gscheduler.
 * Created each time a user does mkdir in "gschedulers" subsystem directory,
 * and destroyed after user does rmdir on the matching directory.
 */
struct gscheduler {
	struct config_group group;	 /** configfs reprensentation */
	struct gscheduler_policy *policy; /** scheduling policy attached to this
					  * gscheduler */
	struct process_set *processes;	 /** set of processes managed by this
					  * gscheduler */
	struct config_group *default_groups[2]; /** default subdirs */
	struct global_config_item global_item; /** global_config subsystem */
	struct global_config_attrs global_attrs;

	hcc_nodemask_t node_set;
	unsigned node_set_exclusive:1;
	unsigned node_set_max_fit:1;

	struct list_head list;

	spinlock_t lock;
};

static inline struct gscheduler *to_gscheduler(struct config_item *item)
{
	return container_of(item, struct gscheduler, group.cg_item);
}

#define GSCHEDULER_ATTR_SIZE 4096

struct gscheduler_attribute {
	struct configfs_attribute config;
	ssize_t (*show)(struct gscheduler *,
			char *);
	ssize_t (*store)(struct gscheduler *,
			 const char *,
			 size_t count);
};

static inline
struct gscheduler_attribute *
to_gscheduler_attribute(struct configfs_attribute *attr)
{
	return container_of(attr, struct gscheduler_attribute, config);
}

static LIST_HEAD(gschedulers_head);
static DEFINE_SPINLOCK(gschedulers_list_lock);
static DEFINE_MUTEX(gschedulers_list_mutex);

static hcc_nodemask_t shared_set;

void gscheduler_get(struct gscheduler *gscheduler)
{
	if (gscheduler)
		config_group_get(&gscheduler->group);
}
EXPORT_SYMBOL(gscheduler_get);

void gscheduler_put(struct gscheduler *gscheduler)
{
	if (gscheduler)
		config_group_put(&gscheduler->group);
}
EXPORT_SYMBOL(gscheduler_put);

static inline struct gscheduler *get_parent_gscheduler(struct config_item *item)
{
	struct config_item *gscheduler_item;
	gscheduler_item = config_item_get(item->ci_parent);
	if (gscheduler_item)
		return to_gscheduler(gscheduler_item);
	return NULL;
}

struct gscheduler *
gscheduler_policy_get_gscheduler(struct gscheduler_policy *policy)
{
	return get_parent_gscheduler(&policy->group.cg_item);
}
EXPORT_SYMBOL(gscheduler_policy_get_gscheduler);

struct gscheduler *process_set_get_gscheduler(struct process_set *pset)
{
	return get_parent_gscheduler(&pset->group.cg_item);
}
EXPORT_SYMBOL(process_set_get_gscheduler);

struct gscheduler_policy *
gscheduler_get_gscheduler_policy(struct gscheduler *gscheduler)
{
	struct gscheduler_policy *policy;

	spin_lock(&gscheduler->lock);
	gscheduler_policy_get(gscheduler->policy);
	policy = gscheduler->policy;
	spin_unlock(&gscheduler->lock);

	return policy;
}
EXPORT_SYMBOL(gscheduler_get_gscheduler_policy);

struct process_set *gscheduler_get_process_set(struct gscheduler *gscheduler)
{
	struct process_set *pset;

	spin_lock(&gscheduler->lock);
	process_set_get(gscheduler->processes);
	pset = gscheduler->processes;
	spin_unlock(&gscheduler->lock);

	return pset;
}
EXPORT_SYMBOL(gscheduler_get_process_set);

static inline const hcc_nodemask_t *get_node_set(struct gscheduler *gscheduler)
{
	if (gscheduler->node_set_max_fit) {
		if (gscheduler->node_set_exclusive)
			return &hcc_node_online_map;
		else
			return &shared_set;
	} else {
		return &gscheduler->node_set;
	}
}

static
inline void set_node_set(struct gscheduler *gscheduler, const hcc_nodemask_t *set)
{
	BUG_ON(gscheduler->node_set_max_fit);
	__hcc_nodes_copy(&gscheduler->node_set, set);
}

void gscheduler_get_node_set(struct gscheduler *gscheduler,
			    hcc_nodemask_t *node_set)
{
	spin_lock(&gschedulers_list_lock);
	spin_lock(&gscheduler->lock);
	__hcc_nodes_copy(node_set, get_node_set(gscheduler));
	spin_unlock(&gscheduler->lock);
	spin_unlock(&gschedulers_list_lock);
}
EXPORT_SYMBOL(gscheduler_get_node_set);

static ssize_t gscheduler_show_attribute(struct config_item *item,
				        struct configfs_attribute *attr,
				        char *page)
{
	struct gscheduler_attribute *sa = to_gscheduler_attribute(attr);
	ssize_t ret = -EACCES;
	if (sa->show)
		ret = sa->show(to_gscheduler(item), page);
	return ret;
}

static ssize_t gscheduler_store_attribute(struct config_item *item,
					 struct configfs_attribute *attr,
					 const char *page,
					 size_t count)
{
	struct gscheduler_attribute *sa = to_gscheduler_attribute(attr);
	struct string_list_object *list;
	ssize_t ret = -EACCES;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;

	if (sa->store) {
		list = global_config_attr_store_begin(item);
		if (IS_ERR(list))
			return PTR_ERR(list);

		ret = sa->store(to_gscheduler(item), page, count);

		if (ret >= 0)
			ret = global_config_attr_store_end(list,
							   item, attr,
							   page, ret);
		else
			global_config_attr_store_error(list, item);
	}

	return ret;
}

static void gscheduler_free(struct gscheduler *);

/*
 * Configfs callback when the last reference on a gscheduler is dropped.
 * Destroys the gscheduler.
 */
static void gscheduler_release(struct config_item *item)
{
	struct gscheduler *s = to_gscheduler(item);
	gscheduler_free(s);
}

static
struct global_config_attrs *gscheduler_global_attrs(struct config_item *item)
{
	return &to_gscheduler(item)->global_attrs;
}

struct global_config_item_operations gscheduler_global_item_ops = {
	.config = {
		.show_attribute = gscheduler_show_attribute,
		.store_attribute = gscheduler_store_attribute,
		.release = gscheduler_release,
	},
	.global_attrs = gscheduler_global_attrs,
};

/**
 * Callback called by global_config when the gscheduler_policy of a gscheduler is
 * globally dropped
 */
static void policy_global_drop(struct global_config_item *item)
{
	struct gscheduler_policy *policy =
		container_of(item, struct gscheduler_policy, global_item);
	global_config_attrs_cleanup_r(&policy->group);
	gscheduler_policy_drop(policy);
}

static struct global_config_drop_operations policy_global_drop_ops = {
	.drop_func = policy_global_drop,
	.is_symlink = 0
};

/**
 * This is a configfs callback function, which is invoked every time user tries
 * to create a directory in a gscheduler directory ("gschedulers/<gscheduler>"
 * directories).  It is used for loading scheduling policy's module, creating
 * and activating a new gscheduler_policy having the type matching the new
 * directory name.
 */
static struct config_group *gscheduler_make_group(struct config_group *group,
						 const char *name)
{
	struct gscheduler *s = to_gscheduler(&group->cg_item);
	struct config_group *ret;
	struct gscheduler_policy *policy;
	struct string_list_object *global_policies;
	int err;

	ret = ERR_PTR(-EPERM);
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		goto out;

	/* Cannot manage several scheduling policies yet */
	ret = ERR_PTR(-EBUSY);
	if (s->policy)
		goto out;

	global_policies = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_policies)) {
		ret = (void *)global_policies;
		goto out;
	}

	policy = gscheduler_policy_new(name);
	if (IS_ERR(policy)) {
		err = PTR_ERR(policy);
		goto err_policy;
	}
	global_config_attrs_init_r(&policy->group);
	global_config_item_init(&policy->global_item,
				&policy_global_drop_ops);
	err = global_config_make_item_end(global_policies,
					  &group->cg_item,
					  &policy->global_item,
					  name);
	if (err)
		goto err_global_end;

	spin_lock(&s->lock);
	s->policy = policy;
	spin_unlock(&s->lock);
	ret = &policy->group;

out:
	return ret;

err_policy:
	global_config_make_item_error(global_policies, name);
	ret = ERR_PTR(err);
	goto out;

err_global_end:
	global_config_attrs_cleanup_r(&policy->group);
	gscheduler_policy_drop(policy);
	ret = ERR_PTR(err);
	goto out;
}

static int gscheduler_allow_drop_item(struct config_group *group,
				     struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;
	return 0;
}

/*
 * Configfs callback called when the scheduling policy directory of a gscheduler
 * is removed.
 */
static void gscheduler_drop_item(struct config_group *group,
				struct config_item *item)
{
	struct gscheduler *s = to_gscheduler(&group->cg_item);
	struct gscheduler_policy *p =
		container_of(item, struct gscheduler_policy, group.cg_item);
	spin_lock(&s->lock);
	s->policy = NULL;
	spin_unlock(&s->lock);
	global_config_drop(&p->global_item);
}

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct configfs_group_operations gscheduler_group_ops = {
	.make_group = gscheduler_make_group,
	.allow_drop_item = gscheduler_allow_drop_item,
	.drop_item = gscheduler_drop_item,
};

/* Scheduler attributes */

static ssize_t node_set_show(struct gscheduler *s, char *page)
{
	hcc_nodemask_t set;

	gscheduler_get_node_set(s, &set);
	return hcc_nodelist_scnprintf(page, GSCHEDULER_ATTR_SIZE, set);
}

static int node_set_may_be_exclusive(const struct gscheduler *s,
				     const hcc_nodemask_t *node_set);

static void policy_update_node_set(struct gscheduler *gscheduler,
				   const hcc_nodemask_t *removed_set,
				   const hcc_nodemask_t *added_set)
{
	struct gscheduler_policy *policy;

	policy = gscheduler_get_gscheduler_policy(gscheduler);
	if (policy) {
		gscheduler_policy_update_node_set(policy,
						 get_node_set(gscheduler),
						 removed_set,
						 added_set);
		gscheduler_policy_put(policy);
	}
}

static int do_update_node_set(struct gscheduler *s,
			      const hcc_nodemask_t *new_set,
			      bool max_fit)
{
	hcc_nodemask_t removed_set, added_set;
	const hcc_nodemask_t *old_set;
	struct gscheduler_policy *policy = NULL;
	int err = -EBUSY;

	mutex_lock(&gschedulers_list_mutex);
	spin_lock(&gschedulers_list_lock);

	if (max_fit) {
		if (s->node_set_exclusive)
			new_set = &hcc_node_online_map;
		else
			new_set = &shared_set;
	} else if (!new_set) {
		new_set = get_node_set(s);
	}

	old_set = get_node_set(s);
	hcc_nodes_andnot(removed_set, *old_set, *new_set);
	hcc_nodes_andnot(added_set, *new_set, *old_set);

	if (s->node_set_exclusive) {
		if (!node_set_may_be_exclusive(s, new_set))
			goto unlock;
		hcc_nodes_andnot(shared_set, shared_set, added_set);
		hcc_nodes_or(shared_set, shared_set, removed_set);
	} else {
		if (!hcc_nodes_subset(*new_set, shared_set))
			goto unlock;
	}
	err = 0;

	spin_lock(&s->lock);
	s->node_set_max_fit = max_fit;
	if (!max_fit)
		set_node_set(s, new_set);
	policy = s->policy;
	gscheduler_policy_get(policy);
	spin_unlock(&s->lock);
unlock:
	spin_unlock(&gschedulers_list_lock);

	if (!err)
		policy_update_node_set(s, &removed_set, &added_set);
	mutex_unlock(&gschedulers_list_mutex);

	return err;
}

static
ssize_t node_set_store(struct gscheduler *s, const char *page, size_t count)
{
	hcc_nodemask_t new_set;
	int err;
	ssize_t ret;

	err = hcc_nodelist_parse(page, new_set);
	if (err) {
		ret = err;
	} else {
		if (hcc_nodes_subset(new_set, hcc_node_online_map)) {
			err = do_update_node_set(s, &new_set, false);
			ret = err ? err : count;
		} else {
			ret = -EINVAL;
		}
	}
	return ret;
}

static struct gscheduler_attribute node_set = {
	.config = {
		.ca_name = "node_set",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = node_set_show,
	.store = node_set_store
};

static ssize_t node_set_exclusive_show(struct gscheduler *s, char *page)
{
	return sprintf(page, "%u", s->node_set_exclusive);
}

static int node_set_may_be_exclusive(const struct gscheduler *s,
			    const hcc_nodemask_t *node_set)
{
	struct gscheduler *pos;

	list_for_each_entry(pos, &gschedulers_head, list)
		if (pos != s
		    && (pos->node_set_exclusive || !pos->node_set_max_fit)
		    && hcc_nodes_intersects(*node_set, *get_node_set(pos)))
			return 0;
	return 1;
}

static int make_node_set_exclusive(struct gscheduler *s)
{
	const hcc_nodemask_t *set = get_node_set(s);
	int err = 0;

	if (s->node_set_exclusive)
		goto out;

	if (!node_set_may_be_exclusive(s, set)) {
		err = -EBUSY;
		goto out;
	}

	hcc_nodes_andnot(shared_set, shared_set, *set);
	s->node_set_exclusive = 1;

out:
	return err;
}

static void make_node_set_not_exclusive(struct gscheduler *s)
{
	if (s->node_set_exclusive) {
		hcc_nodes_or(shared_set, shared_set, *get_node_set(s));
		s->node_set_exclusive = 0;
	}
}

static
ssize_t
node_set_exclusive_store(struct gscheduler *s, const char *page, size_t count)
{
	int new_state;
	char *last_read;
	hcc_nodemask_t added, removed;
	bool changed;
	int err;

	new_state = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	mutex_lock(&gschedulers_list_mutex);
	spin_lock(&gschedulers_list_lock);
	if (new_state) {
		hcc_nodes_clear(added);
		hcc_nodes_copy(removed, *get_node_set(s));
		changed = !s->node_set_exclusive;
		err = make_node_set_exclusive(s);
		changed = changed && !err;
	} else {
		hcc_nodes_copy(added, *get_node_set(s));
		hcc_nodes_clear(removed);
		changed = s->node_set_exclusive;
		make_node_set_not_exclusive(s);
		err = 0;
	}
	spin_unlock(&gschedulers_list_lock);

	if (changed) {
		list_for_each_entry(s, &gschedulers_head, list)
			if (s->node_set_max_fit)
				policy_update_node_set(s, &removed, &added);
	}
	mutex_unlock(&gschedulers_list_mutex);

	return err ? err : count;
}

static struct gscheduler_attribute node_set_exclusive = {
	.config = {
		.ca_name = "node_set_exclusive",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = node_set_exclusive_show,
	.store = node_set_exclusive_store
};

static ssize_t node_set_max_fit_show(struct gscheduler *s, char *page)
{
	return sprintf(page, "%u", s->node_set_max_fit);
}

static
ssize_t
node_set_max_fit_store(struct gscheduler *s, const char *page, size_t count)
{
	int new_state;
	char *last_read;
	int err;

	new_state = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	err = do_update_node_set(s, NULL, new_state);
	return err ? err : count;
}

static struct gscheduler_attribute node_set_max_fit = {
	.config = {
		.ca_name = "node_set_max_fit",
		.ca_owner = THIS_MODULE,
		.ca_mode = S_IRUGO | S_IWUSR,
	},
	.show = node_set_max_fit_show,
	.store = node_set_max_fit_store
};

static struct configfs_attribute *gscheduler_attrs[] = {
	&node_set.config,
	&node_set_exclusive.config,
	&node_set_max_fit.config,
	NULL
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_item_type gscheduler_type = {
	.ct_owner = THIS_MODULE,
	.ct_item_ops = &gscheduler_global_item_ops.config,
	.ct_group_ops = &gscheduler_group_ops,
	.ct_attrs = gscheduler_attrs
};

/**
 * Create a gscheduler with no processes attached and no scheduling policy.
 *
 * @param name		Name of the directory containing the gscheduler
 *
 * @return		pointer to the new gscheduler, or
 *			NULL if error
 */
static struct gscheduler *gscheduler_create(const char *name)
{
	struct gscheduler *s = kmalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		return NULL;
	memset(&s->group, 0, sizeof(s->group));
	config_group_init_type_name(&s->group, name, &gscheduler_type);
	s->policy = NULL;
	s->processes = process_set_create();
	if (!s->processes) {
		config_group_put(&s->group);
		return NULL;
	}
	s->node_set_exclusive = 0;
	s->node_set_max_fit = 1;
	s->default_groups[0] = &s->processes->group;
	s->default_groups[1] = NULL;
	s->group.default_groups = s->default_groups;
	spin_lock_init(&s->lock);
	return s;
}

/**
 * Free a gscheduler
 */
static void gscheduler_free(struct gscheduler *gscheduler)
{
	kfree(gscheduler);
}

static void gscheduler_deactivate(struct gscheduler *gscheduler)
{
	spin_lock(&gscheduler->lock);
	process_set_drop(gscheduler->processes);
	gscheduler->processes = NULL;
	spin_unlock(&gscheduler->lock);
}

/* Global_config callback when the gscheduler directory is globally removed */
static void gscheduler_drop(struct global_config_item *item)
{
	struct gscheduler *gscheduler =
		container_of(item, struct gscheduler, global_item);

	global_config_attrs_cleanup_r(&gscheduler->group);

	mutex_lock(&gschedulers_list_mutex);
	spin_lock(&gschedulers_list_lock);
	list_del(&gscheduler->list);
	make_node_set_not_exclusive(gscheduler);
	spin_unlock(&gschedulers_list_lock);
	mutex_unlock(&gschedulers_list_mutex);

	config_group_put(&gscheduler->group);
}

static struct global_config_drop_operations gscheduler_drop_ops = {
	.drop_func = gscheduler_drop,
	.is_symlink = 0
};

/*
 * Configfs callback called when a user creates a directory under "gschedulers"
 * subsystem directory. This creates a new gscheduler.
 */
static struct config_group *gschedulers_make_group(struct config_group *group,
						  const char *name)
{
	struct config_group *ret;
	struct gscheduler *s;
	struct string_list_object *global_names;
	int err;

	ret = ERR_PTR(-EPERM);
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		goto out;

	if (!(current->flags & PF_KTHREAD)
	    && !IS_HCC_NODE(HCC_FLAGS_RUNNING))
		goto out;

	global_names = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_names)) {
		ret = (void *)global_names;
		goto out;
	}

	err = -ENOMEM;
	s = gscheduler_create(name);
	if (!s)
		goto err_gscheduler;
	global_config_attrs_init_r(&s->group);
	global_config_item_init(&s->global_item, &gscheduler_drop_ops);
	err = __global_config_make_item_commit(global_names,
					       &group->cg_item,
					       &s->global_item,
					       name);
	if (err)
		goto err_global_end;
	mutex_lock(&gschedulers_list_mutex);
	spin_lock(&gschedulers_list_lock);
	list_add(&s->list, &gschedulers_head);
	spin_unlock(&gschedulers_list_lock);
	mutex_unlock(&gschedulers_list_mutex);
	__global_config_make_item_end(global_names);

	ret = &s->group;

out:
	return ret;

err_gscheduler:
	global_config_make_item_error(global_names, name);
	ret = ERR_PTR(err);
	goto out;

err_global_end:
	__global_config_make_item_end(global_names);
	global_config_attrs_cleanup_r(&s->group);
	gscheduler_deactivate(s);
	config_group_put(&s->group);
	ret = ERR_PTR(err);
	goto out;
}

static int gschedulers_allow_drop_item(struct config_group *group,
				      struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;
	return 0;
}

/* Configfs callback when a gscheduler's directory is removed */
static void gschedulers_drop_item(struct config_group *group,
				 struct config_item *item)
{
	struct gscheduler *s = to_gscheduler(item);

	gscheduler_deactivate(s);
	global_config_drop(&s->global_item);
}

static struct configfs_group_operations gschedulers_group_ops = {
	.make_group = gschedulers_make_group,
	.allow_drop_item = gschedulers_allow_drop_item,
	.drop_item = gschedulers_drop_item,
};

static struct config_item_type gschedulers_type = {
	.ct_owner = THIS_MODULE,
	.ct_group_ops = &gschedulers_group_ops,
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_group gschedulers_group = {
	.cg_item = {
		.ci_namebuf = GSCHEDULERS_NAME,
		.ci_type = &gschedulers_type,
	},
};

int gscheduler_post_add(struct ghotplug_context *ctx)
{
	const hcc_nodemask_t *added = &ctx->node_set.v;
	hcc_nodemask_t removed = HCC_NODE_MASK_NONE;
	struct gscheduler *s;

	mutex_lock(&gschedulers_list_mutex);

	list_for_each_entry(s, &gschedulers_head, list)
		if (s->node_set_exclusive && s->node_set_max_fit) {
			policy_update_node_set(s, &removed, added);
			goto unlock;
		}

	spin_lock(&gschedulers_list_lock);
	hcc_nodes_or(shared_set, shared_set, *added);
	spin_unlock(&gschedulers_list_lock);

	list_for_each_entry(s, &gschedulers_head, list)
		if (s->node_set_max_fit)
			policy_update_node_set(s, &removed, added);

unlock:
	mutex_unlock(&gschedulers_list_mutex);

	return 0;
}

/**
 * Initializes the "gschedulers" subsystem directory.
 * @author Innogrid HCC
 */
struct config_group *gscheduler_start(void)
{
	/* initialize configfs entry */
	config_group_init(&gschedulers_group);
	return &gschedulers_group;
}

void gscheduler_exit(void)
{
	printk(KERN_WARNING "[%s] WARNING: loosing memory!\n",
	       __PRETTY_FUNCTION__);
}
