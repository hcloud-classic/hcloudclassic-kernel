/*
 *  hcc/gscheduler/probe.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <hcc/hcc_flags.h>
#include <hcc/gscheduler/pipe.h>
#include <hcc/gscheduler/global_config.h>
#include <hcc/gscheduler/probe.h>

#include "internal.h"

/**
 * This structure represents pluggable probes for measuring various system
 * characteristics (e.g. CPU usage, memory usage, ...). User can implement these
 * probes as separate Linux kernel modules and inserts them dynamcally into
 * kernel. By doing this, it extends set of resource properties that are being
 * measured.
 * The probe module is loaded by issuing
 * "mkdir /config/hcc_gscheduler/probes/<probe_name>" command. When probe is
 * loaded it starts measuring its system characteristic. Probes can also be
 * deactivated by issuing "rmdir /config/hcc_gscheduler/probes/<probe_name>"
 * command from user space.
 *
 * @author Innogrid HCC
 */
struct gscheduler_probe {
	struct config_group group; /** representation of probe in ConfigFS. */

	struct list_head list; /** list of registered probes. */

	unsigned long probe_period; /** timeout between subsequent measurements.
				      * Note: here, time is saved in jiffies.*/
	struct delayed_work work; /** work struct for periodically performing
				   * measurements. */

	spinlock_t lock; /** lock for synchronizing probe accesses. */

	struct global_config_item global_item; /** Used by global config
						* subsystem */
	struct global_config_attrs global_attrs;
};

static
inline
struct gscheduler_probe *to_gscheduler_probe(struct config_item *item)
{
	return container_of(to_config_group(item),
			    struct gscheduler_probe, group);
}

static
inline
struct gscheduler_probe_type *
gscheduler_probe_type_of(struct gscheduler_probe *probe)
{
	return container_of(probe->group.cg_item.ci_type,
			    struct gscheduler_probe_type, item_type);
}

static
inline
struct gscheduler_probe_attribute *
to_gscheduler_probe_attribute(struct configfs_attribute *attr)
{
	return container_of(attr, struct gscheduler_probe_attribute, config);
}

static
inline
struct gscheduler_probe_source *
to_gscheduler_probe_source(struct config_item *item)
{
	return container_of(to_gscheduler_pipe(item),
			    struct gscheduler_probe_source, pipe);
}

static
inline
struct gscheduler_probe_source_type *
gscheduler_probe_source_type_of(struct gscheduler_probe_source *probe_source)
{
	return container_of(gscheduler_pipe_type_of(&(probe_source)->pipe),
			    struct gscheduler_probe_source_type, pipe_type);
}

static
inline
struct gscheduler_probe_source_attribute *
to_gscheduler_probe_source_attribute(struct configfs_attribute *attr)
{
	return container_of(attr,
			    struct gscheduler_probe_source_attribute, config);
}

/* a spinlock protecting access to the list of registered probes. */
static DEFINE_SPINLOCK(probes_lock);
/* List of registered probes. */
static LIST_HEAD(probes_list);

void gscheduler_probe_lock(struct gscheduler_probe *probe)
{
	spin_lock(&probe->lock);
}
EXPORT_SYMBOL(gscheduler_probe_lock);

void gscheduler_probe_unlock(struct gscheduler_probe *probe)
{
	spin_unlock(&probe->lock);
}
EXPORT_SYMBOL(gscheduler_probe_unlock);

/**
 * General function for reading probes' ConfigFS attributes.
 * @author Innogrid HCC
 */
static ssize_t gscheduler_probe_attribute_show(struct config_item *item,
					      struct configfs_attribute *attr,
					      char *page)
{
	struct gscheduler_probe_attribute *probe_attr =
		to_gscheduler_probe_attribute(attr);
	struct gscheduler_probe *probe = to_gscheduler_probe(item);
	ssize_t ret = 0;

	if (probe_attr->show) {
		gscheduler_probe_lock(probe);
		ret = probe_attr->show(probe, page);
		gscheduler_probe_unlock(probe);
	}

	return ret;
}

/**
 * General function for storing probes' ConfigFS attributes.
 */
static ssize_t gscheduler_probe_attribute_store(struct config_item *item,
					       struct configfs_attribute *attr,
					       const char *page, size_t count)
{
	struct gscheduler_probe_attribute *probe_attr =
		to_gscheduler_probe_attribute(attr);
	struct gscheduler_probe *probe = to_gscheduler_probe(item);
	struct string_list_object *list;
	ssize_t ret = 0;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;

	if (probe_attr->store) {
		list = global_config_attr_store_begin(item);
		if (IS_ERR(list))
			return PTR_ERR(list);

		gscheduler_probe_lock(probe);
		ret = probe_attr->store(probe, page, count);
		gscheduler_probe_unlock(probe);

		if (ret >= 0)
			ret = global_config_attr_store_end(list,
							   item, attr,
							   page, ret);
		else
			global_config_attr_store_error(list, item);
	}

	return ret;
}

static struct global_config_attrs *probe_global_attrs(struct config_item *item)
{
	return &to_gscheduler_probe(item)->global_attrs;
}

struct global_config_item_operations probe_global_item_ops = {
	.config = {
		.show_attribute = gscheduler_probe_attribute_show,
		.store_attribute = gscheduler_probe_attribute_store,
	},
	.global_attrs = probe_global_attrs,
};

/**
 * Function for reading "probe_period" attribute.
 * @author Innogrid HCC
 */
static ssize_t gscheduler_probe_attr_period_show(struct gscheduler_probe *probe,
						char *page)
{
	ssize_t ret;
	/* print timeout in milliseconds */
	ret = sprintf(page, "%u\n", jiffies_to_msecs(probe->probe_period));
	return ret;
}

/**
 * Function for storing "probe_period" attribute.
 * @author Innogrid HCC
 */
static ssize_t gscheduler_probe_attr_period_store(struct gscheduler_probe *probe,
						 const char *page, size_t count)
{
	unsigned tmp_period;
	char *last_read;

	tmp_period = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;

	probe->probe_period = msecs_to_jiffies(tmp_period);

	return count;
}

/**
 * "probe_period" attribute.
 * @author Innogrid HCC
 */
static GSCHEDULER_PROBE_ATTRIBUTE(gscheduler_probe_attr_period,
				 "probe_period",
				 S_IRUGO | S_IWUSR,
				 gscheduler_probe_attr_period_show,
				 gscheduler_probe_attr_period_store);

/**
 * Determines length of a NULL-terminated array.
 */
static int probe_source_array_length(struct gscheduler_probe_source **sources)
{
	int i;
	if (!sources)
		return 0;
	for (i=0; sources[i] != NULL; i++)
		;
	return i;
}

static inline char *gscheduler_probe_name(struct gscheduler_probe *probe)
{
	return config_item_name(&probe->group.cg_item);
}

static void refresh_subscribers(struct gscheduler_probe *p)
{
	int i;
	struct gscheduler_probe_source *tmp_ps;
	struct gscheduler_probe_source_type *tmp_pst;

	/* check which measurements have changed since last time. */
	for (i = 0; p->group.default_groups[i] != NULL; i++) {
		tmp_ps = to_gscheduler_probe_source(
			&p->group.default_groups[i]->cg_item);
		tmp_pst = gscheduler_probe_source_type_of(tmp_ps);
		if (tmp_pst->has_changed && tmp_pst->has_changed()) {
			/*
			 * if value has changed, run update function
			 * of all the subscribers.
			 */
			gscheduler_probe_unlock(p);
			gscheduler_source_publish(&tmp_ps->source);
			gscheduler_probe_lock(p);
		}
	}
}

/**
 * General function for periodically performing probe measurements.
 */
static void probe_refresh_func(struct work_struct *work)
{
	struct gscheduler_probe *p = container_of(
		container_of(work, struct delayed_work, work),
		struct gscheduler_probe, work);
	struct gscheduler_probe_type *type = gscheduler_probe_type_of(p);

	gscheduler_probe_lock(p);
	if (type->perform_measurement) {
		type->perform_measurement();
		refresh_subscribers(p);
	}
	gscheduler_probe_unlock(p);
	/* schedule next measurement. */
	schedule_delayed_work(&p->work, p->probe_period);
}

void gscheduler_probe_source_lock(struct gscheduler_probe_source *probe_source)
{
	gscheduler_probe_lock(probe_source->parent);
}
EXPORT_SYMBOL(gscheduler_probe_source_lock);

void gscheduler_probe_source_unlock(struct gscheduler_probe_source *probe_source)
{
	gscheduler_probe_unlock(probe_source->parent);
}
EXPORT_SYMBOL(gscheduler_probe_source_unlock);

static void __gscheduler_probe_source_notify_update(struct work_struct *work)
{
	struct gscheduler_probe_source *s =
		container_of(work,
			     struct gscheduler_probe_source, notify_update_work);

	gscheduler_source_publish(&s->source);
}

/**
 * Function that a probe source should call when the value changes and the probe
 * does not have a perform_measurement() method.
 * Does nothing if the probe provides a perform_measurement() method.
 *
 * @param source		Source having been updated
 */
void gscheduler_probe_source_notify_update(struct gscheduler_probe_source *source)
{
	struct gscheduler_probe *p = source->parent;

	if (gscheduler_probe_type_of(p)->perform_measurement)
		return;

	schedule_work(&source->notify_update_work);
}
EXPORT_SYMBOL(gscheduler_probe_source_notify_update);

/**
 * General function for reading probe sources' ConfigFS attributes.
 * @author Innogrid HCC
 */
static
ssize_t gscheduler_probe_source_attribute_show(struct config_item *item,
					      struct configfs_attribute *attr,
					      char *page)
{
	struct gscheduler_probe_source_attribute *source_attr;
	struct gscheduler_probe_source *ps = to_gscheduler_probe_source(item);
	ssize_t ret;
	int handled;

	ret = gscheduler_pipe_show_attribute(&ps->pipe, attr, page, &handled);
	if (!handled) {
		ret = -EACCES;

		source_attr = to_gscheduler_probe_source_attribute(attr);
		if (source_attr->show) {
			gscheduler_probe_source_lock(ps);
			ret = source_attr->show(page);
			gscheduler_probe_source_unlock(ps);
		}
	}

	return ret;
}

/**
 * General function for storing probe sources' ConfigFS attributes.
 * @author Innogrid HCC
 */
static
ssize_t gscheduler_probe_source_attribute_store(struct config_item *item,
					       struct configfs_attribute *attr,
					       const char *page, size_t count)
{
        struct gscheduler_probe_source_attribute *source_attr =
		to_gscheduler_probe_source_attribute(attr);
        struct gscheduler_probe_source *ps = to_gscheduler_probe_source(item);
	struct string_list_object *list;
	ssize_t ret;
	int handled;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;

	list = global_config_attr_store_begin(item);
	if (IS_ERR(list))
		return PTR_ERR(list);

	ret = gscheduler_pipe_store_attribute(&ps->pipe, attr, page, count,
					     &handled);
	if (!handled) {
		ret = -EACCES;
		if (source_attr->store) {
			gscheduler_probe_source_lock(ps);
			ret = source_attr->store(page, count);
			gscheduler_probe_source_unlock(ps);
		}
	}

	if (ret >= 0)
		ret = global_config_attr_store_end(list,
						   item, attr,
						   page, ret);
	else
		global_config_attr_store_error(list, item);

        return ret;
}

static
struct global_config_attrs *probe_source_global_attrs(struct config_item *item)
{
	return &to_gscheduler_probe_source(item)->global_attrs;
}

struct global_config_item_operations probe_source_global_item_ops = {
	.config = {
		.show_attribute = gscheduler_probe_source_attribute_show,
		.store_attribute = gscheduler_probe_source_attribute_store,
	},
	.global_attrs = probe_source_global_attrs,
};

static int probe_source_attribute_array_length(
	struct gscheduler_probe_source_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

/**
 * This function allocates memory and initializes a probe source.
 * @author Innogrid HCC
 *
 * @param type		Type describing the probe source, defined with
 *			GSCHEDULER_PROBE_SOURCE_TYPE
 * @param name		Name of the source's subdirectory in the probe's
 *			directory. Must be unique for a given a probe.
 *
 * @return		Pointer to the created probe_source, or NULL if error
 */
struct gscheduler_probe_source *
gscheduler_probe_source_create(struct gscheduler_probe_source_type *type,
			      const char *name)
{
	struct gscheduler_probe_source *tmp_ps = NULL;
	struct module *owner = type->pipe_type.item_type.ct_owner;
	struct configfs_attribute **tmp_attrs;
	int nr_attrs;
	int err;

	/* fixup type */
	type->pipe_type = (struct gscheduler_pipe_type)
		GSCHEDULER_PIPE_TYPE_INIT(owner,
					 &probe_source_global_item_ops.config,
					 NULL,
					 &type->source_type, NULL);

	nr_attrs = probe_source_attribute_array_length(type->attrs);
	tmp_attrs = NULL;
	if (nr_attrs) {
		int i;

		tmp_attrs = kmalloc((nr_attrs + 1) * sizeof(*tmp_attrs),
				    GFP_KERNEL);
		if (!tmp_attrs)
			goto err_pipe_type;
		for (i = 0; i < nr_attrs; i++)
			tmp_attrs[i] = &type->attrs[i]->config;
		tmp_attrs[nr_attrs] = NULL;
	}
	err = gscheduler_pipe_type_init(&type->pipe_type, tmp_attrs);
	kfree(tmp_attrs);
	if (err)
		goto err_pipe_type;

	tmp_ps = kmalloc(sizeof(*tmp_ps), GFP_KERNEL);
	if (!tmp_ps)
		goto err_source;
	/* initialize gscheduler_probe_source. */
	memset(tmp_ps, 0, sizeof(*tmp_ps));

	gscheduler_source_init(&tmp_ps->source, &type->source_type);
	if (gscheduler_pipe_init(&tmp_ps->pipe, name, &type->pipe_type,
				&tmp_ps->source, NULL, NULL))
		goto err_pipe;
	INIT_WORK(&tmp_ps->notify_update_work,
		  __gscheduler_probe_source_notify_update);

	return tmp_ps;

err_pipe:
	kfree(tmp_ps);
err_source:
	gscheduler_pipe_type_cleanup(&type->pipe_type);
err_pipe_type:
	return NULL;
}

void gscheduler_probe_source_free(struct gscheduler_probe_source *source)
{
	struct gscheduler_probe_source_type *type =
		gscheduler_probe_source_type_of(source);
	gscheduler_pipe_cleanup(&source->pipe);
	gscheduler_source_cleanup(&source->source);
	kfree(source);
	gscheduler_pipe_type_cleanup(&type->pipe_type);
}

/**
 * Checks that item is an source subdir of a probe.
 * @author Innogrid HCC
 *
 * @param item		pointer to the config_item to check
 */
int is_gscheduler_probe_source(struct config_item *item)
{
	return item->ci_type
		&& item->ci_type->ct_item_ops ==
			&probe_source_global_item_ops.config;
}

static void gscheduler_probe_drop(struct global_config_item *);

static struct global_config_drop_operations gscheduler_probe_drop_ops = {
	.drop_func = gscheduler_probe_drop,
	.is_symlink = 0
};

static
int probe_attribute_array_length(struct gscheduler_probe_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

/**
 * This function allocates memory for new probe and initializes it.
 * @author Innogrid HCC
 *
 * @param name          name of the probe. This name must be unique for each
 *			probe.
 * @param attrs         array of probe's attributes.
 * @param ops           pointer to probe's operations.
 * @param owner         pointer to module that implements probe.
 *
 * @return              pointer to newly create probe or NULL if probe creation
 *                      failed.
 */
struct gscheduler_probe *
gscheduler_probe_create(struct gscheduler_probe_type *type,
		       const char *name,
		       struct gscheduler_probe_source **sources,
		       struct config_group *def_groups[])
{
	int num_sources;
	int nr_attrs;
	int nr_groups;
	int i;
	struct config_group **tmp_def = NULL;
	struct configfs_attribute **tmp_attrs = NULL;
	struct gscheduler_probe *tmp_probe = NULL;

	num_sources = probe_source_array_length(sources);
	nr_attrs = probe_attribute_array_length(type->attrs);
	nr_groups = nr_def_groups(def_groups);
	tmp_probe = kmalloc(sizeof(*tmp_probe), GFP_KERNEL);
	/*
	 * allocate 2 more elements in array of pointers: one for
	 * probe_period attribute and one for NULL element which marks
	 * the end of array.
	 */
	tmp_attrs = kmalloc(sizeof(*tmp_attrs) * (nr_attrs + 2), GFP_KERNEL);
	tmp_def = kcalloc(num_sources + nr_groups + 1, sizeof(*tmp_def), GFP_KERNEL);

	if (!tmp_probe || !tmp_attrs || !tmp_def)
		goto out_kmalloc;

	/* initialize attributes */
	for (i = 0; i < nr_attrs; i++)
		tmp_attrs[i] = &type->attrs[i]->config;
	tmp_attrs[nr_attrs] = &gscheduler_probe_attr_period.config;
	tmp_attrs[nr_attrs + 1] = NULL;

	/* initialize default groups */
	for (i=0; i<num_sources; i++) {
		tmp_def[i] = &sources[i]->pipe.config;

		/* set current probe as parent of gscheduler_probe_source. */
		sources[i]->parent = tmp_probe;
	}

	/* append ports to default groups */
	for (i = 0; i < nr_groups; i++)
		tmp_def[num_sources + i] = def_groups[i];

	tmp_def[num_sources + nr_groups] = NULL;

	/* initialize probe type. */
	type->item_type.ct_item_ops = &probe_global_item_ops.config;
	type->item_type.ct_attrs = tmp_attrs;

	/* initialize probe. */
	memset(tmp_probe, 0, sizeof(*tmp_probe));
	config_group_init_type_name(&tmp_probe->group, name, &type->item_type);
	/* Make sure that item is cleaned only when freeing it */
	config_item_get(&tmp_probe->group.cg_item);
	tmp_probe->group.default_groups = tmp_def;
	spin_lock_init(&tmp_probe->lock);
	tmp_probe->probe_period =
		msecs_to_jiffies(GSCHEDULER_PROBE_DEFAULT_PERIOD);
	global_config_item_init(&tmp_probe->global_item,
				&gscheduler_probe_drop_ops);

	return tmp_probe;

out_kmalloc:
	kfree(tmp_probe);
	kfree(tmp_attrs);
	kfree(tmp_def);

	return NULL;
}

/**
 * This function frees all the memory taken by a probe.
 * @author Innogrid HCC
 *
 * @param probe         pointer to probe whose memory we want to free.
 */
void gscheduler_probe_free(struct gscheduler_probe *probe)
{
	/*
	 * We have to do this here because probes cannot guarantee that they
	 * are not working before calling unregister.
	 */
	flush_scheduled_work();
	config_group_put(&probe->group);
	/*
	 * free all the structures that were allocated during
	 * gscheduler_probe_create.
	 */
	kfree(probe->group.default_groups);
	kfree(gscheduler_probe_type_of(probe)->item_type.ct_attrs);
	kfree(probe);
}

/**
 * Finds probe with a given name. Returns NULL if no such probe is found.
 *
 * Assumes probes_lock held.
 */
static struct gscheduler_probe *probe_find(const char *name)
{
        struct list_head *pos;
        struct gscheduler_probe *entry;

        list_for_each(pos, &probes_list) {
                entry = list_entry(pos, struct gscheduler_probe, list);
                if (strcmp(name, gscheduler_probe_name(entry)) == 0)
                        return entry;
        }

        return NULL;
}

/**
 * This function is used for registering probe. This function has to
 * be called at the end of "init_module" function for each probe's module.
 * @author Innogrid HCC
 *
 * @param probe         pointer to the probe we wish to register.
 *
 * @return      0, if probe was successfully registered.
 *              -EEXIST, if probe with same name is already registered.
 */
int gscheduler_probe_register(struct gscheduler_probe *probe)
{
	int ret = 0;

	spin_lock(&probes_lock);
	if (probe_find(gscheduler_probe_name(probe)) != NULL)
		ret = -EEXIST;
	else
		/*
		 * ok, no probe with the same name exists, proceed with
		 * registration
		 */
		list_add(&probe->list, &probes_list);
	spin_unlock(&probes_lock);

	return ret;
}

/**
 * This function is used for removing probe registration. This function has to
 * be called from "cleanup_module" function for each probe's module.
 * @author Innogrid HCC
 *
 * @param probe         pointer to the probe we wish to unregister.
 */
void gscheduler_probe_unregister(struct gscheduler_probe *probe)
{
	spin_lock(&probes_lock);
	list_del(&probe->list);
	spin_unlock(&probes_lock);
}

/**
 * This is a configfs callback function, which is invoked every time user
 * tries to create directory in "/hcc_gscheduler/probes/" subdirectory. It
 * is used for loading probe's module, initializing and activating it.
 *
 * Note: the function is already synchronized since configfs takes care of
 * locking.
 */
static struct config_group *probes_make_group(struct config_group *group,
					      const char *name)
{
	struct config_group *ret;
	struct gscheduler_probe *tmp_probe;
	struct gscheduler_probe_type *type;
	struct string_list_object *global_probes = NULL;
	int err;

	ret = ERR_PTR(-EPERM);
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		goto out;

	if (!(current->flags & PF_KTHREAD)
	    && !IS_HCC_NODE(HCC_FLAGS_RUNNING))
		goto out;

	global_probes = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_probes)) {
		ret = (void *)(global_probes);
		goto out;
	}

	spin_lock(&probes_lock);
	tmp_probe = probe_find(name);
	if (!tmp_probe) {
		spin_unlock(&probes_lock);

		/*
		 * insert probe's module into kernel space.
		 * Note: no module locking is needed, since module is already
		 * locked by "request_module".
		 *
		 * note: all the probes' files have to be copied into
		 * "/lib/modules/<version>/extra" directory and added
		 * to "/lib/modules/<version>/modules.dep" file.
		 */
		request_module("%s", name);

		spin_lock(&probes_lock);
		tmp_probe = probe_find(name);
	}

	/*
	 * if probe's module didn't manage to register itself, abort.
         * this usually implies an error at probe initialization
         * (in "init_module" function) or that module is already loaded
         * in the kernel and has to be manually unloaded first.
	 */
	err = -ENOENT;
	if (!tmp_probe)
		goto err_module;

	/*
	 * configfs does try_module_get a bit too late for us because we will
	 * already have scheduled probe refreshment.
	 */
	err = -EAGAIN;
	if (!try_module_get(tmp_probe->group.cg_item.ci_type->ct_owner))
		goto err_module;
	spin_unlock(&probes_lock);

	global_config_attrs_init_r(&tmp_probe->group);
	err = global_config_make_item_end(global_probes,
					  &group->cg_item,
					  &tmp_probe->global_item,
					  name);
	if (err) {
		global_config_attrs_cleanup_r(&tmp_probe->group);
		module_put(tmp_probe->group.cg_item.ci_type->ct_owner);
		goto err;
	}

	config_group_get(&tmp_probe->group);

	/* perform measurement of resource properties for the first time. */
	type = gscheduler_probe_type_of(tmp_probe);
	if (type->perform_measurement) {
		gscheduler_probe_lock(tmp_probe);
		type->perform_measurement();
		gscheduler_probe_unlock(tmp_probe);
		/* schedule next refreshment. */
		INIT_DELAYED_WORK(&tmp_probe->work, probe_refresh_func);
		schedule_delayed_work(&tmp_probe->work,
				      tmp_probe->probe_period);
	}

	ret = &tmp_probe->group;

out:
	return ret;

err_module:
	spin_unlock(&probes_lock);
	global_config_make_item_error(global_probes, name);
err:
	ret = ERR_PTR(err);
	goto out;
}

/**
 * Callback called by global_config when the probe is globally dropped
 */
static void gscheduler_probe_drop(struct global_config_item *item)
{
	struct gscheduler_probe *p = container_of(item,
						 struct gscheduler_probe,
						 global_item);

	global_config_attrs_cleanup_r(&p->group);
	config_group_put(&p->group);
	module_put(p->group.cg_item.ci_type->ct_owner);
}

static int probes_allow_drop_item(struct config_group *group,
				  struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;
	return 0;
}

/**
 * This is a configfs callback function, which is invoked every time user
 * tries to remove directory in "/hcc_gscheduler/probes/" subdirectory.
 * It is used for deactivating chosen probe.
 *
 * Note: the function is already synchronized since configfs takes care of
 * locking.
 */
static void probes_drop_item(struct config_group *group,
	struct config_item *item)
{
	struct gscheduler_probe *p = to_gscheduler_probe(item);

	if (gscheduler_probe_type_of(p)->perform_measurement)
		cancel_rearming_delayed_work(&p->work);
	global_config_drop(&p->global_item);
}

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct configfs_group_operations probes_group_ops = {
	.make_group = probes_make_group,
	.allow_drop_item = probes_allow_drop_item,
	.drop_item = probes_drop_item,
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_item_type probes_type = {
	.ct_group_ops = &probes_group_ops,
	.ct_owner = THIS_MODULE,
};

/**
 * This struct is ConfigFS-specific. See ConfigFS documentation for its
 * explanation.
 */
static struct config_group probes_group = {
	.cg_item = {
		.ci_namebuf = PROBES_NAME,
		.ci_type = &probes_type,
	},
};

/**
 * Initializes list of probes and all ConfigFS infrastructure.
 * Registers "probes" subdirectory.
 * author Innogrid HCC
 */
struct config_group *gscheduler_probe_start(void)
{
	/* initialize and register configfs subsystem. */
	config_group_init(&probes_group);
	return &probes_group;
}

/**
 * Unregisters "probes" subdirectory and all the ConfigFS infrastructure
 * related to probes.
 * @author Innogrid HCC
 */
void gscheduler_probe_exit(void)
{
}

EXPORT_SYMBOL(gscheduler_probe_register);
EXPORT_SYMBOL(gscheduler_probe_unregister);
EXPORT_SYMBOL(gscheduler_probe_create);
EXPORT_SYMBOL(gscheduler_probe_free);
EXPORT_SYMBOL(gscheduler_probe_source_create);
EXPORT_SYMBOL(gscheduler_probe_source_free);
