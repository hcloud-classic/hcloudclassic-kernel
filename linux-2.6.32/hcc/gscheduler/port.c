/*
 *  hcc/gscheduler/port.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/module.h>
#include <linux/nsproxy.h>
#include <linux/configfs.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <hcc/gscheduler/global_config.h>
#include <hcc/gscheduler/pipe.h>
#include <hcc/gscheduler/port.h>

#include "internal.h"

/**
 * Get the gscheduler_port_type structure embedding a config_item_type
 *
 * @param type		pointer to a config_item_type embedded in a
 *			gscheduler_port_type
 *
 * @return		pointer to the gscheduler_port_type embedding type
 */
static inline
struct gscheduler_port_type *
to_gscheduler_port_type(struct config_item_type *type)
{
	return container_of(to_gscheduler_pipe_type(type),
			    struct gscheduler_port_type, pipe_type);
}

/**
 * Get the gscheduler_port structure embedding a config_item
 *
 * @param type		pointer to a config_item embedded in a gscheduler_port
 *
 * @return		pointer to the gscheduler_port embedding item
 */
static inline
struct gscheduler_port *to_gscheduler_port(struct config_item *item)
{
	return container_of(to_gscheduler_pipe(item),
			    struct gscheduler_port, pipe);
}

/**
 * Get the gscheduler_port_type of a gscheduler_port
 *
 * @param port		port which type to get
 *
 * @return		type of the port
 */
static inline
struct gscheduler_port_type *gscheduler_port_type_of(struct gscheduler_port *port)
{
	return container_of(gscheduler_pipe_type_of(&port->pipe),
			    struct gscheduler_port_type, pipe_type);
}

static inline struct config_group *config_group_of(struct gscheduler_port *port)
{
	return &port->pipe.config;
}

static inline
struct global_config_item *global_item_of(struct gscheduler_port *port)
{
	return &port->global_item;
}

static inline
struct gscheduler_port_attribute *
to_gscheduler_port_attribute(struct configfs_attribute *attr)
{
	return container_of(attr, struct gscheduler_port_attribute, config);
}

/* List of registered port types */
static LIST_HEAD(types_head);
/* Lock protecting the port types list */
static DEFINE_SPINLOCK(types_lock);

/* Assumes types_lock held */
static struct gscheduler_port_type *port_type_find(const char *name);

/**
 * General function for reading gscheduler_port's ConfigFS attributes. Falls back
 * to the gscheduler_pipe attributes methods the gscheduler_pipe attributes, or to
 * the port attribute show() operation for custom attributes.
 * @author Innogrid HCC
 */
static ssize_t gscheduler_port_attribute_show(struct config_item *item,
					     struct configfs_attribute *attr,
					     char *page)
{
	struct gscheduler_port *port = to_gscheduler_port(item);
	ssize_t ret;
	int handled;

	ret = gscheduler_pipe_show_attribute(&port->pipe, attr, page, &handled);
	if (!handled) {
		struct gscheduler_port_attribute *port_attr =
			to_gscheduler_port_attribute(attr);
		ret = -EACCES;

		if (port_attr->show)
			ret = port_attr->show(port, port_attr, page);
	}

	return ret;
}

/**
 * General function for storing gscheduler_port's ConfigFS attributes. Falls back
 * to the store() method of the port attribute if not called for gscheduler_pipe
 * attribute.
 */
static ssize_t gscheduler_port_attribute_store(struct config_item *item,
					      struct configfs_attribute *attr,
					      const char *page, size_t count)
{
	struct gscheduler_port *port = to_gscheduler_port(item);
	struct string_list_object *list;
        ssize_t ret;
	int handled;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;

	list = global_config_attr_store_begin(item);
	if (IS_ERR(list))
		return PTR_ERR(list);

	ret = gscheduler_pipe_store_attribute(&port->pipe, attr, page, count, &handled);
	if (!handled) {
		struct gscheduler_port_attribute *port_attr =
			to_gscheduler_port_attribute(attr);
		ret = -EACCES;

		if (port_attr->store)
			ret = port_attr->store(port, port_attr, page, count);
        }

	if (ret >= 0)
		ret = global_config_attr_store_end(list,
						   item, attr,
						   page, ret);
	else
		global_config_attr_store_error(list, item);

        return ret;
}

/**
 * Connect a gscheduler_port's gscheduler_sink to another gscheduler_pipe having a
 * source
 *
 * @param port		port having a sink to connect
 * @param peer_pipe	pipe which source to connect to the port's sink
 */
static void connect(struct gscheduler_port *port,
		    struct gscheduler_pipe *peer_pipe)
{
	int subscribe;
	/*
	 * Only subscribe if we are sure that port can push notifications up to
	 * the terminating sink. This avoids having useless notification call
	 * chains.
	 */
	/*
	 * Testing whether port has subscribers is safe as long as subscribers
	 * do not unsubscribe before destroying port. Ports and super-classes
	 * behave so.
	 */
	subscribe = port->sink.type->update_value
		&& (!port->pipe.source
		    || gscheduler_source_has_subscribers(port->pipe.source));
	gscheduler_sink_connect(&port->sink, peer_pipe->source, subscribe);
	rcu_assign_pointer(port->peer_pipe, peer_pipe);
}

/**
 * Disconnect a gscheduler_port's gscheduler_sink from its connected source
 *
 * @param port		port having the sink to disconnect
 */
static void disconnect(struct gscheduler_port *port)
{
	rcu_assign_pointer(port->peer_pipe, NULL);
	gscheduler_sink_disconnect(&port->sink);
	synchronize_rcu();
}

/**
 * Tests whether a port's gscheduler_sink is connected to a source.
 * Must be called under rcu_read_lock()
 *
 * @param port		the port to test
 *
 * @return		true iff a source is connected to the port's sink
 */
static int connected(struct gscheduler_port *port)
{
	return !!gscheduler_sink_get_peer_source(&port->sink);
}

/**
 * Callback called by global_config when the link/item of the peer source is
 * globally dropped
 */
static void gscheduler_port_peer_source_drop(struct global_config_item *item)
{
	struct gscheduler_port *port =
		container_of(item, struct gscheduler_port, global_item);

	config_group_put(config_group_of(port));
}

static void gscheduler_port_drop_peer_source(struct gscheduler_port *port)
{
	disconnect(port);
	global_config_drop(global_item_of(port));
}

static struct global_config_drop_operations gscheduler_port_link_drop_ops = {
	.drop_func = gscheduler_port_peer_source_drop,
	.is_symlink = 1
};

/**
 * checks if source config_item is a probe source
 */
/* TODO: maybe should also allow (type-compatible) ports */
static int is_link_target_valid(struct config_item *target)
{
	return is_gscheduler_probe_source(target);
}

/**
 * Configfs callback called every time symbolic link creation is initiated from
 * a gscheduler_port directory.
 */
static int gscheduler_port_allow_link(struct config_item *src,
				     struct config_item *target,
				     const char *name)
{
	struct gscheduler_port *src_port = to_gscheduler_port(src);
	struct gscheduler_pipe *peer_pipe;
	struct string_list_object *list;
	int err;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;

	/* At most one source connected at a given time */
	rcu_read_lock();
	if (connected(src_port)) {
		rcu_read_unlock();
		return -EPERM;
	}
	rcu_read_unlock();

	if (!is_link_target_valid(target))
		return -EINVAL;

	if (!gscheduler_types_compatible(
		    src_port->sink.type,
		    to_gscheduler_pipe_type(target->ci_type)->source_type))
		return -EINVAL;

	list = global_config_allow_link_begin(src, name, target);
	if (IS_ERR(list)) {
		err = PTR_ERR(list);
		goto err_global_begin;
	}

	config_item_get(src); /* To make sure a reference remains until drop is
			       * finished. */

	global_config_item_init(global_item_of(src_port),
				&gscheduler_port_link_drop_ops);
	err = global_config_allow_link_end(list,
						src,
						global_item_of(src_port),
						name,
						target);
	if (err)
		goto err_global_end;

	peer_pipe = to_gscheduler_pipe(target);
	connect(src_port, peer_pipe);
	/*
	 * always read source's value when the notification chain becomes
	 * complete.
	 */
	if (gscheduler_sink_subscribed(&src_port->sink))
		src_port->sink.type->update_value(&src_port->sink, peer_pipe->source);
out:
	return err;

err_global_end:
	config_item_put(src);
err_global_begin:
	goto out;
}

static int gscheduler_port_allow_drop_link(struct config_item *src,
					  struct config_item *target)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;
	return 0;
}

/**
 * Configfs callback called every time symbolic link removal is initiated from
 * a gscheduler_port directory
 */
static int gscheduler_port_drop_link(struct config_item *src,
				    struct config_item *target)
{
	struct gscheduler_port *src_port = to_gscheduler_port(src);
	gscheduler_port_drop_peer_source(src_port);
	return 0;
}

static void gscheduler_port_release(struct config_item *item);

static struct global_config_attrs *port_global_attrs(struct config_item *item)
{
	return &to_gscheduler_port(item)->global_attrs;
}

struct global_config_item_operations port_global_item_ops = {
	.config = {
		.release = gscheduler_port_release,
		.show_attribute = gscheduler_port_attribute_show,
		.store_attribute = gscheduler_port_attribute_store,
		.allow_link = gscheduler_port_allow_link,
		.allow_drop_link = gscheduler_port_allow_drop_link,
		.drop_link = gscheduler_port_drop_link,
	},
	.global_attrs = port_global_attrs,
};

static struct global_config_drop_operations gscheduler_port_item_drop_ops = {
	.drop_func = gscheduler_port_peer_source_drop,
};

/*
 * Configfs callback called when user does mkdir in a gscheduler_port
 * directory
 */
static struct config_group *
gscheduler_port_make_group(struct config_group *group, const char *name)
{
	struct gscheduler_port *port = to_gscheduler_port(&group->cg_item);
	struct gscheduler_port_type *peer_type;
	struct gscheduler_port *peer_port;
	struct module *peer_owner = NULL;
	struct string_list_object *global_list = NULL;
	int err;

	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return ERR_PTR(-EPERM);

	/* At most one source connected at a given time */
	rcu_read_lock();
	if (connected(port)) {
		rcu_read_unlock();
		return ERR_PTR(-EBUSY);
	}
	rcu_read_unlock();

	global_list = global_config_make_item_begin(&group->cg_item, name);
	if (IS_ERR(global_list)) {
		err = PTR_ERR(global_list);
		goto err_global_begin;
	}

	/* Find the port type having the requested name */
	spin_lock(&types_lock);
	peer_type = port_type_find(name);
	if (!peer_type) {
		spin_unlock(&types_lock);

		request_module("%s", name);

		spin_lock(&types_lock);
		peer_type = port_type_find(name);
	}
	if (peer_type) {
		peer_owner = peer_type->pipe_type.item_type.ct_owner;
		if (!peer_type->new || !try_module_get(peer_owner))
			peer_type = NULL;
	}
	spin_unlock(&types_lock);
	err = -ENOENT;
	if (!peer_type)
		goto err_type;

	err = -EINVAL;
	if (!gscheduler_types_compatible(port->sink.type,
					peer_type->pipe_type.source_type))
		goto err_port;

	/* Create the new port */
	err = -ENOMEM;
	peer_port = peer_type->new(name);
	if (!peer_port)
		goto err_port;

	global_config_attrs_init_r(config_group_of(peer_port));
	config_group_get(group); /* To make sure a reference remains until drop
				  * is finished. */
	global_config_item_init(global_item_of(port),
				&gscheduler_port_item_drop_ops);
	err = global_config_make_item_end(global_list,
					  &group->cg_item,
					  global_item_of(port),
					  name);
	if (err) {
		config_group_put(group);
		global_config_attrs_cleanup_r(config_group_of(peer_port));
		peer_type->destroy(peer_port);
		module_put(peer_owner);
		return ERR_PTR(err);
	}

	/* Connect the parent port's sink to the new port's source */
	connect(port, &peer_port->pipe);

	return config_group_of(peer_port);

err_port:
	module_put(peer_owner);
err_type:
	global_config_make_item_error(global_list, name);
err_global_begin:
	return ERR_PTR(err);
}

static int gscheduler_port_allow_drop_item(struct config_group *group,
					  struct config_item *item)
{
	if (!(current->flags & PF_KTHREAD) && !current->nsproxy->hcc_ns)
		return -EPERM;
	return 0;
}

/*
 * Configfs callback called when user does rmdir in a gscheduler port.
 * Initiates the destruction of the child port.
 */
static void gscheduler_port_drop_item(struct config_group *group,
				     struct config_item *item)
{
	struct gscheduler_port *port = to_gscheduler_port(&group->cg_item);

	global_config_attrs_cleanup_r(to_config_group(item));
	gscheduler_port_drop_peer_source(port);
	config_item_put(item);
}

static struct configfs_group_operations port_group_ops = {
	.make_group = gscheduler_port_make_group,
	.allow_drop_item = gscheduler_port_allow_drop_item,
	.drop_item = gscheduler_port_drop_item,
};

int gscheduler_port_init(struct gscheduler_port *port,
			const char *name,
			struct gscheduler_port_type *type,
			struct gscheduler_source *source,
			struct config_group **default_groups)
{
	int err;

	gscheduler_sink_init(&port->sink, &type->sink_type);
	err = gscheduler_pipe_init(&port->pipe, name, &type->pipe_type,
				  source, &port->sink, default_groups);
	if (err)
		return err;
	port->peer_pipe = NULL;

	return 0;
}
EXPORT_SYMBOL(gscheduler_port_init);

void gscheduler_port_cleanup(struct gscheduler_port *port)
{
	gscheduler_pipe_cleanup(&port->pipe);
	gscheduler_sink_cleanup(&port->sink);
}
EXPORT_SYMBOL(gscheduler_port_cleanup);

/**
 * Called by configfs when the last reference to a gscheduler_port is dropped
 */
static void gscheduler_port_release(struct config_item *item)
{
	struct gscheduler_port *port = to_gscheduler_port(item);
	struct gscheduler_port_type *type = gscheduler_port_type_of(port);
	struct module *owner = type->pipe_type.item_type.ct_owner;

	if (type->destroy)
		type->destroy(port);
	module_put(owner);
}

/* Assumes types_lock held */
static struct gscheduler_port_type *port_type_find(const char *name)
{
	struct gscheduler_port_type *type;
	list_for_each_entry(type, &types_head, list)
		if (!strcmp(type->name, name))
			return type;
	return NULL;
}

int gscheduler_port_type_init(struct gscheduler_port_type *type,
			     struct configfs_attribute **attrs)
{
	struct gscheduler_source_type *source_type = type->pipe_type.source_type;
	struct module *owner = type->pipe_type.item_type.ct_owner;

	/* Fixup type */
	type->pipe_type = (struct gscheduler_pipe_type)
		GSCHEDULER_PIPE_TYPE_INIT(owner,
					 &port_global_item_ops.config,
					 &port_group_ops,
					 source_type,
					 &type->sink_type);
	return gscheduler_pipe_type_init(&type->pipe_type, attrs);
}
EXPORT_SYMBOL(gscheduler_port_type_init);

void gscheduler_port_type_cleanup(struct gscheduler_port_type *type)
{
	gscheduler_pipe_type_cleanup(&type->pipe_type);
}
EXPORT_SYMBOL(gscheduler_port_type_cleanup);

int gscheduler_port_type_register(struct gscheduler_port_type *type,
				 struct configfs_attribute **attrs)
{
	int err;

	err = gscheduler_port_type_init(type, attrs);
	if (err)
		goto out;

	err = -EEXIST;
	spin_lock(&types_lock);
	if (!port_type_find(type->name)) {
		list_add_tail(&type->list, &types_head);
		err = 0;
	}
	spin_unlock(&types_lock);
	if (err)
		goto err_add;

out:
	return err;
err_add:
	gscheduler_port_type_cleanup(type);
	goto out;
}
EXPORT_SYMBOL(gscheduler_port_type_register);

/* Must be called at module unload only */
void gscheduler_port_type_unregister(struct gscheduler_port_type *type)
{
	spin_lock(&types_lock);
	list_del(&type->list);
	spin_unlock(&types_lock);

	gscheduler_port_type_cleanup(type);
}
EXPORT_SYMBOL(gscheduler_port_type_unregister);

int gscheduler_port_get_remote_value(struct gscheduler_port *port,
				    hcc_node_t node,
				    void *value_p, unsigned int nr,
				    const void *in_value_p,
				    unsigned int in_nr)
{
	struct gscheduler_pipe *peer_pipe;
	int ret = -EACCES;

	rcu_read_lock();
	peer_pipe = rcu_dereference(port->peer_pipe);
	if (peer_pipe) {
		struct gscheduler_pipe_type *peer_type;

		peer_type = gscheduler_pipe_type_of(peer_pipe);
		/*
		 * If the peer pipe is a port, forward down until a
		 * get_remote_value() method is defined or a source not being a
		 * port is reached.
		 */
		if (peer_type->item_type.ct_item_ops == &port_global_item_ops.config) {
			struct gscheduler_port *peer_port =
				container_of(peer_pipe,
					     typeof(*peer_port), pipe);
			struct gscheduler_port_type *peer_port_type =
				gscheduler_port_type_of(peer_port);
			port_get_remote_value_t *cb;

			cb = peer_port_type->get_remote_value;
			if (!cb)
				cb = gscheduler_port_get_remote_value;
			ret = cb(peer_port, node,
				 value_p, nr,
				 in_value_p, in_nr);
		} else {
			ret = gscheduler_pipe_get_remote_value(
				&port->sink, peer_pipe,	node,
				value_p, nr,
				in_value_p, in_nr);
		}
	}
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(gscheduler_port_get_remote_value);
