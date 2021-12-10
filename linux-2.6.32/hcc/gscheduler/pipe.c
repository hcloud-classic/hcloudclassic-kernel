/*
 *  hcc/gscheduler/pipe.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <hcc/gscheduler/global_config.h>
#include <hcc/gscheduler/pipe.h>

void gscheduler_source_init(struct gscheduler_source *source,
			   struct gscheduler_source_type *type)
{
	source->type = type;
	INIT_LIST_HEAD(&source->pub_sub_head);
	spin_lock_init(&source->lock);
}

void gscheduler_sink_init(struct gscheduler_sink *sink,
			 struct gscheduler_sink_type *type)
{
	sink->type = type;
	rcu_assign_pointer(sink->source, NULL);
	INIT_LIST_HEAD(&sink->pub_sub_list);
	sink->subscribed = 0;
	gscheduler_sink_remote_pipe_init(sink);
}

void gscheduler_sink_cleanup(struct gscheduler_sink *sink)
{
	gscheduler_sink_remote_pipe_cleanup(sink);
}

int gscheduler_source_get_value(struct gscheduler_source *source,
			       void *value_p, unsigned int nr,
			       const void *in_value_p, unsigned int in_nr)
{
	struct gscheduler_source_type *type = gscheduler_source_type_of(source);

	if (!type->get_value)
		return -EACCES;
	if (!nr && !in_nr)
		return 0;
	if ((nr && !value_p) || (in_nr && !in_value_p))
		return -EINVAL;

	return type->get_value(source, value_p, nr, in_value_p, in_nr);
}

ssize_t gscheduler_source_show_value(struct gscheduler_source *source, char *page)
{
	struct gscheduler_source_type *type = gscheduler_source_type_of(source);
	ssize_t ret = -EACCES;

	if (type->show_value)
		ret = type->show_value(source, page);

	return ret;
}

/*
 * TODO: perhaps we could relax the rules for in_types: equal or one of them
 * NULL.
 */
int gscheduler_types_compatible(const struct gscheduler_sink_type *sink_type,
			       const struct gscheduler_source_type *source_type)
{
	const struct get_value_types *sink_types = &sink_type->get_value_types;
	const struct get_value_types *source_types =
		&source_type->get_value_types;

	return !(strcmp(sink_types->out_type, source_types->out_type) ||
		 (sink_types->out_type_size != source_types->out_type_size)
		 ||
		 (!sink_types->in_type && source_types->in_type) ||
		 (sink_types->in_type && !source_types->in_type)
		 ||
		 (sink_types->in_type &&
		  (strcmp(sink_types->in_type, source_types->in_type) ||
		   (sink_types->in_type_size != source_types->in_type_size))));
}

void gscheduler_sink_connect(struct gscheduler_sink *sink,
			    struct gscheduler_source *source,
			    int subscribe)
{
	rcu_assign_pointer(sink->source, source);
	if (subscribe) {
		sink->subscribed = 1;
		gscheduler_source_lock(source);
		list_add_rcu(&sink->pub_sub_list, &source->pub_sub_head);
		gscheduler_source_unlock(source);
	}
}

void gscheduler_sink_disconnect(struct gscheduler_sink *sink)
{
	if (sink->subscribed) {
		struct gscheduler_source *source = rcu_dereference(sink->source);
		gscheduler_source_lock(source);
		list_del_rcu(&sink->pub_sub_list);
		gscheduler_source_unlock(source);
		sink->subscribed = 0;
	}
	rcu_assign_pointer(sink->source, NULL);
	gscheduler_sink_remote_pipe_disconnect(sink);
}

struct gscheduler_source *
gscheduler_sink_get_peer_source(struct gscheduler_sink *sink)
{
	return rcu_dereference(sink->source);
}

int gscheduler_sink_subscribed(struct gscheduler_sink *sink)
{
	return sink->subscribed;
}

int gscheduler_source_has_subscribers(struct gscheduler_source *source)
{
	return !list_empty(&source->pub_sub_head);
}

void gscheduler_source_publish(struct gscheduler_source *source)
{
	struct gscheduler_sink *subscriber;

	rcu_read_lock();
	list_for_each_entry_rcu(subscriber,
				&source->pub_sub_head, pub_sub_list)
		subscriber->type->update_value(subscriber, source);
	rcu_read_unlock();
}

int gscheduler_sink_get_value(struct gscheduler_sink *sink,
			     void *value_p, unsigned int nr,
			     const void *in_value_p, unsigned int in_nr)
{
	struct gscheduler_source *peer_source;
	int ret = -EACCES;

	rcu_read_lock();
	peer_source = gscheduler_sink_get_peer_source(sink);
	if (peer_source)
		ret = gscheduler_source_get_value(peer_source,
						 value_p, nr,
						 in_value_p, in_nr);
	rcu_read_unlock();

	return ret;
}
/* Used by inline definition of gscheduler_port_get_value */
EXPORT_SYMBOL(gscheduler_sink_get_value);

ssize_t gscheduler_sink_show_value(struct gscheduler_sink *sink, char *page)
{
	struct gscheduler_source *peer_source;
	ssize_t ret = -EACCES;

	rcu_read_lock();
	peer_source = gscheduler_sink_get_peer_source(sink);
	if (peer_source)
		ret = gscheduler_source_show_value(peer_source, page);
	rcu_read_unlock();

	return ret;
}
/* Used by inline definition of gscheduler_port_show_value */
EXPORT_SYMBOL(gscheduler_sink_show_value);

/* Complete initialization of the value attribute of the pipe type. */
static void value_attr_init(struct configfs_attribute *attr,
			    struct gscheduler_pipe_type *type,
			    const char *name,
			    int readable)
{
	attr->ca_name = name;
	attr->ca_owner = type->item_type.ct_owner;
	attr->ca_mode = 0;
	if (readable)
		attr->ca_mode |= S_IRUGO;
}

static int nr_attrs(struct configfs_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

/* Default pipe attributes are packed right before the attributes array. */
int gscheduler_pipe_type_init(struct gscheduler_pipe_type *type,
			     struct configfs_attribute **attrs)
{
	struct configfs_attribute *next_value_attr;
	struct configfs_attribute **tmp_attrs;
	struct configfs_attribute **next_attr;
	int nr_custom_attrs;
	void *attrs_mem;
	size_t attrs_size;
	int err = -ENOMEM;

	nr_custom_attrs = nr_attrs(attrs);
	attrs_size = (nr_custom_attrs + 1) * sizeof(*tmp_attrs);
	if (type->source_type) {
		/* Store the "value" attribute at the beginning */
		attrs_size += sizeof(struct configfs_attribute);
		/* One more element in the attributes array */
		attrs_size += sizeof(*tmp_attrs);
	}
	if (type->sink_type) {
		/*
		 * Store the "collected_value" attribute right after the "value"
		 * attribute
		 */
		attrs_size += sizeof(struct configfs_attribute);
		/* One more element in the attributes array */
		attrs_size += sizeof(*tmp_attrs);
	}
	attrs_mem = kmalloc(attrs_size, GFP_KERNEL);
	if (!attrs_mem)
		goto err_attrs;

	/* Reserve memory for the value attributes */
	next_value_attr = attrs_mem;
	if (type->source_type)
		next_value_attr++;
	if (type->sink_type)
		next_value_attr++;
	tmp_attrs = (struct configfs_attribute **) next_value_attr;

	/* Initialize the value attributes */
	next_value_attr = attrs_mem;
	next_attr = tmp_attrs;
	if (type->source_type) {
		value_attr_init(next_value_attr,
				type,
				"value",
				!!type->source_type->show_value);

		*next_attr = next_value_attr;
		next_value_attr++;
		next_attr++;
	}
	if (type->sink_type) {
		value_attr_init(next_value_attr, type, "collected_value", 1);

		*next_attr = next_value_attr;
		next_value_attr++;
		next_attr++;
	}

	/* initialize configfs attributes. */
	memcpy(next_attr, attrs, nr_custom_attrs * sizeof(*next_attr));
	next_attr[nr_custom_attrs] = NULL;

	/* initialize configfs type. */
	type->item_type.ct_attrs = tmp_attrs;
	return 0;

err_attrs:
	return err;
}

void gscheduler_pipe_type_cleanup(struct gscheduler_pipe_type *type)
{
	struct configfs_attribute *prev_value_attr;

	prev_value_attr = (struct configfs_attribute *)
		type->item_type.ct_attrs;
	type->item_type.ct_attrs = NULL;

	if (type->sink_type)
		prev_value_attr--;
	if (type->source_type)
		prev_value_attr--;
	kfree(prev_value_attr);
}

int gscheduler_pipe_init(struct gscheduler_pipe *pipe,
			const char *name,
			struct gscheduler_pipe_type *type,
			struct gscheduler_source *source,
			struct gscheduler_sink *sink,
			struct config_group **default_groups)
{
	/* initialize config_group */
	memset(&pipe->config, 0, sizeof(pipe->config));
	/*
	 * Should be able to report allocation errors, but has no return
	 * type...
	 */
	config_group_init_type_name(&pipe->config, name, &type->item_type);
	pipe->config.default_groups = default_groups;

	pipe->source = source;
	pipe->sink = sink;

	return 0;
}

static inline int is_source_value_attr(struct gscheduler_pipe_type *type,
				       struct configfs_attribute *attr)
{
	return type->source_type && attr == type->item_type.ct_attrs[0];
}

static inline int is_sink_value_attr(struct gscheduler_pipe_type *type,
				     struct configfs_attribute *attr)
{
	return type->sink_type
		&& ((!type->source_type && attr == type->item_type.ct_attrs[0])
		    || (type->source_type
			&& attr == type->item_type.ct_attrs[1]));
}

ssize_t gscheduler_pipe_show_attribute(struct gscheduler_pipe *pipe,
				      struct configfs_attribute *attr,
				      char *page,
				      int *handled)
{
	struct gscheduler_pipe_type *type = gscheduler_pipe_type_of(pipe);
	int is_source_attr;
	int is_sink_attr = 0; /* Only to prevent gcc from warning */
	ssize_t ret = -EACCES;

	/* The only attributes are values. */

	is_source_attr = is_source_value_attr(type, attr);
	if (is_source_attr)
		ret = gscheduler_source_show_value(pipe->source, page);
	else {
		is_sink_attr = is_sink_value_attr(type, attr);
		if (is_sink_attr)
			ret = gscheduler_sink_show_value(pipe->sink, page);
	}

	*handled = is_source_attr || is_sink_attr;
	return ret;
}

ssize_t gscheduler_pipe_store_attribute(struct gscheduler_pipe *pipe,
				       struct configfs_attribute *attr,
				       const char *page, size_t count,
				       int *handled)
{
	struct gscheduler_pipe_type *type = gscheduler_pipe_type_of(pipe);
	*handled = is_source_value_attr(type, attr)
		|| is_sink_value_attr(type, attr);
	return -EACCES;
}
