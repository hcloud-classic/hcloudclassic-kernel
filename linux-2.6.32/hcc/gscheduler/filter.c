/*
 *  hcc/gscheduler/filter.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <hcc/sys/types.h>
#include <hcc/gscheduler/pipe.h>
#include <hcc/gscheduler/port.h>
#include <hcc/gscheduler/filter.h>

static int gscheduler_filter_attribute_array_length(
	struct gscheduler_filter_attribute **attrs)
{
	int nr = 0;
	if (attrs)
		while (attrs[nr])
			nr++;
	return nr;
}

int gscheduler_filter_type_register(struct gscheduler_filter_type *type)
{
	struct configfs_attribute **tmp_attrs = NULL;
	int nr_attrs, i;
	int err;

	if (!type->source_type.get_value
	    || !type->port_type.new || !type->port_type.destroy)
		return -EINVAL;

	nr_attrs = gscheduler_filter_attribute_array_length(type->attrs);
	if (nr_attrs) {
		err = -ENOMEM;
		tmp_attrs = kmalloc(sizeof(*tmp_attrs) * (nr_attrs + 1),
				    GFP_KERNEL);
		if (!tmp_attrs)
			goto err_attrs;
		for (i = 0; i < nr_attrs; i++)
			tmp_attrs[i] = &type->attrs[i]->port_attr.config;
		tmp_attrs[nr_attrs] = NULL;
	}
	err = gscheduler_port_type_register(&type->port_type, tmp_attrs);
	kfree(tmp_attrs);

out:
	return err;
err_attrs:
	goto out;
}
EXPORT_SYMBOL(gscheduler_filter_type_register);

void gscheduler_filter_type_unregister(struct gscheduler_filter_type *type)
{
	gscheduler_port_type_unregister(&type->port_type);
}
EXPORT_SYMBOL(gscheduler_filter_type_unregister);

int gscheduler_filter_init(struct gscheduler_filter *filter,
			  const char *name,
			  struct gscheduler_filter_type *type,
			  struct config_group **default_groups)
{
	gscheduler_source_init(&filter->source, &type->source_type);
	return gscheduler_port_init(&filter->port, name, &type->port_type,
				   &filter->source,
				   default_groups);
}
EXPORT_SYMBOL(gscheduler_filter_init);

void gscheduler_filter_cleanup(struct gscheduler_filter *filter)
{
	gscheduler_port_cleanup(&filter->port);
	gscheduler_source_cleanup(&filter->source);
}
EXPORT_SYMBOL(gscheduler_filter_cleanup);

int gscheduler_filter_simple_source_get_value(struct gscheduler_source *source,
					     void *value_p, unsigned int nr,
					     const void *in_value_p,
					     unsigned int in_nr)
{
	struct gscheduler_filter *filter;
	filter = container_of(source, struct gscheduler_filter, source);
	return gscheduler_port_get_value(&filter->port,
					value_p, nr, in_value_p, in_nr);
}
EXPORT_SYMBOL(gscheduler_filter_simple_source_get_value);

ssize_t
gscheduler_filter_simple_source_show_value(struct gscheduler_source *source,
					  char *page)
{
	struct gscheduler_filter *filter;
	filter = container_of(source, struct gscheduler_filter, source);
	return gscheduler_port_show_value(&filter->port, page);
}
EXPORT_SYMBOL(gscheduler_filter_simple_source_show_value);

void gscheduler_filter_simple_sink_update_value(struct gscheduler_sink *sink,
					       struct gscheduler_source *source)
{
	struct gscheduler_filter *filter;
	filter = container_of(sink, struct gscheduler_filter, port.sink);
	gscheduler_source_publish(&filter->source);
}
EXPORT_SYMBOL(gscheduler_filter_simple_sink_update_value);
