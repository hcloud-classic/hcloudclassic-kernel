/*
 *  hcc/gscheduler/filters/threshold_filter.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <hcc/gscheduler/filter.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Innogrid HCC");
MODULE_DESCRIPTION("Filter to propagate updates of values above a threshold");

struct threshold_filter {
	struct gscheduler_filter filter;
	unsigned long threshold __attribute__((aligned(sizeof(unsigned long))));
};

/*
 * The threshold attribute is not protected by gscheduler_filter_lock() since
 * atomic memory access is sufficient.
 */

static inline
struct threshold_filter *to_threshold_filter(struct gscheduler_filter *filter)
{
	return container_of(filter, struct threshold_filter, filter);
}

DEFINE_GSCHEDULER_FILTER_ATTRIBUTE_SHOW(threshold, filter, attr, page)
{
	struct threshold_filter *f = to_threshold_filter(filter);
	return sprintf(page, "%lu", f->threshold);
}

DEFINE_GSCHEDULER_FILTER_ATTRIBUTE_STORE(threshold, filter, attr, page, count)
{
	struct threshold_filter *f = to_threshold_filter(filter);
	unsigned long new_value;
	char *last_read;

	new_value = simple_strtoul(page, &last_read, 0);
	if (last_read - page + 1 < count
	    || (last_read[1] != '\0' && last_read[1] != '\n'))
		return -EINVAL;
	f->threshold = new_value;
	return count;
}

static BEGIN_GSCHEDULER_FILTER_ATTRIBUTE(threshold_attr, threshold, 0666),
	.GSCHEDULER_FILTER_ATTRIBUTE_SHOW(threshold),
	.GSCHEDULER_FILTER_ATTRIBUTE_STORE(threshold),
END_GSCHEDULER_FILTER_ATTRIBUTE(threshold);

static struct gscheduler_filter_attribute *threshold_attrs[] = {
	&threshold_attr,
	NULL
};

DEFINE_GSCHEDULER_FILTER_UPDATE_VALUE(threshold_filter, filter)
{
	struct threshold_filter *f = to_threshold_filter(filter);
	unsigned long value;
	ssize_t ret;

	ret = gscheduler_filter_simple_get_value(filter, &value, 1);
	if (ret > 0 && value >= f->threshold)
		gscheduler_filter_simple_update_value(filter);
}

/* Forward declaration */
static struct gscheduler_filter_type threshold_filter_type;

DEFINE_GSCHEDULER_FILTER_NEW(threshold_filter, name)
{
	struct threshold_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_f;
	err = gscheduler_filter_init(&f->filter, name, &threshold_filter_type,
				    NULL);
	if (err)
		goto err_filter;
	f->threshold = 0;

	return &f->filter;

err_filter:
	kfree(f);
err_f:
	return NULL;
}

DEFINE_GSCHEDULER_FILTER_DESTROY(threshold_filter, filter)
{
	struct threshold_filter *f = to_threshold_filter(filter);
	gscheduler_filter_cleanup(filter);
	kfree(f);
}

static BEGIN_GSCHEDULER_FILTER_TYPE(threshold_filter),
	.GSCHEDULER_FILTER_UPDATE_VALUE(threshold_filter),
	.GSCHEDULER_FILTER_SOURCE_VALUE_TYPE(threshold_filter, unsigned long),
	.GSCHEDULER_FILTER_PORT_VALUE_TYPE(threshold_filter, unsigned long),
	.GSCHEDULER_FILTER_ATTRIBUTES(threshold_filter, threshold_attrs),
END_GSCHEDULER_FILTER_TYPE(threshold_filter);

static int threshold_start(void)
{
	return gscheduler_filter_type_register(&threshold_filter_type);
}

static void threshold_exit(void)
{
	gscheduler_filter_type_unregister(&threshold_filter_type);
}

module_init(threshold_start);
module_exit(threshold_exit);
