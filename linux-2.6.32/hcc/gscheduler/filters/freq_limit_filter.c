/*
 *  hcc/gscheduler/filters/freq_limit_filter.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <hcc/gscheduler/filter.h>
#include <hcc/gscheduler/port.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Innogrid HCC");
MODULE_DESCRIPTION("Filter to limit the frequency of events");

struct config_group;

struct freq_limit_filter {
	struct gscheduler_filter filter;
	u64 min_interval_nsec;
	struct gscheduler_port last_event_port;
	struct gscheduler_port events_on_going_port;
	struct config_group *default_groups[3];
};

static inline
struct freq_limit_filter *to_freq_limit_filter(struct gscheduler_filter *filter)
{
	return container_of(filter, struct freq_limit_filter, filter);
}

DEFINE_GSCHEDULER_FILTER_ATTRIBUTE_SHOW(min_interval, filter, attr, page)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);
	u64 min_interval_nsec;

	/*
	 * Access to 64 bits is not atomic on 32 bits x86 so locking is
	 * required.
	 */
	gscheduler_filter_lock(filter);
	min_interval_nsec = f->min_interval_nsec;
	gscheduler_filter_unlock(filter);
	return sprintf(page, "%llu\n", min_interval_nsec);
}

DEFINE_GSCHEDULER_FILTER_ATTRIBUTE_STORE(min_interval, filter, attr, buffer, size)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);
	char *pos;
	u64 min_interval;

	min_interval = simple_strtoull(buffer, &pos, 10);
	if (((*pos == '\n' && pos - buffer == size - 1)
	     || (*pos == '\0' && pos - buffer == size))
	    && pos != buffer) {
		gscheduler_filter_lock(filter);
		f->min_interval_nsec = min_interval;
		gscheduler_filter_unlock(filter);
		return size;
	}
	return -EINVAL;
}

static BEGIN_GSCHEDULER_FILTER_ATTRIBUTE(min_interval_attr, min_interval, 0664),
	.GSCHEDULER_FILTER_ATTRIBUTE_SHOW(min_interval),
	.GSCHEDULER_FILTER_ATTRIBUTE_STORE(min_interval),
END_GSCHEDULER_FILTER_ATTRIBUTE(min_interval);

static struct gscheduler_filter_attribute *freq_limit_attrs[] = {
	&min_interval_attr,
	NULL
};

static BEGIN_GSCHEDULER_PORT_TYPE(last_event_port),
	.GSCHEDULER_PORT_VALUE_TYPE(last_event_port, ktime_t),
END_GSCHEDULER_PORT_TYPE(last_event_port);
static BEGIN_GSCHEDULER_PORT_TYPE(events_on_going_port),
	.GSCHEDULER_PORT_VALUE_TYPE(events_on_going_port, int),
END_GSCHEDULER_PORT_TYPE(events_on_going_port);

DEFINE_GSCHEDULER_FILTER_UPDATE_VALUE(freq_limit_filter, filter)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);
	ktime_t last_event;
	int on_going;
	ktime_t now;
	struct timespec now_ts;
	u64 interval;
	u64 min_interval;
	int ret;

	gscheduler_filter_lock(filter);
	min_interval = f->min_interval_nsec;
	gscheduler_filter_unlock(filter);

	if (!min_interval)
		goto propagate;

	ret = gscheduler_port_get_value(&f->last_event_port,
				       &last_event, 1, NULL, 0);
	if (ret < 1)
		return;

	ktime_get_ts(&now_ts);
	now = timespec_to_ktime(now_ts);

	interval = (u64) ktime_to_ns(ktime_sub(now, last_event));
	if (interval < min_interval)
		return;

	ret = gscheduler_port_get_value(&f->events_on_going_port,
				       &on_going, 1, NULL, 0);
	if (ret == 1 && on_going)
		return;

propagate:
	gscheduler_filter_simple_update_value(filter);
}

/* Forward declaration */
static struct gscheduler_filter_type freq_limit_filter_type;

DEFINE_GSCHEDULER_FILTER_NEW(freq_limit_filter, name)
{
	struct freq_limit_filter *f = kmalloc(sizeof(*f), GFP_KERNEL);
	int err;

	if (!f)
		goto err_freq_limit;
	f->min_interval_nsec = 0;
	err = gscheduler_port_init(&f->last_event_port, "last_event",
				  &last_event_port_type, NULL, NULL);
	if (err)
		goto err_last_event;
	err = gscheduler_port_init(&f->events_on_going_port, "events_on_going",
				  &events_on_going_port_type, NULL, NULL);
	if (err)
		goto err_events_on_going;
	f->default_groups[0] = gscheduler_port_config_group(&f->last_event_port);
	f->default_groups[1] =
		gscheduler_port_config_group(&f->events_on_going_port);
	f->default_groups[2] = NULL;
	err = gscheduler_filter_init(&f->filter, name, &freq_limit_filter_type,
				    f->default_groups);
	if (err)
		goto err_filter;

	return &f->filter;

err_filter:
	gscheduler_port_cleanup(&f->events_on_going_port);
err_events_on_going:
	gscheduler_port_cleanup(&f->last_event_port);
err_last_event:
	kfree(f);
err_freq_limit:
	return NULL;
}

DEFINE_GSCHEDULER_FILTER_DESTROY(freq_limit_filter, filter)
{
	struct freq_limit_filter *f = to_freq_limit_filter(filter);

	gscheduler_filter_cleanup(&f->filter);
	gscheduler_port_cleanup(&f->events_on_going_port);
	gscheduler_port_cleanup(&f->last_event_port);
	kfree(f);
}

static BEGIN_GSCHEDULER_FILTER_TYPE(freq_limit_filter),
	.GSCHEDULER_FILTER_UPDATE_VALUE(freq_limit_filter),
	.GSCHEDULER_FILTER_SOURCE_VALUE_TYPE(freq_limit_filter, unsigned long),
	.GSCHEDULER_FILTER_PORT_VALUE_TYPE(freq_limit_filter, unsigned long),
	.GSCHEDULER_FILTER_ATTRIBUTES(freq_limit_filter, freq_limit_attrs),
END_GSCHEDULER_FILTER_TYPE(freq_limit_filter);

int freq_limit_start(void)
{
	int err;

	err = gscheduler_port_type_init(&last_event_port_type, NULL);
	if (err)
		goto err_last_event;
	err = gscheduler_port_type_init(&events_on_going_port_type, NULL);
	if (err)
		goto err_events_on_going;
	err = gscheduler_filter_type_register(&freq_limit_filter_type);
	if (err)
		goto err_register;
out:
	return err;

err_register:
	gscheduler_port_type_cleanup(&events_on_going_port_type);
err_events_on_going:
	gscheduler_port_type_cleanup(&last_event_port_type);
err_last_event:
	goto out;
}

void freq_limit_exit(void)
{
	gscheduler_filter_type_unregister(&freq_limit_filter_type);
	gscheduler_port_type_cleanup(&events_on_going_port_type);
	gscheduler_port_type_cleanup(&last_event_port_type);
}

module_init(freq_limit_start);
module_exit(freq_limit_exit);
