/*
 *  hcc/gscheduler/policies/echo_policy.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <hcc/gscheduler/policy.h>
#include <hcc/gscheduler/port.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Innogrid HCC");
MODULE_DESCRIPTION("Policy that displays collected values");

struct echo_policy {
	struct gscheduler_policy policy;
	struct gscheduler_port port_mem_free;
	struct gscheduler_port port_mem_total;
};

static
ssize_t
gscheduler_policy_attr_echo_show(struct gscheduler_policy *item, char *page)
{
	ssize_t ret = 0;

	ret = sprintf(page, "calling gscheduler_policy_attr_echo_show!\n");

	return ret;
}

static struct gscheduler_policy_attribute echo_attr = {
	.attr = {
		.ca_owner = THIS_MODULE,
		.ca_name = "echo_attr",
		.ca_mode = S_IRUGO,
	},
	.show = gscheduler_policy_attr_echo_show,
};

static struct gscheduler_policy_attribute *echo_policy_attrs[] = {
	&echo_attr,
	NULL,
};

/* DEFINE_GSCHEDULER_PORT_UPDATE_VALUE(port_mem_free, port) */
/* { */
/*         unsigned long mem_free; */

/*         if (gscheduler_port_get_value(port, &mem_free, 1, NULL, 0) > 0) { */
/*                 printk(KERN_INFO "echo_policy: mem_free=%lu\n", mem_free); */
/*         } */
/*         else { */
/*                 printk(KERN_ERR "echo_policy: cannot read mem_free\n"); */
/*         } */
/* } */

static BEGIN_GSCHEDULER_PORT_TYPE(port_mem_free),
/*	.GSCHEDULER_PORT_UPDATE_VALUE(port_mem_free), */
	.GSCHEDULER_PORT_VALUE_TYPE(port_mem_free, unsigned long),
END_GSCHEDULER_PORT_TYPE(port_mem_free);

DEFINE_GSCHEDULER_PORT_UPDATE_VALUE(port_mem_total, port)
{
	unsigned long mem_total;

	if (gscheduler_port_get_value(port, &mem_total, 1, NULL, 0) > 0) {
		printk(KERN_INFO "echo_policy: mem_total=%lu\n", mem_total);
	}
	else {
		printk(KERN_ERR "echo_policy: cannot read mem_total\n");
	}
}

static BEGIN_GSCHEDULER_PORT_TYPE(port_mem_total),
	.GSCHEDULER_PORT_UPDATE_VALUE(port_mem_total),
	.GSCHEDULER_PORT_VALUE_TYPE(port_mem_total, unsigned long),
END_GSCHEDULER_PORT_TYPE(port_mem_total);

static struct gscheduler_policy *echo_policy_new(const char *name);
static void echo_policy_destroy(struct gscheduler_policy *policy);

static struct gscheduler_policy_operations echo_policy_ops = {
	.new = echo_policy_new,
	.destroy = echo_policy_destroy,
};

static GSCHEDULER_POLICY_TYPE(echo_policy_type, "echo_policy",
			     &echo_policy_ops, echo_policy_attrs);

static struct gscheduler_policy *echo_policy_new(const char *name)
{
	struct echo_policy *p;
	struct config_group *def_groups[3];
	int err;

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		goto err_echo_policy;

	err = gscheduler_port_init(&p->port_mem_free, "port_mem_free",
				  &port_mem_free_type, NULL, NULL);
	if (err)
		goto err_mem_free;
	err = gscheduler_port_init(&p->port_mem_total, "port_mem_total",
				  &port_mem_total_type, NULL, NULL);
	if (err)
		goto err_mem_total;

	/* initialize default memory groups. */
	def_groups[0] = gscheduler_port_config_group(&p->port_mem_free);
	def_groups[1] = gscheduler_port_config_group(&p->port_mem_total);
	def_groups[2] = NULL;

	err = gscheduler_policy_init(&p->policy, name, &echo_policy_type,
				    def_groups);
	if (err)
		goto err_policy;

	return &p->policy;

err_policy:
	gscheduler_port_cleanup(&p->port_mem_total);
err_mem_total:
	gscheduler_port_cleanup(&p->port_mem_free);
err_mem_free:
	kfree(p);
err_echo_policy:
	printk(KERN_ERR "error: echo_policy creation failed!\n");
	return NULL;
}

static void echo_policy_destroy(struct gscheduler_policy *policy)
{
	struct echo_policy *p =
		container_of(policy, struct echo_policy, policy);
	gscheduler_policy_cleanup(policy);
	gscheduler_port_cleanup(&p->port_mem_free);
	gscheduler_port_cleanup(&p->port_mem_total);
	kfree(p);
}

int init_module(void)
{
	int err;

	err = gscheduler_port_type_init(&port_mem_free_type, NULL);
	if (err)
		goto err_mem_free;
	err = gscheduler_port_type_init(&port_mem_total_type, NULL);
	if (err)
		goto err_mem_total;
	err = gscheduler_policy_type_register(&echo_policy_type);
	if (err)
		goto err_register;
out:
	return err;

err_register:
	gscheduler_port_type_cleanup(&port_mem_total_type);
err_mem_total:
	gscheduler_port_type_cleanup(&port_mem_free_type);
err_mem_free:
	goto out;
}

void cleanup_module(void)
{
	gscheduler_policy_type_unregister(&echo_policy_type);
	gscheduler_port_type_cleanup(&port_mem_total_type);
	gscheduler_port_type_cleanup(&port_mem_free_type);
}
