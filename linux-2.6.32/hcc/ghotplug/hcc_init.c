/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/workqueue.h>
#include <linux/sysdev.h>
#include <linux/if.h>

#include <hcc/version.h>
#include <hcc/types.h>
#include <hcc/hcc_init.h>
#include <hcc/hcc_flags.h>
#include <linux/cluster_barrier.h>
#include <linux/unique_id.h>
#include <net/grpc/grpc.h>
#ifdef CONFIG_HCC_PROC
#include <hcc/pid.h>
#endif
#ifdef CONFIG_HCC_GHOTPLUG
#include <hcc/ghotplug.h>
#endif

void init_node_discovering(void);

/* Node id */
hcc_node_t hcc_node_id = -1;
EXPORT_SYMBOL(hcc_node_id);

/* Number of active nodes in the cluster */
hcc_node_t hcc_nb_nodes = -1;

/* Min number of node before to start a cluster */
hcc_node_t hcc_nb_nodes_min = -1;

/* Session id in order to mix several hcc in the same physical network */
hcc_session_t hcc_session_id = 0;

/* ID of subcluster in the main one */
hcc_subsession_t hcc_subsession_id = -1;

/* Initialisation flags */
#ifdef CONFIG_HCC_AUTONODEID_ON
#define IF_AUTONODEID (1<<HCC_INIT_FLAGS_AUTONODEID)
#else
#define IF_AUTONODEID (0)
#endif
int hcc_init_flags = IF_AUTONODEID;

/* lock around process transformation and hooks install */
DECLARE_RWSEM(hcc_init_sem);
EXPORT_SYMBOL(hcc_init_sem);

int hcc_cluster_flags;
EXPORT_SYMBOL(hcc_cluster_flags);

int hcc_node_flags;
EXPORT_SYMBOL(hcc_node_flags);

int __hcc_panic__ = 0;

struct workqueue_struct *hcc_wq;
struct workqueue_struct *hcc_nb_wq;

struct kobject* hcc_sys;
struct kobject* hcc_ghotplugsys;

#define deffct(p) extern int init_##p(void); extern void cleanup_##p(void)

deffct(tools);
#ifdef CONFIG_HCC_GHOTPLUG
deffct(ghotplug);
#endif
#ifdef CONFIG_HCC_GRPC
deffct(grpc);
#endif
#ifdef CONFIG_HCC_STREAM
deffct(stream);
#endif
deffct(gdm);
deffct(gmm);
#ifdef CONFIG_HCC_DVFS
deffct(dvfs);
#endif
#ifdef CONFIG_HCC_GIPC
deffct(keripc);
#endif
#ifdef CONFIG_HCC_GCAP
deffct(hcc_gcap);
#endif
#ifdef CONFIG_HCC_PROCFS
deffct(procfs);
#endif
#ifdef CONFIG_HCC_PROC
deffct(proc);
#endif
#ifdef CONFIG_HCC_GPM
deffct(ghost);
deffct(gpm);
#endif
#ifdef CONFIG_HCC_GSCHED
deffct(gscheduler);
#endif

/*
 * Handle Kernel parameters
 */

static int __init  parse_autonodeid(char *str) {
	int v = 0;
	get_option(&str, &v);
	if(v)
		SET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_AUTONODEID);
	else
		CLR_HCC_INIT_FLAGS(HCC_INIT_FLAGS_AUTONODEID);
	return 0;
}
__setup("autonodeid=",parse_autonodeid);

static int __init  parse_node_id(char *str) {
	int v;
	get_option(&str, &v);
	hcc_node_id = v;
	SET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID);
	return 0;
}
__setup("node_id=",parse_node_id);

static int __init  parse_session_id(char *str){
	int v;
	get_option(&str, &v);
	hcc_session_id = v;
	SET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_SESSIONID);
	return 0;
}
__setup("session_id=",parse_session_id);

static int __init  parse_nb_nodes_min(char *str){
	int v;
	get_option(&str, &v);
	hcc_nb_nodes_min = v;
	return 0;
}
__setup("nb_nodes_min=",parse_nb_nodes_min);

/*****************************************************************************/
/*                                                                           */
/*                          HCC INIT FUNCTION                          */
/*                                                                           */
/*****************************************************************************/

static inline void check_node_id (int node_id)
{
	if ((node_id >= HCC_MAX_NODES) || (node_id <= 0))
	{
		printk ("Invalid hcc node_id %d. Must be greater then 0 and less than max id. (max id = %d)\n",
			node_id, HCC_MAX_NODES);
		BUG();
	}
}

static char *read_from_file(char *_filename, int size)
{
	int error;
	struct file *f;
	char *b;
	struct filename *filename;

	b = kmalloc(size, GFP_ATOMIC);
	BUG_ON(b==NULL);

	filename = getname(_filename);
	if (!IS_ERR(filename)) {
		f = filp_open((const char *)filename->name, O_RDONLY, 0);
		if (IS_ERR(f)) {
			printk("error: %ld\n", PTR_ERR(f));
			goto err_file;
		}

		error = kernel_read(f, 0, b, size);
		//printk("read %d bytes\n", error);

		b[error] = 0;
		//printk(">>>%s<<<\n", b);

		if (f->f_op && f->f_op->flush) {
			error = f->f_op->flush(f, NULL);
			if (error)
				printk("init_ids: Error while closing file %d\n", error);
		}
	}
	putname(filename);
	return b;

 err_file:
	kfree(b);
	return NULL;
}

/* Remove then CR (if any) */
static void strip_hostname(char *h)
{
	char *i;

	for (i = h; *i; i++) {
		if (*i == 10) {
			*i=0;
			break;
		}
	}
}

static char *get_next_line(char *k)
{
	char *i;

	BUG_ON(*k==0);

	for (i = k; *i; i++) {
		if (*i == 10)
			return i+1;
	}

	return NULL;
}

static void read_hcc_nodes(char *_h, char *k)
{
	char *ik, *h;
	int lh;

	if ((_h==NULL) || (k==NULL))
		return;

	lh = strlen(_h);
	h = kmalloc(lh+1, GFP_ATOMIC);
	strncpy(h, _h, lh);
	h[lh] = ':';
	h[lh+1] = 0;
	lh = strlen(h);

	for (ik=k; ik && *ik;) {
		if (!ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_SESSIONID)) {
			if (strncmp("session=", ik, 8) == 0){
				ik += 8;
				hcc_session_id = simple_strtoul(ik, NULL, 10);
				SET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_SESSIONID);

				ik = get_next_line(ik);
				continue;
			}
		}

		if (strncmp("nbmin=", ik, 6) == 0) {
			ik += 6;
			hcc_nb_nodes_min = simple_strtoul(ik, NULL, 10);
			ik = get_next_line(ik);
			continue;
		}

		if (!ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID)) {
			if (strncmp(h, ik, lh) == 0) {
				char *end;
				ik += lh;

				hcc_node_id = simple_strtoul(ik, &end, 10);
				SET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID);
			}
		}

		ik = get_next_line(ik);
	}
}

static void __init init_ids(void)
{
	char *hostname, *hcc_nodes;

	if (!ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID) ||
	    !ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_SESSIONID)) {
		/* first we read the name of the node */
		hostname = read_from_file("/etc/hostname", 256);
		if (!hostname) {
			printk("Can't read /etc/hostname\n");
			goto out;
		}
		strip_hostname(hostname);

		hcc_nodes = read_from_file("/etc/hcc_nodes", 4096);
		if (!hcc_nodes) {
			kfree(hostname);
			printk("Can't read /etc/hcc_nodes\n");
			goto out;
		}
		read_hcc_nodes(hostname, hcc_nodes);

		kfree(hcc_nodes);
		kfree(hostname);
	}

 out:
	if (ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID)) {
		check_node_id(hcc_node_id);
#ifdef CONFIG_HCC_GHOTPLUG
		universe[hcc_node_id].state = 1;
		set_hcc_node_present(hcc_node_id);
#endif
	}

	hcc_cluster_flags = 0;
	hcc_node_flags = 0;

	printk("HCC session ID : %d\n", hcc_session_id);
	printk("HCC node ID    : %d\n", hcc_node_id);
	printk("HCC min nodes  : %d\n", hcc_nb_nodes_min);

	if (!ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_NODEID) ||
	    !ISSET_HCC_INIT_FLAGS(HCC_INIT_FLAGS_SESSIONID))
		panic("hcc: incomplete session ID / node ID settings!\n");

	return;
}

int init_hcc_communication_system(void)
{
	printk("Init HCC low-level framework...\n");

	if (init_tools())
		goto err_tools;

	hcc_nb_nodes = 0;

#ifdef CONFIG_HCC_GRPC
	if (init_grpc())
		goto err_grpc;
#endif

#ifdef CONFIG_HCC_GHOTPLUG
	if (init_ghotplug())
		goto err_ghotplug;
#endif

	printk("Init HCC low-level framework (nodeid %d) : done\n", hcc_node_id);

	return 0;

#ifdef CONFIG_HCC_GHOTPLUG
err_ghotplug:
	cleanup_ghotplug();
#endif
#ifdef CONFIG_HCC_GRPC
err_grpc:
#endif
	cleanup_tools();
err_tools:
	return -1;
}

#ifdef CONFIG_HCC
int init_hcc_upper_layers(void)
{
	printk("Init HCC distributed services...\n");

#ifdef CONFIG_HCC_GDM
	if (init_gdm())
		goto err_gdm;
#endif

#ifdef CONFIG_HCC_GPM
	if (init_ghost())
		goto err_ghost;
#endif

#ifdef CONFIG_HCC_STREAM
	if (init_stream())
		goto err_palantir;
#endif

#ifdef CONFIG_HCC_GMM
	if (init_gmm())
		goto err_gmm;
#endif

#ifdef CONFIG_HCC_DVFS
	if (init_dvfs())
		goto err_dvfs;
#endif

#ifdef CONFIG_HCC_GIPC
	if (init_keripc())
		goto err_keripc;
#endif

#ifdef CONFIG_HCC_GCAP
	if (init_hcc_gcap())
		goto err_hcc_gcap;
#endif

#ifdef CONFIG_HCC_PROC
	if (init_proc())
		goto err_proc;
#endif

#ifdef CONFIG_HCC_PROCFS
	if (init_procfs())
		goto err_procfs;
#endif

#ifdef CONFIG_HCC_GPM
	if (init_gpm())
		goto err_gpm;
#endif

	printk("Init HCC distributed services: done\n");

#ifdef CONFIG_HCC_GSCHED
	if (init_gscheduler())
		goto err_sched;
#endif

	return 0;

#ifdef CONFIG_HCC_GSCHED
	cleanup_gscheduler();
      err_sched:
#endif
#ifdef CONFIG_HCC_GPM
	cleanup_gpm();
      err_gpm:
#endif
#ifdef CONFIG_HCC_GIPC
	cleanup_keripc();
      err_keripc:
#endif
#ifdef CONFIG_HCC_DVFS
	cleanup_dvfs();
      err_dvfs:
#endif
#ifdef CONFIG_HCC_PROCFS
	cleanup_procfs();
      err_procfs:
#endif
#ifdef CONFIG_HCC_PROC
	cleanup_proc();
      err_proc:
#endif
#ifdef CONFIG_HCC_GCAP
	cleanup_hcc_gcap();
      err_hcc_gcap:
#endif
#ifdef CONFIG_HCC_GMM
	cleanup_gmm();
      err_gmm:
#endif
#ifdef CONFIG_HCC_GDM
	cleanup_gdm();
      err_gdm:
#endif
#ifdef CONFIG_HCC_STREAM
	cleanup_stream();
      err_palantir:
#endif
#ifdef CONFIG_HCC_GPM
	cleanup_ghost();
      err_ghost:
#endif
#ifdef CONFIG_HCC_GRPC
	cleanup_grpc();
#endif
	return -1;
}
#endif

#if 0
static ssize_t hcc_operation_show(struct kobject *obj, struct kobj_attribute *attr,
					char *page) {
        return sprintf(page, "blabla\n");
}

static ssize_t hcc_operation_store(struct kobject *obj, struct kobj_attribute *attr,
					const char *buf, size_t count) {
	printk("requested_operation: %s\n", buf);
        return count;
}

static struct kobj_attribute operation =
		__ATTR(operation, 0644,
			hcc_operation_show,
			hcc_operation_store);
#endif

static ssize_t node_id_show(struct kobject *obj, struct kobj_attribute *attr,
			    char *page)
{
	return sprintf(page, "%d\n", hcc_node_id);
}
static struct kobj_attribute kobj_attr_node_id =
		__ATTR_RO(node_id);

static ssize_t session_id_show(struct kobject *obj, struct kobj_attribute *attr,
			       char *page)
{
	return sprintf(page, "%d\n", hcc_session_id);
}
static struct kobj_attribute kobj_attr_session_id =
		__ATTR_RO(session_id);

static ssize_t subsession_id_show(struct kobject *obj, struct kobj_attribute *attr,
				  char *page)
{
	return sprintf(page, "%d\n", hcc_subsession_id);
}
static struct kobj_attribute kobj_attr_subsession_id =
		__ATTR_RO(subsession_id);

static ssize_t max_nodes_show(struct kobject *obj, struct kobj_attribute *attr,
			      char *page)
{
	return sprintf(page, "%d\n", HCC_MAX_NODES);
}
static struct kobj_attribute kobj_attr_max_nodes =
		__ATTR_RO(max_nodes);

static ssize_t max_subclusters_show(struct kobject *obj, struct kobj_attribute *attr,
				    char *page)
{
	return sprintf(page, "%d\n", HCC_MAX_CLUSTERS);
}
static struct kobj_attribute kobj_attr_max_subclusters =
		__ATTR_RO(max_subclusters);

static ssize_t abi_show(struct kobject *obj, struct kobj_attribute *attr,
			char *page)
{
	return sprintf(page, "%s\n", HCC_ABI);
}
static struct kobj_attribute kobj_attr_abi =
		__ATTR_RO(abi);

static ssize_t net_devices_store(struct kobject *obj,
				 struct kobj_attribute *attr,
				 const char *page, size_t count)
{
	char buf[IFNAMSIZ + 2];
	char *name;
	int err;

	if (sysfs_streq(page, "+ALL") || sysfs_streq(page, "ALL")) {
		grpc_enable_alldev();
		return count;
	} else if (sysfs_streq(page, "-ALL")) {
		grpc_disable_alldev();
		return count;
	}

	name = strncpy(buf, page, IFNAMSIZ + 2);
	if (buf[IFNAMSIZ + 1])
		return -EINVAL;
	name = strstrip(name);

	switch (name[0]) {
	case '-':
		err = grpc_disable_dev(name + 1);
		break;
	case '+':
		name++;
		/* Fallthrough */
	default:
		err = grpc_enable_dev(name);
		break;
	}
	if (err)
		return err;

	return count;
}

static struct kobj_attribute kobj_attr_net_devices =
	__ATTR(net_devices, 0200, NULL, net_devices_store);

static struct attribute *attrs[] = {
	&kobj_attr_node_id.attr,
	&kobj_attr_session_id.attr,
	&kobj_attr_subsession_id.attr,
	&kobj_attr_max_nodes.attr,
	&kobj_attr_max_subclusters.attr,
	&kobj_attr_abi.attr,
	&kobj_attr_net_devices.attr,
	NULL
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int init_sysfs(void){
	int r;

	hcc_sys = kobject_create_and_add("hcc", NULL);
	if(!hcc_sys)
		return -1;

	hcc_ghotplugsys = kobject_create_and_add("ghotplug", hcc_sys);
	if(!hcc_ghotplugsys)
		return -1;

	r = sysfs_create_group(hcc_sys, &attr_group);
	if(r)
		kobject_put(hcc_sys);

	return 0;
}

void __init hcc_init(void){
	printk("HCC: stage 0\n");
	init_ids();

	printk("HCC: stage 1\n");

	init_sysfs();
	hcc_wq = create_workqueue("hcc");
	hcc_nb_wq = create_workqueue("hccNB");
	BUG_ON(hcc_wq == NULL);
	BUG_ON(hcc_nb_wq == NULL);

	init_unique_ids();
	init_node_discovering();

	printk("HCC: stage 2\n");

	if (init_hcc_communication_system())
		return;

	init_cluster_barrier();

#ifdef CONFIG_HCC
	if (init_hcc_upper_layers())
		return;
#endif

	SET_HCC_CLUSTER_FLAGS(HCC_FLAGS_LOADED);
	SET_HCC_NODE_FLAGS(HCC_FLAGS_LOADED);

	printk("HCC... loaded!\n");

	grpc_enable(CLUSTER_START);
}
