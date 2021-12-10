/** /proc/hcc/ manager
 *  @file proc.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <asm/processor.h>
#include <linux/kernel_stat.h>
#include <linux/seq_file.h>
#include <linux/if.h>
#include <asm/div64.h>
#include <linux/threads.h>
#include <linux/vmalloc.h>
#include <linux/hugetlb.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/proc_fs.h>
#include <hcc/hcc_flags.h>
#include <hcc/procfs.h>

#include <hcc/ghotplug.h>
#include "proc.h"
#include "static_node_info_linker.h"
#include "static_cpu_info_linker.h"
#include <hcc/dynamic_node_info_linker.h>
#include "dynamic_cpu_info_linker.h"

#define PROC_STAT_DEPEND_ON_CAPABILITY (HCC_MAX_NODES + 1)

extern unsigned int (*kstat_irqs_usr_fn)(unsigned int irq);

/* /proc/hcc entries */

static struct proc_dir_entry *procfs_nodes;	/* /proc/hcc/nodes   */
static struct proc_dir_entry *procfs_nrnodes;	/* /proc/hcc/nodes/nrnodes */

static void hcc_create_seq_entry(char *name,
				 mode_t mode,
				 struct file_operations *f,
				 struct proc_dir_entry *parent, void *data)
{
	struct proc_dir_entry *entry;
	entry = create_proc_entry(name, mode, parent);
	if (entry) {
		entry->proc_fops = f;
		entry->data = data;
	}
}

/** Check if a < b */
static inline int timespec_lt(struct timespec *a, struct timespec *b)
{
	return ((a->tv_sec < b->tv_sec) ||
		((a->tv_sec == b->tv_sec) && (a->tv_nsec < b->tv_nsec)));
}

static inline hcc_node_t get_req_node(hcc_node_t nodeid)
{
	if (!current->nsproxy->hcc_ns) {
		if (nodeid == PROC_STAT_DEPEND_ON_CAPABILITY)
			return hcc_node_id;
		else
			return nodeid;
	}

#ifdef CONFIG_HCC_GCAP
	if (nodeid == PROC_STAT_DEPEND_ON_CAPABILITY) {
		if (cap_raised
		    (current->hcc_gcaps.effective, GCAP_SEE_LOCAL_PROC_STAT))
			return hcc_node_id;
		else
			return HCC_MAX_NODES;
	}
#endif
	return nodeid;
}


static inline hcc_nodemask_t get_proc_nodes_vector(hcc_node_t nodeid)
{
	hcc_nodemask_t nodes;
	nodeid = get_req_node(nodeid);
	hcc_nodes_clear(nodes);

	if (nodeid == HCC_MAX_NODES) {
		if (IS_HCC_NODE(HCC_FLAGS_RUNNING))
			hcc_nodes_copy(nodes, hcc_node_online_map);
		else
			hcc_node_set(hcc_node_id, nodes);
	} else
		hcc_node_set(nodeid, nodes);

	return nodes;
}

static void free_stat_buf(int size, void *buf)
{
	if (size > PAGE_SIZE)
		vfree(buf);
	else
		kfree(buf);
}

static int hcc_proc_stat_open(struct inode *inode,
			      struct file *file,
			      int (*show) (struct seq_file *, void *), int size)
{
	char *buf;
	struct seq_file *m;
	int res;

	if (size > PAGE_SIZE)
		buf = vmalloc(size);
	else
		buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	res = single_open(file, show, PROC_I(inode)->hcc_procfs_private);
	if (!res) {
		m = file->private_data;
		m->buf = buf;
		m->size = size;
	} else
		free_stat_buf(size, buf);

	return res;
}

static int hcc_proc_stat_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;

	free_stat_buf(m->size, m->buf);
	m->buf = NULL;

	return single_release (inode, file);
}

/****************************************************************************/
/*                                                                          */
/*                   /proc/hcc/cpuinfo  Management                    */
/*                                                                          */
/****************************************************************************/

struct cpu_info_seq_struct {
	int cur_node;
	int last_node;
	int cpu_id;
	int req_node;
	int last_pos;
};

static void init_cpu_info_seq_struct(struct cpu_info_seq_struct *seq_data)
{
	hcc_node_t req_node ;

	req_node = get_req_node(seq_data->req_node);

	if (hcc_node_online(hcc_node_id)) {
		// Init values to parse CPU.
		if (req_node == HCC_MAX_NODES) {
			// Cluster wide CPU info
			seq_data->cur_node = nth_online_hcc_node(0);
			seq_data->last_node = HCC_MAX_NODES - 1;
		} else {
			// Node wide CPU info
			seq_data->cur_node = req_node;
			seq_data->last_node = req_node;
		}
	} else {
		seq_data->cur_node = hcc_node_id;
		seq_data->last_node = hcc_node_id;
	}
	seq_data->cpu_id = 0;
	seq_data->last_pos = 0;
}

static void go_to_selected_cpu(struct cpu_info_seq_struct *seq_data,
			       loff_t pos)
{
	hcc_static_node_info_t *static_node_info = NULL;
	int i;

	for (i = seq_data->last_pos; i < pos; i++) {
		seq_data->cpu_id++;
		static_node_info = get_static_node_info(seq_data->cur_node);
		if (seq_data->cpu_id >= static_node_info->nr_cpu) {
			seq_data->cur_node =
				hcc_node_next_online(seq_data->cur_node);
			seq_data->cpu_id = 0;
		}
	}
	seq_data->last_pos = pos;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	struct cpu_info_seq_struct *seq_data = m->private;
	hcc_static_cpu_info_t *cpu_info;

	if (!current->nsproxy->hcc_ns)
		return cpuinfo_op.start(m, pos);

	if (*pos == 0)
		init_cpu_info_seq_struct (seq_data);
	else {
		// Switch to the requested CPU.
		if (unlikely(*pos < seq_data->last_pos))
			init_cpu_info_seq_struct (seq_data);

		go_to_selected_cpu(seq_data, *pos);
	}

	if (seq_data->cur_node <= seq_data->last_node) {
		cpu_info =
		    get_static_cpu_info(seq_data->cur_node, seq_data->cpu_id);
		return &cpu_info->info;
	} else
		return NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	if (!current->nsproxy->hcc_ns)
		return cpuinfo_op.next(m, v, pos);

	++*pos;

	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
	if (!current->nsproxy->hcc_ns)
		cpuinfo_op.stop(m, v);
}

static int show_cpuinfo(struct seq_file *m, void *v)
{
	return cpuinfo_op.show(m, v);
}

struct seq_operations hcc_cpuinfo_op = {
	.start = c_start,
	.next = c_next,
	.stop = c_stop,
	.show = show_cpuinfo,
};

extern struct seq_operations hcc_cpuinfo_op;

static int hcc_cpuinfo_open(struct inode *inode, struct file *file)
{
	struct cpu_info_seq_struct *seq_data;
	struct seq_file *m;
	int ret;

	ret = seq_open(file, &hcc_cpuinfo_op);
	if (ret < 0)
		return ret;

	seq_data = kmalloc(sizeof(struct cpu_info_seq_struct), GFP_KERNEL);
	if (seq_data == NULL) {
		seq_release(inode, file);
		return -ENOMEM;
	}

	seq_data->req_node = (long)PROC_I(inode)->hcc_procfs_private;
	m = file->private_data;
	m->private = seq_data;

	return 0;
}

static int hcc_cpuinfo_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	kfree(m->private);

	return seq_release(inode, file);
}

static struct file_operations proc_hcc_cpuinfo_operations = {
	.open = hcc_cpuinfo_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_cpuinfo_release,
};

/****************************************************************************/
/*                                                                          */
/*                   /proc/hcc/meminfo  Management                    */
/*                                                                          */
/****************************************************************************/

void
__attribute__((weak))
hcc_arch_accumulate_meminfo(const hcc_dynamic_node_info_t *local_info,
			    hcc_dynamic_node_info_t *global_info)
{
}

void
__attribute__((weak))
hcc_arch_report_meminfo(struct seq_file *m, const hcc_dynamic_node_info_t *info)
{
}

/** Read function for /proc/hcc/meminfo entry.
 *  @author Innogrid HCC
 */
static int show_meminfo(struct seq_file *p, void *v)
{
	hcc_node_t nodeid = (long)p->private;
	hcc_nodemask_t nodes;
	hcc_dynamic_node_info_t global_dyn_info;
	hcc_dynamic_node_info_t *dyn_info;
	hcc_node_t node;
	long cached;
	int i;

	if (!current->nsproxy->hcc_ns)
		return meminfo_proc_show(p, v);

	nodes = get_proc_nodes_vector(nodeid);

	memset(&global_dyn_info, 0, sizeof(hcc_dynamic_node_info_t));

	for_each_hcc_node_mask(node, nodes) {
		dyn_info = get_dynamic_node_info(node);

		global_dyn_info.totalram += dyn_info->totalram;
		global_dyn_info.freeram += dyn_info->freeram;
		global_dyn_info.bufferram += dyn_info->bufferram;
		global_dyn_info.totalhigh += dyn_info->totalhigh;
		global_dyn_info.freehigh += dyn_info->freehigh;
		global_dyn_info.totalswap += dyn_info->totalswap;
		global_dyn_info.freeswap += dyn_info->freeswap;
		global_dyn_info.swapcache_pages += dyn_info->swapcache_pages;

		for_each_lru(i)
			global_dyn_info.nr_pages[i - LRU_BASE] +=
				dyn_info->nr_pages[i - LRU_BASE];
		global_dyn_info.nr_mlock += dyn_info->nr_mlock;
		global_dyn_info.nr_file_pages += dyn_info->nr_file_pages;
		global_dyn_info.nr_file_dirty += dyn_info->nr_file_dirty;
		global_dyn_info.nr_writeback += dyn_info->nr_writeback;
		global_dyn_info.nr_anon_pages += dyn_info->nr_anon_pages;
		global_dyn_info.nr_file_mapped += dyn_info->nr_file_mapped;
		global_dyn_info.nr_page_table_pages +=
		    dyn_info->nr_page_table_pages;
		global_dyn_info.nr_slab_reclaimable +=
			dyn_info->nr_slab_reclaimable;
		global_dyn_info.nr_slab_unreclaimable +=
			dyn_info->nr_slab_unreclaimable;
		global_dyn_info.nr_unstable_nfs += dyn_info->nr_unstable_nfs;
		global_dyn_info.nr_bounce += dyn_info->nr_bounce;
		global_dyn_info.nr_writeback_temp +=
			dyn_info->nr_writeback_temp;

		global_dyn_info.quicklists += dyn_info->quicklists;

		global_dyn_info.vmi.used += dyn_info->vmi.used;
		if (dyn_info->vmi.largest_chunk >
		    global_dyn_info.vmi.largest_chunk)
			global_dyn_info.vmi.largest_chunk =
			    dyn_info->vmi.largest_chunk;
		global_dyn_info.vmalloc_total += dyn_info->vmalloc_total;

		global_dyn_info.allowed += dyn_info->allowed;
		global_dyn_info.commited += dyn_info->commited;

		global_dyn_info.nr_huge_pages += dyn_info->nr_huge_pages;
		global_dyn_info.free_huge_pages += dyn_info->free_huge_pages;
		global_dyn_info.resv_huge_pages += dyn_info->resv_huge_pages;
		global_dyn_info.surplus_huge_pages +=
			dyn_info->surplus_huge_pages;

		hcc_arch_accumulate_meminfo(dyn_info, &global_dyn_info);
	}

#define K(x) ((x) << (PAGE_SHIFT - 10))

        cached = global_dyn_info.nr_file_pages -
		global_dyn_info.swapcache_pages - global_dyn_info.bufferram;
	if (cached < 0)
		cached = 0;

	seq_printf(p,
		   "MemTotal:       %8lu kB\n"
		   "MemFree:        %8lu kB\n"
		   "Buffers:        %8lu kB\n"
		   "Cached:         %8lu kB\n"
		   "SwapCached:     %8lu kB\n"
		   "Active:         %8lu kB\n"
		   "Inactive:       %8lu kB\n"
		   "Active(anon):   %8lu kB\n"
		   "Inactive(anon): %8lu kB\n"
		   "Active(file):   %8lu kB\n"
		   "Inactive(file): %8lu kB\n"
		   "Unevictable:    %8lu kB\n"
		   "Mlocked:        %8lu kB\n"
#ifdef CONFIG_HIGHMEM
		   "HighTotal:      %8lu kB\n"
		   "HighFree:       %8lu kB\n"
		   "LowTotal:       %8lu kB\n"
		   "LowFree:        %8lu kB\n"
#endif
#ifndef CONFIG_MMU
#error Is it possible to run HCC without an MMU?
#endif
		   "SwapTotal:      %8lu kB\n"
		   "SwapFree:       %8lu kB\n"
		   "Dirty:          %8lu kB\n"
		   "Writeback:      %8lu kB\n"
		   "AnonPages:      %8lu kB\n"
		   "Mapped:         %8lu kB\n"
		   "Slab:           %8lu kB\n"
		   "SReclaimable:   %8lu kB\n"
		   "SUnreclaim:     %8lu kB\n"
		   "PageTables:     %8lu kB\n"
#ifdef CONFIG_QUICKLIST
		   "Quicklists:     %8lu kB\n"
#endif
		   "NFS_Unstable:   %8lu kB\n"
		   "Bounce:         %8lu kB\n"
		   "WritebackTmp:   %8lu kB\n"
		   "CommitLimit:    %8lu kB\n"
		   "Committed_AS:   %8lu kB\n"
		   "VmallocTotal:   %8lu kB\n"
		   "VmallocUsed:    %8lu kB\n"
		   "VmallocChunk:   %8lu kB\n",
		   K(global_dyn_info.totalram),
		   K(global_dyn_info.freeram),
		   K(global_dyn_info.bufferram),
		   K(cached),
		   K(global_dyn_info.swapcache_pages),
		   K(global_dyn_info.nr_pages[LRU_ACTIVE_ANON - LRU_BASE] +
		     global_dyn_info.nr_pages[LRU_ACTIVE_FILE - LRU_BASE]),
		   K(global_dyn_info.nr_pages[LRU_INACTIVE_ANON - LRU_BASE] +
		     global_dyn_info.nr_pages[LRU_INACTIVE_FILE - LRU_BASE]),
		   K(global_dyn_info.nr_pages[LRU_ACTIVE_ANON - LRU_BASE]),
		   K(global_dyn_info.nr_pages[LRU_INACTIVE_ANON - LRU_BASE]),
		   K(global_dyn_info.nr_pages[LRU_ACTIVE_FILE - LRU_BASE]),
		   K(global_dyn_info.nr_pages[LRU_INACTIVE_FILE - LRU_BASE]),
		   K(global_dyn_info.nr_pages[LRU_UNEVICTABLE - LRU_BASE]),
		   K(global_dyn_info.nr_mlock),
#ifdef CONFIG_HIGHMEM
		   K(global_dyn_info.totalhigh),
		   K(global_dyn_info.freehigh),
		   K(global_dyn_info.totalram - global_dyn_info.totalhigh),
		   K(global_dyn_info.freeram - global_dyn_info.freehigh),
#endif
		   K(global_dyn_info.totalswap),
		   K(global_dyn_info.freeswap),
		   K(global_dyn_info.nr_file_dirty),
		   K(global_dyn_info.nr_writeback),
		   K(global_dyn_info.nr_anon_pages),
		   K(global_dyn_info.nr_file_mapped),
		   K(global_dyn_info.nr_slab_reclaimable +
		     global_dyn_info.nr_slab_unreclaimable),
		   K(global_dyn_info.nr_slab_reclaimable),
		   K(global_dyn_info.nr_slab_unreclaimable),
		   K(global_dyn_info.nr_page_table_pages),
#ifdef CONFIG_QUICKLIST
		   K(global_dyn_info.quicklists),
#endif
		   K(global_dyn_info.nr_unstable_nfs),
		   K(global_dyn_info.nr_bounce),
		   K(global_dyn_info.nr_writeback_temp),
		   K(global_dyn_info.allowed),
		   K(global_dyn_info.commited),
		   global_dyn_info.vmalloc_total >> 10,
		   global_dyn_info.vmi.used >> 10,
		   global_dyn_info.vmi.largest_chunk >> 10);

#ifdef CONFIG_HUGETLB_PAGE
	seq_printf(p,
		   "HugePages_Total:   %5lu\n"
		   "HugePages_Free:    %5lu\n"
		   "HugePages_Rsvd:    %5lu\n"
		   "HugePages_Surp:    %5lu\n"
		   "Hugepagesize:   %8lu kB\n",
		   global_dyn_info.nr_huge_pages,
		   global_dyn_info.free_huge_pages,
		   global_dyn_info.resv_huge_pages,
		   global_dyn_info.surplus_huge_pages,
		   1UL << (huge_page_order(&default_hstate) + PAGE_SHIFT - 10));
#endif

	hcc_arch_report_meminfo(p, &global_dyn_info);

	return 0;
#undef K
}

static int meminfo_open(struct inode *inode, struct file *file)
{
	return hcc_proc_stat_open(inode, file, show_meminfo, 1500);
}

static struct file_operations proc_hcc_meminfo_operations = {
	.open = meminfo_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/****************************************************************************/
/*                                                                          */
/*                     /proc/hcc/stat  Management                     */
/*                                                                          */
/****************************************************************************/

/** Read function for /proc/hcc/stat entry.
 *  @author Innogrid HCC
 *
 */
static int hcc_show_stat(struct seq_file *p, void *v)
{
	hcc_node_t req_nodeid = (long)p->private;
	hcc_dynamic_cpu_info_t *dynamic_cpu_info;
	struct cpu_usage_stat *stat;
	hcc_dynamic_node_info_t *dynamic_node_info;
	hcc_static_node_info_t *static_node_info;
	int i, j;
	hcc_nodemask_t nodes;
	cputime64_t user, nice, system, idle, iowait, irq, softirq, steal;
	cputime64_t guest;
	unsigned long long nr_context_switches = 0;
	unsigned long jif = 0, total_forks = 0, nr_running = 0, nr_iowait = 0;
	hcc_node_t node_id;
	u64 sum_irq = 0;
	u64 sum_softirq = 0;
	unsigned int per_softirq_sums[NR_SOFTIRQS] = {0};
#define HEAD_BLANK_LEN 81
	static const char head_blank[HEAD_BLANK_LEN + 1] = {
		[ 0 ... HEAD_BLANK_LEN - 2 ] = ' ',
		[HEAD_BLANK_LEN - 1] = '\n',
		[HEAD_BLANK_LEN] = '\0'
	};
	int head_len;

	if (!current->nsproxy->hcc_ns)
		return show_stat(p, v);

	nodes = get_proc_nodes_vector(req_nodeid);

	user = nice = system = idle = iowait = irq = softirq = steal =
	    cputime64_zero;
	guest = cputime64_zero;

	/*
	 * Keep space to overwrite "cpu" line later in order to get this line
	 * first without parsing data twice... Yes... Dirty...
	 */
	seq_printf(p, "%s", head_blank);
	for_each_hcc_node_mask(node_id, nodes) {
		static_node_info = get_static_node_info(node_id);
		dynamic_node_info = get_dynamic_node_info(node_id);

		/* Compute node level stat informations */

		nr_context_switches += dynamic_node_info->nr_context_switches;
		if (dynamic_node_info->jif > jif)
			jif = dynamic_node_info->jif;
		total_forks += dynamic_node_info->total_forks;
		nr_running += dynamic_node_info->nr_running;
		nr_iowait += dynamic_node_info->nr_iowait;

		for (i = 0; i < static_node_info->nr_cpu; i++) {
			dynamic_cpu_info = get_dynamic_cpu_info(node_id, i);

			stat = &dynamic_cpu_info->stat.cpustat;
			seq_printf(p,
				   "cpu%d  %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
				   __hcc_cpu_id(node_id, i),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->user),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->nice),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->system),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->idle),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->iowait),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->irq),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->softirq),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->steal),
				   (unsigned long long)
				   cputime64_to_clock_t(stat->guest));

			/* Compute CPU level stat informations */

			user = cputime64_add(user, stat->user);
			nice = cputime64_add(nice, stat->nice);
			system = cputime64_add(system, stat->system);
			idle = cputime64_add(idle, stat->idle);
			iowait = cputime64_add(iowait, stat->iowait);
			irq = cputime64_add(irq, stat->irq);
			softirq = cputime64_add(softirq, stat->softirq);
			steal = cputime64_add(steal, stat->steal);
			guest = cputime64_add(guest, stat->guest);
			sum_irq += dynamic_cpu_info->sum_irq;
			sum_softirq += dynamic_cpu_info->sum_softirq;

			for (j = 0; j < NR_SOFTIRQS; j++) {
				per_softirq_sums[j] += dynamic_cpu_info->per_softirq_sums[j];
			}
		}
		sum_irq += dynamic_node_info->arch_irq;
	}

	/* Dirty trick to print "cpu" line at the beginning without parsing data
	 * twice
	 */
	head_len = snprintf(p->buf, HEAD_BLANK_LEN,
			    "cpu   %llu %llu %llu %llu %llu %llu %llu %llu %llu",
			    (unsigned long long)cputime64_to_clock_t(user),
			    (unsigned long long)cputime64_to_clock_t(nice),
			    (unsigned long long)cputime64_to_clock_t(system),
			    (unsigned long long)cputime64_to_clock_t(idle),
			    (unsigned long long)cputime64_to_clock_t(iowait),
			    (unsigned long long)cputime64_to_clock_t(irq),
			    (unsigned long long)cputime64_to_clock_t(softirq),
			    (unsigned long long)cputime64_to_clock_t(steal),
			    (unsigned long long)cputime64_to_clock_t(guest));
	/*
	 * The NUL byte inserted overwrote a blank...
	 * in the middle of the file!
	 */
	if (head_len >= HEAD_BLANK_LEN - 1)
		/* NUL byte overwrote \n */
		p->buf[HEAD_BLANK_LEN - 1] = '\n';
	else
		p->buf[head_len] = ' ';
#undef HEAD_BLANK_LEN

	seq_printf(p, "intr %llu", (unsigned long long)sum_irq);

	/* sum again ? it could be updated? */
	for_each_irq_nr(j)
		seq_printf(p, " %u", kstat_irqs_usr_fn(j));

	seq_printf(p,
		   "\nctxt %llu\n"
		   "btime %lu\n"
		   "processes %lu\n"
		   "procs_running %lu\n"
		   "procs_blocked %lu\n",
		   nr_context_switches,
		   jif,
		   total_forks,
		   nr_running,
		   nr_iowait);

	seq_printf(p, "softirq %llu", (unsigned long long)sum_softirq);

	for (i = 0; i < NR_SOFTIRQS; i++)
		seq_printf(p, " %u", per_softirq_sums[i]);
	seq_printf(p, "\n");

	return 0;
}

static int stat_open(struct inode *inode, struct file *file)
{
	unsigned size;

	size = 256 + NR_IRQS * 8 + NR_CPUS * hcc_nb_nodes * 80;

	/* minimum size to display an interrupt count : 2 bytes */
	size += 2 * nr_irqs;

	return hcc_proc_stat_open(inode, file, hcc_show_stat, size);
}

static struct file_operations proc_hcc_stat_operations = {
	.open = stat_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_proc_stat_release,
};

/****************************************************************************/
/*                                                                          */
/*                    /proc/hcc/loadavg  Management                   */
/*                                                                          */
/****************************************************************************/

/* Copied from fs/proc/loadavg.c */
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

/** Read function for /proc/hcc/loadavg entry.
 *  @author Innogrid HCC
 *
 */
static int show_loadavg(struct seq_file *p, void *v)
{
	hcc_node_t nodeid = (long)p->private;
	hcc_dynamic_node_info_t *dynamic_node_info;
	hcc_nodemask_t nodes;
	hcc_node_t i;
	int a, b, c, nr_threads, last_pid;
	long nr_running;

	if (!current->nsproxy->hcc_ns)
		return loadavg_proc_show(p, v);

	a = b = c = nr_running = nr_threads = last_pid = 0;

	nodes = get_proc_nodes_vector(nodeid);

	for_each_hcc_node_mask(i, nodes) {
		dynamic_node_info = get_dynamic_node_info(i);
		a += dynamic_node_info->avenrun[0];
		b += dynamic_node_info->avenrun[1];
		c += dynamic_node_info->avenrun[2];

		nr_running += dynamic_node_info->nr_running;
		nr_threads += dynamic_node_info->nr_threads;
		last_pid = dynamic_node_info->last_pid;
	}
	a += (FIXED_1 / 200);
	b += (FIXED_1 / 200);
	c += (FIXED_1 / 200);

	seq_printf(p, "%d.%02d %d.%02d %d.%02d %ld/%d %d\n",
		   LOAD_INT(a), LOAD_FRAC(a),
		   LOAD_INT(b), LOAD_FRAC(b),
		   LOAD_INT(c), LOAD_FRAC(c),
		   nr_running, nr_threads,
		   last_pid);

	return 0;
}

static int loadavg_open(struct inode *inode, struct file *file)
{
	return hcc_proc_stat_open(inode, file, show_loadavg, 100);
}

static struct file_operations proc_hcc_loadavg_operations = {
	.open = loadavg_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_proc_stat_release,
};

/****************************************************************************/
/*                                                                          */
/*                    /proc/hcc/nodeid  Management                    */
/*                                                                          */
/****************************************************************************/

static int show_nodeid(struct seq_file *p, void *v)
{
	hcc_node_t nodeid = (long)p->private;

	if (nodeid >= HCC_MAX_NODES)
		seq_printf(p, "-\n");
	else
		seq_printf(p, "%d\n", nodeid);

	return 0;
}

static int nodeid_open(struct inode *inode, struct file *file)
{
	return hcc_proc_stat_open(inode, file, show_nodeid, 10);
}

static struct file_operations proc_hcc_nodeid_operations = {
	.open = nodeid_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_proc_stat_release,
};

/****************************************************************************/
/*                                                                          */
/*                 /proc/nodes/nrnodes  Management                          */
/*                                                                          */
/****************************************************************************/

/** Read function for /proc/nodes/nrnodes entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
static int hcc_nrnodes_read_proc(char *buffer, char **start, off_t offset,
				 int count, int *eof, void *data)
{
	static char mybuffer[64];
	static int len;

	if (offset == 0)
		len = snprintf(mybuffer, 40,
			       "ONLINE:%d\n"
			       "PRESENT:%d\n"
			       "POSSIBLE:%d\n",
			       num_online_hcc_nodes(),
			       num_present_hcc_nodes(),
			       num_possible_hcc_nodes());

	if (offset + count >= len) {
		count = len - offset;
		if (count < 0)
			count = 0;
		*eof = 1;
	}

	memcpy(buffer, &mybuffer[offset], count);

	return count;
}

/****************************************************************************/
/*                                                                          */
/*                    /proc/hcc/session  Management                   */
/*                                                                          */
/****************************************************************************/

static int show_session(struct seq_file *p, void *v)
{
	seq_printf(p, "%d\n", hcc_session_id);

	return 0;
}

static int session_open(struct inode *inode, struct file *file)
{
	return hcc_proc_stat_open(inode, file, show_session, 10);
}

static struct file_operations proc_hcc_session_operations = {
	.open = session_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_proc_stat_release,
};

/****************************************************************************/
/*                                                                          */
/*                    /proc/hcc/uptime  Management                    */
/*                                                                          */
/****************************************************************************/

/** Read function for /proc/hcc/uptime entry.
 *  @author Innogrid HCC
 */
static int show_uptime(struct seq_file *p, void *v)
{
	hcc_node_t nodeid = (long)p->private;
	hcc_dynamic_node_info_t *dynamic_node_info;
	hcc_node_t i, nr_nodes = 0;
	hcc_nodemask_t nodes;
	struct timespec uptime;
	unsigned long long idle = 0;
	unsigned long idle_mod;

	if (!current->nsproxy->hcc_ns)
		return uptime_proc_show(p, v);

	nodes = get_proc_nodes_vector(nodeid);

	uptime.tv_sec = uptime.tv_nsec = 0;

	for_each_hcc_node_mask(i, nodes) {
		dynamic_node_info = get_dynamic_node_info(i);
		nr_nodes++;

		if (timespec_lt(&uptime, &dynamic_node_info->uptime))
			uptime = dynamic_node_info->uptime;

		idle += (unsigned long long)dynamic_node_info->idletime.tv_sec *
		    NSEC_PER_SEC + dynamic_node_info->idletime.tv_nsec;
	}

	do_div(idle, nr_nodes);
	idle_mod = do_div(idle, NSEC_PER_SEC);

	seq_printf(p, "%lu.%02lu %lu.%02lu\n",
		   (unsigned long)uptime.tv_sec,
		   (uptime.tv_nsec / (NSEC_PER_SEC / 100)),
		   (unsigned long)idle, (idle_mod / (NSEC_PER_SEC / 100)));

	return 0;
}

static int uptime_open(struct inode *inode, struct file *file)
{
	return hcc_proc_stat_open(inode, file, show_uptime, 100);
}

static struct file_operations proc_hcc_uptime_operations = {
	.open = uptime_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = hcc_proc_stat_release,
};

/****************************************************************************/
/*                                                                          */
/*                   /proc/hcc/net/dev  Management                    */
/*                                                                          */
/****************************************************************************/

/** Read function for /proc/hcc/nodeid entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
int hcc_netdev_read_proc(char *buffer,
			 char **start,
			 off_t offset, int count, int *eof, void *data)
{
	return count;
}

/** Create a /proc/nodes/node<x> directory and sub-files.
 *  @author Innogrid HCC
 *
 *  @param nodeid   Id of the node to create a proc entry for.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int create_proc_node_info(hcc_node_t nodeid)
{
	struct proc_dir_entry *node_procfs;
	char dir_name[80];

	/* Create the /proc/nodes/node<x> entry */

	if (nodeid == HCC_MAX_NODES)
		snprintf(dir_name, 80, "cluster");
	else
		snprintf(dir_name, 80, "node%d", nodeid);

	node_procfs = create_proc_entry(dir_name, S_IFDIR | S_IRUGO | S_IWUGO |
					S_IXUGO, procfs_nodes);

	if (node_procfs == NULL)
		return -ENOMEM;

	/* Create entries in /proc/nodes/node<x> */

	if (nodeid != HCC_MAX_NODES)
		hcc_create_seq_entry("nodeid", 0, &proc_hcc_nodeid_operations,
				     node_procfs, (void *)((long)nodeid));
	hcc_create_seq_entry("session", 0, &proc_hcc_session_operations,
			     node_procfs, (void *)((long)nodeid));
#ifdef CONFIG_CLUSTER_WIDE_PROC_CPUINFO
#define CW_CPUINFO 1
#else
#define CW_CPUINFO 0
#endif
	if (CW_CPUINFO || nodeid != HCC_MAX_NODES)
		hcc_create_seq_entry("cpuinfo", 0, &proc_hcc_cpuinfo_operations,
				     node_procfs, (void *)((long)nodeid));
#ifdef CONFIG_CLUSTER_WIDE_PROC_MEMINFO
#define CW_MEMINFO 1
#else
#define CW_MEMINFO 0
#endif
	if (CW_MEMINFO || nodeid != HCC_MAX_NODES)
		hcc_create_seq_entry("meminfo", 0, &proc_hcc_meminfo_operations,
				     node_procfs, (void *)((long)nodeid));
#ifdef CONFIG_CLUSTER_WIDE_PROC_LOADAVG
#define CW_LOADAVG 1
#else
#define CW_LOADAVG 0
#endif
	if (CW_LOADAVG || nodeid != HCC_MAX_NODES)
		hcc_create_seq_entry("loadavg", 0, &proc_hcc_loadavg_operations,
				     node_procfs, (void *)((long)nodeid));
#ifdef CONFIG_CLUSTER_WIDE_PROC_UPTIME
#define CW_UPTIME 1
#else
#define CW_UPTIME 0
#endif
	if (CW_UPTIME || nodeid != HCC_MAX_NODES)
		hcc_create_seq_entry("uptime", 0, &proc_hcc_uptime_operations,
				     node_procfs, (void *)((long)nodeid));
#ifdef CONFIG_CLUSTER_WIDE_PROC_STAT
#define CW_STAT 1
#else
#define CW_STAT 0
#endif
	if (CW_STAT || nodeid != HCC_MAX_NODES)
		hcc_create_seq_entry("stat", 0, &proc_hcc_stat_operations,
				     node_procfs, (void *)((long)nodeid));

	if (nodeid == hcc_node_id)
		proc_symlink("self", procfs_nodes, dir_name);

	return 0;
}

/** Remove a /proc/nodes/node<x> directory and sub-files.
 *  @author Innogrid HCC
 *
 *  @param nodeid   Id of the node to remove a proc entry for.
 *
 *  @return  0 if everything ok.
 *           Negative value otherwise.
 */
int remove_proc_node_info(hcc_node_t nodeid)
{
	struct proc_dir_entry *subdir, *next;
	char dir_name[80];

	snprintf(dir_name, 80, "node%d", nodeid);

	subdir = procfs_nodes->subdir;
	if (subdir) {
		for (next = subdir->next; next;
                     subdir = next, next = subdir->next)
			if (!strcmp(subdir->name, dir_name)){
				procfs_deltree(subdir);
				return 0;
			}
	}

	return -ENOENT;
}

/** Init HCC proc stuffs.
 *  @author Innogrid HCC
 */
int hcc_procfs_init(void)
{
	/* Create the /proc/hcc/nodes entry */

#ifdef CONFIG_CLUSTER_WIDE_PROC
	procfs_nodes = create_proc_entry("nodes", S_IFDIR | S_IRUGO | S_IWUGO |
					 S_IXUGO, NULL);
#else
	procfs_nodes = create_proc_entry("nodes", S_IFDIR | S_IRUGO | S_IWUGO |
					 S_IXUGO, proc_hcc);
#endif

	if (procfs_nodes == NULL) {
		WARNING("Cannot create /proc/hcc/nodes\n");
		return -ENOMEM;
	}

	/* Create the /proc/hcc/nodes/nrnodes entry */

	procfs_nrnodes =
	    create_proc_read_entry("nrnodes", S_IRUGO, procfs_nodes,
				   hcc_nrnodes_read_proc, NULL);

	if (procfs_nrnodes == NULL) {
		WARNING("Cannot create /proc/hcc/nodes/nrnodes\n");
		return -ENOMEM;
	}

	/* Create cluster-wide entries in /proc/ */

#ifdef CONFIG_CLUSTER_WIDE_PROC_CPUINFO
	remove_proc_entry("cpuinfo", NULL);
	hcc_create_seq_entry("cpuinfo", 0, &proc_hcc_cpuinfo_operations,
			     NULL,
			     (void *)((int)PROC_STAT_DEPEND_ON_CAPABILITY));
#endif
#ifdef CONFIG_CLUSTER_WIDE_PROC_MEMINFO
	remove_proc_entry("meminfo", NULL);
	hcc_create_seq_entry("meminfo", 0, &proc_hcc_meminfo_operations, NULL,
			     (void *)((int)PROC_STAT_DEPEND_ON_CAPABILITY));
#endif
#ifdef CONFIG_CLUSTER_WIDE_PROC_LOADAVG
	remove_proc_entry("loadavg", NULL);
	hcc_create_seq_entry("loadavg", 0, &proc_hcc_loadavg_operations, NULL,
			     (void *)((int)PROC_STAT_DEPEND_ON_CAPABILITY));
#endif
#ifdef CONFIG_CLUSTER_WIDE_PROC_STAT
	remove_proc_entry("stat", NULL);
	hcc_create_seq_entry("stat", 0, &proc_hcc_stat_operations, NULL,
			     (void *)((int)PROC_STAT_DEPEND_ON_CAPABILITY));
#endif
#ifdef CONFIG_CLUSTER_WIDE_PROC_UPTIME
	remove_proc_entry("uptime", NULL);
	hcc_create_seq_entry("uptime", 0, &proc_hcc_uptime_operations, NULL,
			     (void *)((int)PROC_STAT_DEPEND_ON_CAPABILITY));
#endif
	/*  proc_net_remove("dev"); */

#ifdef CONFIG_CLUSTER_WIDE_PROC_INFRA
	/* Create the /proc/hcc/nodes/cluster entry */

	create_proc_node_info(HCC_MAX_NODES);
#endif

	return 0;
}

/** Finalize HCC proc stuffs.
 *  @author Innogrid HCC
 */
int hcc_procfs_finalize(void)
{
	procfs_deltree(procfs_nodes);

	return 0;
}
