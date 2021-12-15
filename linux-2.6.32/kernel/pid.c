/*
 * Generic pidhash and scalable, time-bounded PID allocator
 *
 * (C) 2002-2003 William Irwin, IBM
 * (C) 2004 William Irwin, Oracle
 * (C) 2002-2004 Ingo Molnar, Red Hat
 *
 * pid-structures are backing objects for tasks sharing a given ID to chain
 * against. There is very little to them aside from hashing them and
 * parking tasks using given ID's on a list.
 *
 * The hash is always changed with the tasklist_lock write-acquired,
 * and the hash is only accessed with the tasklist_lock at least
 * read-acquired, so there's no additional SMP locking needed here.
 *
 * We have a list of bitmap pages, which bitmaps represent the PID space.
 * Allocating and freeing PIDs is completely lockless. The worst-case
 * allocation scenario when all but one out of 1 million PIDs possible are
 * allocated already: the scanning of 32 list entries and at most PAGE_SIZE
 * bytes. The typical fastpath is a single successful setbit. Freeing is O(1).
 *
 * Pid namespaces:
 *    (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.
 *    (C) 2007 Sukadev Bhattiprolu <sukadev@us.ibm.com>, IBM
 *     Many thanks to Oleg Nesterov for comments and help
 *
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/rculist.h>
#include <linux/bootmem.h>
#include <linux/hash.h>
#include <linux/pid_namespace.h>
#include <linux/init_task.h>
#include <linux/syscalls.h>
#include <linux/proc_fs.h>

#ifdef CONFIG_HCC_PROC
#include <hcc/pid.h>
#include <hcc/hcc_init.h>
#endif

#define pid_hashfn(nr, ns)	\
	hash_long((unsigned long)nr + (unsigned long)ns, pidhash_shift)
static struct hlist_head *pid_hash;
static unsigned int pidhash_shift = 4;
struct pid init_struct_pid = INIT_STRUCT_PID;

int pid_max = PID_MAX_DEFAULT;

#define RESERVED_PIDS		300

int pid_max_min = RESERVED_PIDS + 1;
int pid_max_max = PID_MAX_LIMIT;

#define BITS_PER_PAGE		(PAGE_SIZE*8)
#define BITS_PER_PAGE_MASK	(BITS_PER_PAGE-1)

static inline int mk_pid(struct pid_namespace *pid_ns,
		struct pidmap *map, int off)
{
	return (map - pid_ns->pidmap)*BITS_PER_PAGE + off;
}

#define find_next_offset(map, off)					\
		find_next_zero_bit((map)->page, BITS_PER_PAGE, off)

/*
 * PID-map pages start out as NULL, they get allocated upon
 * first use and are never deallocated. This way a low pid_max
 * value does not cause lots of bitmaps to be allocated, but
 * the scheme scales to up to 4 million PIDs, runtime.
 */
struct pid_namespace init_pid_ns = {
	.kref = {
		.refcount       = ATOMIC_INIT(2),
	},
	.pidmap = {
		[ 0 ... PIDMAP_ENTRIES-1] = { ATOMIC_INIT(BITS_PER_PAGE), NULL }
	},
	.last_pid = 0,
	.level = 0,
	.child_reaper = &init_task,
#ifdef CONFIG_HCC_PROC
	.hcc_ns_root = NULL,
	.global = 0,
#endif
	.proc_inum = PROC_PID_INIT_INO,
};
EXPORT_SYMBOL_GPL(init_pid_ns);

int is_container_init(struct task_struct *tsk)
{
	int ret = 0;
	struct pid *pid;

	rcu_read_lock();
	pid = task_pid(tsk);
	if (pid != NULL && pid->numbers[pid->level].nr == 1)
		ret = 1;
	rcu_read_unlock();

	return ret;
}
EXPORT_SYMBOL(is_container_init);

/*
 * Note: disable interrupts while the pidmap_lock is held as an
 * interrupt might come in and do read_lock(&tasklist_lock).
 *
 * If we don't disable interrupts there is a nasty deadlock between
 * detach_pid()->free_pid() and another cpu that does
 * spin_lock(&pidmap_lock) followed by an interrupt routine that does
 * read_lock(&tasklist_lock);
 *
 * After we clean up the tasklist_lock and know there are no
 * irq handlers that take it we can leave the interrupts enabled.
 * For now it is easier to be safe than to prove it can't happen.
 */

static  __cacheline_aligned_in_smp DEFINE_SPINLOCK(pidmap_lock);

#ifdef CONFIG_HCC_GPM
void __free_pidmap(struct upid *upid)
#else
static void free_pidmap(struct upid *upid)
#endif
{
#ifndef CONFIG_HCC_PROC
	int nr = upid->nr;
#else
	int nr = SHORT_PID(upid->nr);
#endif
	struct pidmap *map = upid->ns->pidmap + nr / BITS_PER_PAGE;
	int offset = nr & BITS_PER_PAGE_MASK;

	clear_bit(offset, map->page);
	atomic_inc(&map->nr_free);
}

#ifdef CONFIG_HCC_GPM
static void free_pidmap(struct upid *upid)
{
	if ((upid->nr & GLOBAL_PID_MASK)
	    && ORIG_NODE(upid->nr) != hcc_node_id)
		hcc_free_pidmap(upid);
	else
		__free_pidmap(upid);
}

int alloc_pidmap_page(struct pidmap *map)
{
	void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	/*
	 * Free the page if someone raced with us
	 * installing it:
	 */
	spin_lock_irq(&pidmap_lock);
	if (map->page)
		kfree(page);
	else
		map->page = page;
	spin_unlock_irq(&pidmap_lock);
	if (unlikely(!map->page))
		return -ENOMEM;
	return 0;
}
#endif /* CONFIG_HCC_GPM */

/*
 * If we started walking pids at 'base', is 'a' seen before 'b'?
 */
static int pid_before(int base, int a, int b)
{
	/*
	 * This is the same as saying
	 *
	 * (a - base + MAXUINT) % MAXUINT < (b - base + MAXUINT) % MAXUINT
	 * and that mapping orders 'a' and 'b' with respect to 'base'.
	 */
	return (unsigned)(a - base) < (unsigned)(b - base);
}

/*
 * We might be racing with someone else trying to set pid_ns->last_pid.
 * We want the winner to have the "later" value, because if the
 * "earlier" value prevails, then a pid may get reused immediately.
 *
 * Since pids rollover, it is not sufficient to just pick the bigger
 * value.  We have to consider where we started counting from.
 *
 * 'base' is the value of pid_ns->last_pid that we observed when
 * we started looking for a pid.
 *
 * 'pid' is the pid that we eventually found.
 */
static void set_last_pid(struct pid_namespace *pid_ns, int base, int pid)
{
	int prev;
	int last_write = base;
	do {
		prev = last_write;
		last_write = cmpxchg(&pid_ns->last_pid, prev, pid);
	} while ((prev != last_write) && (pid_before(base, last_write, pid)));
}

static int alloc_pidmap(struct pid_namespace *pid_ns)
{
	int i, offset, max_scan, pid, last = pid_ns->last_pid;
	struct pidmap *map;

	pid = last + 1;
	if (pid >= pid_max)
		pid = RESERVED_PIDS;
	offset = pid & BITS_PER_PAGE_MASK;
	map = &pid_ns->pidmap[pid/BITS_PER_PAGE];
	max_scan = (pid_max + BITS_PER_PAGE - 1)/BITS_PER_PAGE - !offset;
	for (i = 0; i <= max_scan; ++i) {
		if (unlikely(!map->page)) {
#ifdef CONFIG_HCC_GPM
			if (alloc_pidmap_page(map))
#else
			void *page = kzalloc(PAGE_SIZE, GFP_KERNEL);
			/*
			 * Free the page if someone raced with us
			 * installing it:
			 */
			spin_lock_irq(&pidmap_lock);
			if (map->page)
				kfree(page);
			else
				map->page = page;
			spin_unlock_irq(&pidmap_lock);
			if (unlikely(!map->page))
#endif
				break;
		}
		if (likely(atomic_read(&map->nr_free))) {
			do {
				if (!test_and_set_bit(offset, map->page)) {
					atomic_dec(&map->nr_free);
					set_last_pid(pid_ns, last, pid);
					return pid;
				}
				offset = find_next_offset(map, offset);
				pid = mk_pid(pid_ns, map, offset);
			/*
			 * find_next_offset() found a bit, the pid from it
			 * is in-bounds, and if we fell back to the last
			 * bitmap block and the final block was the same
			 * as the starting point, pid is before last_pid.
			 */
			} while (offset < BITS_PER_PAGE && pid < pid_max &&
					(i != max_scan || pid < last ||
					    !((last+1) & BITS_PER_PAGE_MASK)));
		}
		if (map < &pid_ns->pidmap[(pid_max-1)/BITS_PER_PAGE]) {
			++map;
			offset = 0;
		} else {
			map = &pid_ns->pidmap[0];
			offset = RESERVED_PIDS;
			if (unlikely(last == offset))
				break;
		}
		pid = mk_pid(pid_ns, map, offset);
	}
	return -1;
}

#ifdef CONFIG_HCC_GPM
int reserve_pidmap(struct pid_namespace *pid_ns, int pid)
{
	int offset;
	struct pidmap *map;

	pid = SHORT_PID(pid);
	if (pid >= pid_max)
		return -EINVAL;

	offset = pid & BITS_PER_PAGE_MASK;
	map = &pid_ns->pidmap[pid/BITS_PER_PAGE];
	if (!map->page) {
		/* next_pidmap() is safe if intermediate pages are missing */
		int err = alloc_pidmap_page(map);
		if (err)
			return err;
	}

	/* Reserve pid in the page */
	BUG_ON(pid != mk_pid(pid_ns, map, offset));
	if (!test_and_set_bit(offset, map->page)) {
		atomic_dec(&map->nr_free);
		return 0;
	}

	return -EBUSY;
}
#endif /* CONFIG_HCC_GPM */

int next_pidmap(struct pid_namespace *pid_ns, unsigned int last)
{
	int offset;
	struct pidmap *map, *end;

	if (last >= PID_MAX_LIMIT)
		return -1;

	offset = (last + 1) & BITS_PER_PAGE_MASK;
	map = &pid_ns->pidmap[(last + 1)/BITS_PER_PAGE];
	end = &pid_ns->pidmap[PIDMAP_ENTRIES];
	for (; map < end; map++, offset = 0) {
		if (unlikely(!map->page))
			continue;
		offset = find_next_bit((map)->page, BITS_PER_PAGE, offset);
		if (offset < BITS_PER_PAGE)
			return mk_pid(pid_ns, map, offset);
	}
	return -1;
}

void put_pid(struct pid *pid)
{
	struct pid_namespace *ns;

	if (!pid)
		return;

	ns = pid->numbers[pid->level].ns;
	if ((atomic_read(&pid->count) == 1) ||
	     atomic_dec_and_test(&pid->count)) {
		kmem_cache_free(ns->pid_cachep, pid);
		put_pid_ns(ns);
	}
}
EXPORT_SYMBOL_GPL(put_pid);

static void delayed_put_pid(struct rcu_head *rhp)
{
	struct pid *pid = container_of(rhp, struct pid, rcu);
	put_pid(pid);
}

void free_pid(struct pid *pid)
{
	/* We can be called with write_lock_irq(&tasklist_lock) held */
	int i;
	unsigned long flags;

	spin_lock_irqsave(&pidmap_lock, flags);
	for (i = 0; i <= pid->level; i++) {
		struct upid *upid = pid->numbers + i;
		struct pid_namespace *ns = upid->ns;
		hlist_del_rcu(&upid->pid_chain);
		switch(--ns->nr_hashed) {
		case 2:
		case 1:
			/* When all that is left in the pid namespace
			 * is the reaper wake up the reaper.  The reaper
			 * may be sleeping in zap_pid_ns_processes().
			 */
			wake_up_process(ns->child_reaper);
			break;
		case PIDNS_HASH_ADDING:
			/* Handle a fork failure of the first process */
			WARN_ON(ns->child_reaper);
			ns->nr_hashed = 0;
			/* fall through */
		case 0:
			schedule_work(&ns->proc_work);
			break;
		}
	}
	spin_unlock_irqrestore(&pidmap_lock, flags);

	for (i = 0; i <= pid->level; i++)
		free_pidmap(pid->numbers + i);

	call_rcu(&pid->rcu, delayed_put_pid);
}

#ifdef CONFIG_HCC_GPM
struct pid *__alloc_pid(struct pid_namespace *ns, const int *req_nr)
#else
struct pid *alloc_pid(struct pid_namespace *ns)
#endif
{
	struct pid *pid;
	enum pid_type type;
	int i, nr;
	struct pid_namespace *tmp;
	struct upid *upid;

	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
	if (!pid)
		goto out;
#ifdef CONFIG_HCC_GPM
	pid->gdm_obj = NULL;
	BUG_ON(req_nr && !is_hcc_pid_ns_root(ns));
#endif

	tmp = ns;
	pid->level = ns->level;
	for (i = ns->level; i >= 0; i--) {
#ifdef CONFIG_HCC_GPM
		if (req_nr && tmp == ns) {
			nr = req_nr[i - tmp->level];
		} else {
#endif
		nr = alloc_pidmap(tmp);
		if (nr < 0)
			goto out_free;
#ifdef CONFIG_HCC_PROC
		if (tmp->global && nr != 1)
			nr = GLOBAL_PID(nr);
#endif
#ifdef CONFIG_HCC_GPM
		}
#endif

		pid->numbers[i].nr = nr;
		pid->numbers[i].ns = tmp;
		tmp = tmp->parent;
	}

	if (unlikely(is_child_reaper(pid))) {
		if (pid_ns_prepare_proc(ns))
			goto out_free;
	}

	get_pid_ns(ns);
	atomic_set(&pid->count, 1);
	for (type = 0; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_HEAD(&pid->tasks[type]);
#ifdef CONFIG_HCC_GSCHED
	for (type = 0; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_HEAD(&pid->process_sets[type]);
#endif

	upid = pid->numbers + ns->level;
	spin_lock_irq(&pidmap_lock);
	if (!(ns->nr_hashed & PIDNS_HASH_ADDING))
		goto out_unlock;
	for ( ; upid >= pid->numbers; --upid) {
		hlist_add_head_rcu(&upid->pid_chain,
				&pid_hash[pid_hashfn(upid->nr, upid->ns)]);
		upid->ns->nr_hashed++;
	}
	spin_unlock_irq(&pidmap_lock);

out:
	return pid;

out_unlock:
	spin_unlock_irq(&pidmap_lock);
	put_pid_ns(ns);

out_free:
#ifdef CONFIG_HCC_GPM
	BUG_ON(req_nr);
#endif
	while (++i <= ns->level)
		free_pidmap(pid->numbers + i);

	kmem_cache_free(ns->pid_cachep, pid);
	pid = NULL;
	goto out;
}

void disable_pid_allocation(struct pid_namespace *ns)
{
	spin_lock_irq(&pidmap_lock);
	ns->nr_hashed &= ~PIDNS_HASH_ADDING;
	spin_unlock_irq(&pidmap_lock);
}

struct pid *find_pid_ns(int nr, struct pid_namespace *ns)
{
	struct hlist_node *elem;
	struct upid *pnr;

	hlist_for_each_entry_rcu(pnr, elem,
			&pid_hash[pid_hashfn(nr, ns)], pid_chain)
		if (pnr->nr == nr && pnr->ns == ns)
			return container_of(pnr, struct pid,
					numbers[ns->level]);

	return NULL;
}
EXPORT_SYMBOL_GPL(find_pid_ns);

struct pid *find_vpid(int nr)
{
	return find_pid_ns(nr, task_active_pid_ns(current));
}
EXPORT_SYMBOL_GPL(find_vpid);

/*
 * attach_pid() must be called with the tasklist_lock write-held.
 */
void attach_pid(struct task_struct *task, enum pid_type type,
		struct pid *pid)
{
	struct pid_link *link;

	link = &task->pids[type];
	link->pid = pid;
	hlist_add_head_rcu(&link->node, &pid->tasks[type]);
}

static void __change_pid(struct task_struct *task, enum pid_type type,
			struct pid *new)
{
	struct pid_link *link;
	struct pid *pid;
	int tmp;

	link = &task->pids[type];
	pid = link->pid;

	hlist_del_rcu(&link->node);
	link->pid = new;

	for (tmp = PIDTYPE_MAX; --tmp >= 0; )
		if (!hlist_empty(&pid->tasks[tmp]))
			return;

#ifdef CONFIG_HCC_GPM
	hcc_put_pid(pid);
#else
	free_pid(pid);
#endif
}

void detach_pid(struct task_struct *task, enum pid_type type)
{
	__change_pid(task, type, NULL);
}

void change_pid(struct task_struct *task, enum pid_type type,
		struct pid *pid)
{
	__change_pid(task, type, pid);
	attach_pid(task, type, pid);
}

/* transfer_pid is an optimization of attach_pid(new), detach_pid(old) */
void transfer_pid(struct task_struct *old, struct task_struct *new,
			   enum pid_type type)
{
	new->pids[type].pid = old->pids[type].pid;
	hlist_replace_rcu(&old->pids[type].node, &new->pids[type].node);
}

struct task_struct *pid_task(struct pid *pid, enum pid_type type)
{
	struct task_struct *result = NULL;
	if (pid) {
		struct hlist_node *first;
		first = rcu_dereference(pid->tasks[type].first);
		if (first)
			result = hlist_entry(first, struct task_struct, pids[(type)].node);
	}
	return result;
}
EXPORT_SYMBOL(pid_task);

/*
 * Must be called under rcu_read_lock() or with tasklist_lock read-held.
 */
struct task_struct *find_task_by_pid_ns(pid_t nr, struct pid_namespace *ns)
{
	return pid_task(find_pid_ns(nr, ns), PIDTYPE_PID);
}

struct task_struct *find_task_by_vpid(pid_t vnr)
{
	return find_task_by_pid_ns(vnr, task_active_pid_ns(current));
}

struct pid *get_task_pid(struct task_struct *task, enum pid_type type)
{
	struct pid *pid;
	rcu_read_lock();
	if (type != PIDTYPE_PID)
		task = task->group_leader;
	pid = get_pid(task->pids[type].pid);
	rcu_read_unlock();
	return pid;
}
EXPORT_SYMBOL_GPL(get_task_pid);

struct task_struct *get_pid_task(struct pid *pid, enum pid_type type)
{
	struct task_struct *result;
	rcu_read_lock();
	result = pid_task(pid, type);
	if (result)
		get_task_struct(result);
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(get_pid_task);

struct pid *find_get_pid(pid_t nr)
{
	struct pid *pid;

	rcu_read_lock();
	pid = get_pid(find_vpid(nr));
	rcu_read_unlock();

	return pid;
}
EXPORT_SYMBOL_GPL(find_get_pid);

pid_t pid_nr_ns(struct pid *pid, struct pid_namespace *ns)
{
	struct upid *upid;
	pid_t nr = 0;

	if (pid && ns->level <= pid->level) {
		upid = &pid->numbers[ns->level];
		if (upid->ns == ns)
			nr = upid->nr;
	}
	return nr;
}
#ifdef CONFIG_HCC_PROC
EXPORT_SYMBOL(pid_nr_ns);
#endif

pid_t pid_vnr(struct pid *pid)
{
	return pid_nr_ns(pid, task_active_pid_ns(current));
}
EXPORT_SYMBOL_GPL(pid_vnr);

pid_t __task_pid_nr_ns(struct task_struct *task, enum pid_type type,
			struct pid_namespace *ns)
{
	pid_t nr = 0;

	rcu_read_lock();
	if (!ns)
		ns = task_active_pid_ns(current);
	if (likely(pid_alive(task))) {
		if (type != PIDTYPE_PID)
			task = task->group_leader;
		nr = pid_nr_ns(task->pids[type].pid, ns);
	}
	rcu_read_unlock();

	return nr;
}
EXPORT_SYMBOL(__task_pid_nr_ns);

pid_t task_tgid_nr_ns(struct task_struct *tsk, struct pid_namespace *ns)
{
	return pid_nr_ns(task_tgid(tsk), ns);
}
EXPORT_SYMBOL(task_tgid_nr_ns);

struct pid_namespace *task_active_pid_ns(struct task_struct *tsk)
{
	return ns_of_pid(task_pid(tsk));
}
EXPORT_SYMBOL_GPL(task_active_pid_ns);

/*
 * Used by proc to find the first pid that is greater than or equal to nr.
 *
 * If there is a pid at nr this function is exactly the same as find_pid_ns.
 */
struct pid *find_ge_pid(int nr, struct pid_namespace *ns)
{
	struct pid *pid;
#ifdef CONFIG_HCC_PROC
	int global = (nr & GLOBAL_PID_MASK) && ns->global;
#endif

	do {
#ifdef CONFIG_HCC_PROC
		if (global && !(nr & GLOBAL_PID_MASK))
			nr = GLOBAL_PID(nr);
#endif
		pid = find_pid_ns(nr, ns);
		if (pid)
			break;
#ifdef CONFIG_HCC_PROC
		if (global) {
			if (ORIG_NODE(nr) != hcc_node_id)
				break;
			nr = SHORT_PID(nr);
		}
#endif
		nr = next_pidmap(ns, nr);
	} while (nr > 0);
#ifdef CONFIG_HCC_PROC
	if (nr <= 0 && !global && ns->global)
		return find_ge_pid(GLOBAL_PID(0), ns);
#endif

	return pid;
}

#ifdef CONFIG_HCC_PROC
struct pid *hcc_find_ge_pid(int nr, struct pid_namespace *pid_ns,
			    struct pid_namespace *pidmap_ns)
{
	hcc_node_t node = ORIG_NODE(nr);
	struct pid *pid;

	BUG_ON(!pid_ns->global);
	BUG_ON(!(nr & GLOBAL_PID_MASK));

	do {
		pid = find_pid_ns(nr, pid_ns);
		if (pid)
			break;
		nr = next_pidmap(pidmap_ns, SHORT_PID(nr));
		if (nr > 0)
			nr = GLOBAL_PID_NODE(nr, node);
	} while (nr > 0);

	return pid;
}
#endif /* CONFIG_HCC_PROC */

/*
 * The pid hash table is scaled according to the amount of memory in the
 * machine.  From a minimum of 16 slots up to 4096 slots at one gigabyte or
 * more.
 */
void __init pidhash_init(void)
{
	unsigned int i, pidhash_size;

	pid_hash = alloc_large_system_hash("PID", sizeof(*pid_hash), 0, 18,
					   HASH_EARLY | HASH_SMALL,
					   &pidhash_shift, NULL, 4096);
	pidhash_size = 1U << pidhash_shift;

	for (i = 0; i < pidhash_size; i++)
		INIT_HLIST_HEAD(&pid_hash[i]);
}

void __init pidmap_init(void)
{
	/* Veryify no one has done anything silly */
	BUILD_BUG_ON(PID_MAX_LIMIT >= PIDNS_HASH_ADDING);

	/* bump default and minimum pid_max based on number of cpus */
	pid_max = min(pid_max_max, max_t(int, pid_max,
				PIDS_PER_CPU_DEFAULT * num_possible_cpus()));
	pid_max_min = max_t(int, pid_max_min,
				PIDS_PER_CPU_MIN * num_possible_cpus());
	pr_info("pid_max: default: %u minimum: %u\n", pid_max, pid_max_min);

	init_pid_ns.pidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	/* Reserve PID 0. We never call free_pidmap(0) */
	set_bit(0, init_pid_ns.pidmap[0].page);
	atomic_dec(&init_pid_ns.pidmap[0].nr_free);
	init_pid_ns.nr_hashed = PIDNS_HASH_ADDING;

	init_pid_ns.pid_cachep = KMEM_CACHE(pid,
			SLAB_HWCACHE_ALIGN | SLAB_PANIC);
}