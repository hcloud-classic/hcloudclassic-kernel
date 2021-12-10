#ifndef BLK_INTERNAL_H
#define BLK_INTERNAL_H

/* Amount of time in which a process may batch requests */
#define BLK_BATCH_TIME	(HZ/50UL)

/* Number of requests a "batching" process may submit */
#define BLK_BATCH_REQ	32

extern struct kmem_cache *blk_requestq_cachep;
extern struct kobj_type blk_queue_ktype;

static inline void __blk_get_queue(struct request_queue *q)
{
	kobject_get(&q->kobj);
}

void init_request_from_bio(struct request *req, struct bio *bio);
void blk_rq_bio_prep(struct request_queue *q, struct request *rq,
			struct bio *bio);
int blk_rq_append_bio(struct request_queue *q, struct request *rq,
		      struct bio *bio);
void blk_drain_queue(struct request_queue *q, bool drain_all);
void blk_dequeue_request(struct request *rq);
void __blk_queue_free_tags(struct request_queue *q);

void blk_unplug_work(struct work_struct *work);
void blk_unplug_timeout(unsigned long data);
void blk_rq_timed_out_timer(unsigned long data);
void blk_delete_timer(struct request *);
void blk_add_timer(struct request *);
void __generic_unplug_device(struct request_queue *);

/*
 * Internal atomic flags for request handling
 */
enum rq_atomic_flags {
	REQ_ATOM_COMPLETE = 0,
};

/*
 * EH timer and IO completion will both attempt to 'grab' the request, make
 * sure that only one of them suceeds
 */
static inline int blk_mark_rq_complete(struct request *rq)
{
	return test_and_set_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags);
}

static inline void blk_clear_rq_complete(struct request *rq)
{
	clear_bit(REQ_ATOM_COMPLETE, &rq->atomic_flags);
}

/*
 * Internal elevator interface
 */
#define ELV_ON_HASH(rq)		(!hlist_unhashed(&(rq)->hash))

void blk_insert_flush(struct request *rq);
void blk_abort_flushes(struct request_queue *q);

static inline struct request *__elv_next_request(struct request_queue *q)
{
	struct request *rq;

	while (1) {
		if (!list_empty(&q->queue_head)) {
			rq = list_entry_rq(q->queue_head.next);
			return rq;
		}
		/*
		 * Flush request is running and flush request isn't queueable
		 * in the drive, we can hold the queue till flush request is
		 * finished. Even we don't do this, driver can't dispatch next
		 * requests and will requeue them. And this can improve
		 * throughput too. For example, we have request flush1, write1,
		 * flush 2. flush1 is dispatched, then queue is hold, write1
		 * isn't inserted to queue. After flush1 is finished, flush2
		 * will be dispatched. Since disk cache is already clean,
		 * flush2 will be finished very soon, so looks like flush2 is
		 * folded to flush1.
		 * Since the queue is hold, a flag is set to indicate the queue
		 * should be restarted later. Please see flush_end_io() for
		 * details.
		 */
		if (q->flush_pending_idx != q->flush_running_idx &&
				!queue_flush_queueable(q)) {
			q->flush_queue_delayed = 1;
			return NULL;
		}
		if (unlikely(blk_queue_dying(q)) ||
		    !q->elevator->ops->elevator_dispatch_fn(q, 0))
			return NULL;
	}
}

static inline void elv_activate_rq(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e->ops->elevator_activate_req_fn)
		e->ops->elevator_activate_req_fn(q, rq);
}

static inline void elv_deactivate_rq(struct request_queue *q, struct request *rq)
{
	struct elevator_queue *e = q->elevator;

	if (e->ops->elevator_deactivate_req_fn)
		e->ops->elevator_deactivate_req_fn(q, rq);
}

#ifdef CONFIG_FAIL_IO_TIMEOUT
int blk_should_fake_timeout(struct request_queue *);
ssize_t part_timeout_show(struct device *, struct device_attribute *, char *);
ssize_t part_timeout_store(struct device *, struct device_attribute *,
				const char *, size_t);
#else
static inline int blk_should_fake_timeout(struct request_queue *q)
{
	return 0;
}
#endif

struct io_context *current_io_context(gfp_t gfp_flags, int node);

int ll_back_merge_fn(struct request_queue *q, struct request *req,
		     struct bio *bio);
int ll_front_merge_fn(struct request_queue *q, struct request *req, 
		      struct bio *bio);
int attempt_back_merge(struct request_queue *q, struct request *rq);
int attempt_front_merge(struct request_queue *q, struct request *rq);
void blk_recalc_rq_segments(struct request *rq);
void blk_rq_set_mixed_merge(struct request *rq);
bool blk_rq_merge_ok(struct request *rq, struct bio *bio);
int blk_try_merge(struct request *rq, struct bio *bio);

void blk_queue_congestion_threshold(struct request_queue *q);

void __blk_run_queue_uncond(struct request_queue *q);

int blk_dev_init(void);

void elv_quiesce_start(struct request_queue *q);
void elv_quiesce_end(struct request_queue *q);


/*
 * Return the threshold (number of used requests) at which the queue is
 * considered to be congested.  It include a little hysteresis to keep the
 * context switch rate down.
 */
static inline int queue_congestion_on_threshold(struct request_queue *q)
{
	return q->nr_congestion_on;
}

/*
 * The threshold at which a queue is considered to be uncongested
 */
static inline int queue_congestion_off_threshold(struct request_queue *q)
{
	return q->nr_congestion_off;
}

#if defined(CONFIG_BLK_DEV_INTEGRITY)

#define rq_for_each_integrity_segment(bvl, _rq, _iter)		\
	__rq_for_each_bio(_iter.bio, _rq)			\
		bip_for_each_vec(bvl, _iter.bio->bi_integrity, _iter.i)

#endif /* BLK_DEV_INTEGRITY */

static inline int blk_cpu_to_group(int cpu)
{
	int group = NR_CPUS;
#ifdef CONFIG_SCHED_MC
	const struct cpumask *mask = cpu_coregroup_mask(cpu);
	group = cpumask_first(mask);
#elif defined(CONFIG_SCHED_SMT)
	group = cpumask_first(topology_thread_cpumask(cpu));
#else
	return cpu;
#endif

	if (likely(group < NR_CPUS))
		return group;
	return cpu;
}

/*
 * Contribute to IO statistics IFF:
 *
 *	a) it's attached to a gendisk, and
 *	b) the queue had IO stats enabled when this request was started, and
 *	c) it's a file system request
 */
static inline int blk_do_io_stat(struct request *rq)
{
	return rq->rq_disk &&
	       (rq->cmd_flags & REQ_IO_STAT) &&
		(rq->cmd_type == REQ_TYPE_FS);
}

bool part_valid(struct gendisk *disk, struct hd_struct *check);

/*
 * KABI hack: rq->part is only valid if drive_stat_acct was called.
 * Unfortunately, we can't know whether it was called.  Some 3rd party
 * drivers copy parts of a struct request to a new request, and then
 * issue I/O with that new request.  We can't guarantee that they
 * copied rq->part, nor can we guarantee that they even initialized it
 * to NULL.  So, check to see if rq->part points to a valid hd_struct.
 * If it doesn't, fall back to the old method of using disk_map_sector_rcu.
 * This function must be called with rcu_read_lock held.
 */
static inline struct hd_struct *req_to_part(struct request *rq)
{
	struct hd_struct *part = disk_map_sector_rcu(rq->rq_disk,
						     blk_rq_pos(rq));
	/*
	 * The most common case is that the partition in the request
	 * matches the one we found in the lookup.
	 */
	if (likely(rq->part == part))
		return part;

	/*
	 * Some drivers copy portions of struct request, but not all
	 * of it.  If req->part is NULL, just return the result of
	 * the lookup.
	 */
	if (rq->part == NULL)
		return part;

	/*
	 * In rare cases, partitions may overlap.  Here we check to
	 * see if rq->part is actually a valid hd_struct.  If it is,
	 * return it.  If not, return the result of the lookup.
	 */
	if (part_valid(rq->rq_disk, rq->part))
		return rq->part;

	return part;
}

#ifdef CONFIG_BLK_DEV_THROTTLING
extern bool blk_throtl_bio(struct request_queue *q, struct bio *bio);
extern void blk_throtl_drain(struct request_queue *q);
extern int blk_throtl_init(struct request_queue *q);
extern void blk_throtl_exit(struct request_queue *q);
extern void blk_throtl_release(struct request_queue *q);
#else /* CONFIG_BLK_DEV_THROTTLING */
static inline bool blk_throtl_bio(struct request_queue *q, struct bio *bio)
{
	return false;
}
static inline void blk_throtl_drain(struct request_queue *q) { }
static inline int blk_throtl_init(struct request_queue *q) { return 0; }
static inline void blk_throtl_exit(struct request_queue *q) { }
static inline void blk_throtl_release(struct request_queue *q) { }
#endif /* CONFIG_BLK_DEV_THROTTLING */

#endif /* BLK_INTERNAL_H */
