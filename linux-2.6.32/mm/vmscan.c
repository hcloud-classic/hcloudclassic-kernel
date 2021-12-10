/*
 *  linux/mm/vmscan.c
 *
 *  Copyright (C) 1991, 1992, 1993, 1994  Linus Torvalds
 *
 *  Swap reorganised 29.12.95, Stephen Tweedie.
 *  kswapd added: 7.1.96  sct
 *  Removed kswapd_ctl limits, and swap out as many pages as needed
 *  to bring the system back to freepages.high: 2.4.97, Rik van Riel.
 *  Zone aware kswapd started 02/00, Kanoj Sarcar (kanoj@sgi.com).
 *  Multiqueue VM started 5.8.00, Rik van Riel.
 */

#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	/* for try_to_release_page(),
					buffer_heads_over_limit */
#include <linux/mm_inline.h>
#include <linux/pagevec.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/compaction.h>
#include <trace/events/kmem.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>

#include <linux/swapops.h>

#include "internal.h"

#ifdef CONFIG_HCC_GMM
#include <net/grpc/grpc.h>
#endif

#define GRPC_MAX_PAGES 1700

struct scan_control {
	/* Incremented by the number of inactive pages that were scanned */
	unsigned long nr_scanned;

	/* Number of pages freed so far during a call to shrink_zones() */
	unsigned long nr_reclaimed;

	/* How many pages shrink_list() should reclaim */
	unsigned long nr_to_reclaim;

	unsigned long hibernation_mode;

	/* This context's GFP mask */
	gfp_t gfp_mask;

	int may_writepage;

	/* Can mapped pages be reclaimed? */
	int may_unmap;

	/* Can pages be swapped as part of reclaim? */
	int may_swap;

	int swappiness;

	int all_unreclaimable;

	int order;

	/*
	 * The memory cgroup that hit its limit and as a result is the
	 * primary target of this reclaim invocation.
	 */
	struct mem_cgroup *target_mem_cgroup;

	/*
	 * Nodemask of nodes allowed by the caller. If NULL, all nodes
	 * are scanned.
	 */
	nodemask_t	*nodemask;

	/* Force scanning of anon pages if OOM kill is imminent */
	bool oom_force_anon_scan;
};

struct mem_cgroup_zone {
	struct mem_cgroup *mem_cgroup;
	struct zone *zone;
};

#define lru_to_page(_head) (list_entry((_head)->prev, struct page, lru))

#ifdef ARCH_HAS_PREFETCH
#define prefetch_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetch(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetch_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

#ifdef ARCH_HAS_PREFETCHW
#define prefetchw_prev_lru_page(_page, _base, _field)			\
	do {								\
		if ((_page)->lru.prev != _base) {			\
			struct page *prev;				\
									\
			prev = lru_to_page(&(_page->lru));		\
			prefetchw(&prev->_field);			\
		}							\
	} while (0)
#else
#define prefetchw_prev_lru_page(_page, _base, _field) do { } while (0)
#endif

/*
 * From 0 .. 100.  Higher means more swappy.
 */
int vm_swappiness = 60;
unsigned long vm_total_pages;	/* The total number of pages which the VM controls */

static LIST_HEAD(shrinker_list);
static DECLARE_RWSEM(shrinker_rwsem);

#ifdef CONFIG_CGROUP_MEM_RES_CTLR
static bool global_reclaim(struct scan_control *sc)
{
	return !sc->target_mem_cgroup;
}

static bool scanning_global_lru(struct mem_cgroup_zone *mz)
{
	return !mz->mem_cgroup;
}
#else
static bool global_reclaim(struct scan_control *sc)
{
	return true;
}

static bool scanning_global_lru(struct mem_cgroup_zone *mz)
{
	return true;
}
#endif

static struct zone_reclaim_stat *get_reclaim_stat(struct mem_cgroup_zone *mz)
{
	if (!scanning_global_lru(mz))
		return mem_cgroup_get_reclaim_stat(mz->mem_cgroup, mz->zone);

	return &mz->zone->reclaim_stat;
}

static unsigned long zone_nr_lru_pages(struct mem_cgroup_zone *mz,
				       enum lru_list lru)
{
	if (!scanning_global_lru(mz))
		return mem_cgroup_zone_nr_pages(mz->mem_cgroup, mz->zone, lru);

	return zone_page_state(mz->zone, NR_LRU_BASE + lru);
}


/*
 * Add a shrinker callback to be called from the vm
 */
void register_shrinker(struct shrinker *shrinker)
{
	shrinker->nr = 0;
	down_write(&shrinker_rwsem);
	list_add_tail(&shrinker->list, &shrinker_list);
	up_write(&shrinker_rwsem);
}
EXPORT_SYMBOL(register_shrinker);

/*
 * Remove one
 */
void unregister_shrinker(struct shrinker *shrinker)
{
	down_write(&shrinker_rwsem);
	list_del(&shrinker->list);
	up_write(&shrinker_rwsem);
}
EXPORT_SYMBOL(unregister_shrinker);

#define SHRINK_BATCH 128
/*
 * Call the shrink functions to age shrinkable caches
 *
 * Here we assume it costs one seek to replace a lru page and that it also
 * takes a seek to recreate a cache object.  With this in mind we age equal
 * percentages of the lru and ageable caches.  This should balance the seeks
 * generated by these structures.
 *
 * If the vm encountered mapped pages on the LRU it increase the pressure on
 * slab to avoid swapping.
 *
 * We do weird things to avoid (scanned*seeks*entries) overflowing 32 bits.
 *
 * `lru_pages' represents the number of on-LRU pages in all the zones which
 * are eligible for the caller's allocation attempt.  It is used for balancing
 * slab reclaim versus page reclaim.
 *
 * Returns the number of slab objects which we shrunk.
 */
unsigned long shrink_slab(unsigned long scanned, gfp_t gfp_mask,
			unsigned long lru_pages)
{
	struct shrinker *shrinker;
	unsigned long ret = 0;

	if (scanned == 0)
		scanned = SWAP_CLUSTER_MAX;

	if (!down_read_trylock(&shrinker_rwsem)) {
		/* Assume we'll be able to shrink next time */
		ret = 1;
		goto out;
	}

	list_for_each_entry(shrinker, &shrinker_list, list) {
		unsigned long long delta;
		unsigned long total_scan;
		unsigned long max_pass;

		max_pass = (*shrinker->shrink)(shrinker, 0, gfp_mask);
		/* -> shrink returns an int; many have overflow issues */
		if (max_pass > INT_MAX)
			max_pass = INT_MAX;
		delta = (4 * scanned) / shrinker->seeks;
		delta *= max_pass;
		do_div(delta, lru_pages + 1);
		shrinker->nr += delta;
		if (shrinker->nr < 0) {
			printk(KERN_ERR "shrink_slab: %pF negative objects to "
			       "delete nr=%ld\n",
			       shrinker->shrink, shrinker->nr);
			shrinker->nr = max_pass;
		}

		/*
		 * Avoid risking looping forever due to too large nr value:
		 * never try to free more than twice the estimate number of
		 * freeable entries.
		 */
		if (shrinker->nr > max_pass * 2)
			shrinker->nr = max_pass * 2;

		total_scan = shrinker->nr;
		shrinker->nr = 0;

		while (total_scan >= SHRINK_BATCH) {
			long this_scan = SHRINK_BATCH;
			int shrink_ret;
			int nr_before;

			nr_before = (*shrinker->shrink)(shrinker, 0, gfp_mask);
			shrink_ret = (*shrinker->shrink)(shrinker, this_scan,
								gfp_mask);
			if (shrink_ret == -1)
				break;
			if (shrink_ret < nr_before)
				ret += nr_before - shrink_ret;
			count_vm_events(SLABS_SCANNED, this_scan);
			total_scan -= this_scan;

			cond_resched();
		}

		shrinker->nr += total_scan;
	}
	up_read(&shrinker_rwsem);
out:
	cond_resched();
	return ret;
}

static inline int is_page_cache_freeable(struct page *page)
{
	/*
	 * A freeable page cache page is referenced only by the caller
	 * that isolated the page, the page cache radix tree and
	 * optional buffer heads at page->private.
	 */
	return page_count(page) - page_has_private(page) == 2;
}

static int may_write_to_queue(struct backing_dev_info *bdi)
{
	if (current->flags & PF_SWAPWRITE)
		return 1;
	if (!bdi_write_congested(bdi))
		return 1;
	if (bdi == current->backing_dev_info)
		return 1;
	return 0;
}

/*
 * We detected a synchronous write error writing a page out.  Probably
 * -ENOSPC.  We need to propagate that into the address_space for a subsequent
 * fsync(), msync() or close().
 *
 * The tricky part is that after writepage we cannot touch the mapping: nothing
 * prevents it from being freed up.  But we have a ref on the page and once
 * that page is locked, the mapping is pinned.
 *
 * We're allowed to run sleeping lock_page() here because we know the caller has
 * __GFP_FS.
 */
static void handle_write_error(struct address_space *mapping,
				struct page *page, int error)
{
	lock_page(page);
	if (page_mapping(page) == mapping)
		mapping_set_error(mapping, error);
	unlock_page(page);
}

/* Request for sync pageout. */
enum pageout_io {
	PAGEOUT_IO_ASYNC,
	PAGEOUT_IO_SYNC,
};

/* possible outcome of pageout() */
typedef enum {
	/* failed to write page out, page is locked */
	PAGE_KEEP,
	/* move page to the active list, page is locked */
	PAGE_ACTIVATE,
	/* page has been sent to the disk successfully, page is unlocked */
	PAGE_SUCCESS,
	/* page is clean and locked */
	PAGE_CLEAN,
} pageout_t;

/*
 * pageout is called by shrink_page_list() for each dirty page.
 * Calls ->writepage().
 */
static pageout_t pageout(struct page *page, struct address_space *mapping,
						enum pageout_io sync_writeback)
{
	/*
	 * If the page is dirty, only perform writeback if that write
	 * will be non-blocking.  To prevent this allocation from being
	 * stalled by pagecache activity.  But note that there may be
	 * stalls if we need to run get_block().  We could test
	 * PagePrivate for that.
	 *
	 * If this process is currently in generic_file_write() against
	 * this page's queue, we can perform writeback even if that
	 * will block.
	 *
	 * If the page is swapcache, write it back even if that would
	 * block, for some throttling. This happens by accident, because
	 * swap_backing_dev_info is bust: it doesn't reflect the
	 * congestion state of the swapdevs.  Easy to fix, if needed.
	 */
	if (!is_page_cache_freeable(page))
		return PAGE_KEEP;
	if (!mapping) {
		/*
		 * Some data journaling orphaned pages can have
		 * page->mapping == NULL while being dirty with clean buffers.
		 */
		if (page_has_private(page)) {
			if (try_to_free_buffers(page)) {
				ClearPageDirty(page);
				printk("%s: orphaned page\n", __func__);
				return PAGE_CLEAN;
			}
		}
		return PAGE_KEEP;
	}
	if (mapping->a_ops->writepage == NULL)
		return PAGE_ACTIVATE;
	if (!may_write_to_queue(mapping->backing_dev_info))
		return PAGE_KEEP;

	if (clear_page_dirty_for_io(page)) {
		int res;
		struct writeback_control wbc = {
			.sync_mode = WB_SYNC_NONE,
			.nr_to_write = SWAP_CLUSTER_MAX,
			.range_start = 0,
			.range_end = LLONG_MAX,
			.nonblocking = 1,
			.for_reclaim = 1,
		};

		SetPageReclaim(page);
		res = mapping->a_ops->writepage(page, &wbc);
		if (res < 0)
			handle_write_error(mapping, page, res);
		if (res == AOP_WRITEPAGE_ACTIVATE) {
			ClearPageReclaim(page);
			return PAGE_ACTIVATE;
		}

		if (!PageWriteback(page)) {
			/* synchronous write or broken a_ops? */
			ClearPageReclaim(page);
		}
		trace_mm_vmscan_writepage(page,
			page_is_file_cache(page),
			sync_writeback == PAGEOUT_IO_SYNC);
		inc_zone_page_state(page, NR_VMSCAN_WRITE);
		trace_mm_pagereclaim_pgout(mapping, page->index<<PAGE_SHIFT,
					PageAnon(page), page_is_file_cache(page));
		return PAGE_SUCCESS;
	}

	return PAGE_CLEAN;
}

/*
 * Same as remove_mapping, but if the page is removed from the mapping, it
 * gets returned with a refcount of 0.
 */
static int __remove_mapping(struct address_space *mapping, struct page *page)
{
	struct inode *inode = mapping->host;

	BUG_ON(!PageLocked(page));
	BUG_ON(mapping != page_mapping(page));

	spin_lock_irq(&mapping->tree_lock);
	/*
	 * The non racy check for a busy page.
	 *
	 * Must be careful with the order of the tests. When someone has
	 * a ref to the page, it may be possible that they dirty it then
	 * drop the reference. So if PageDirty is tested before page_count
	 * here, then the following race may occur:
	 *
	 * get_user_pages(&page);
	 * [user mapping goes away]
	 * write_to(page);
	 *				!PageDirty(page)    [good]
	 * SetPageDirty(page);
	 * put_page(page);
	 *				!page_count(page)   [good, discard it]
	 *
	 * [oops, our write_to data is lost]
	 *
	 * Reversing the order of the tests ensures such a situation cannot
	 * escape unnoticed. The smp_rmb is needed to ensure the page->flags
	 * load is not satisfied before that of page->_count.
	 *
	 * Note that if SetPageDirty is always performed via set_page_dirty,
	 * and thus under tree_lock, then this ordering is not required.
	 */
	if (!page_freeze_refs(page, 2))
		goto cannot_free;
	/* note: atomic_cmpxchg in page_freeze_refs provides the smp_rmb */
	if (unlikely(PageDirty(page))) {
		page_unfreeze_refs(page, 2);
		goto cannot_free;
	}

	if (PageSwapCache(page)) {
		swp_entry_t swap = { .val = page_private(page) };
		__delete_from_swap_cache(page);
		spin_unlock_irq(&mapping->tree_lock);
		swapcache_free(swap, page);
	} else {
		void (*freepage)(struct page *) = NULL;

		if (IS_AOP_EXT(inode))
			freepage = EXT_AOPS(mapping->a_ops)->freepage;

		__remove_from_page_cache(page);
		spin_unlock_irq(&mapping->tree_lock);
		mem_cgroup_uncharge_cache_page(page);

		if (freepage != NULL)
			freepage(page);
	}

	return 1;

cannot_free:
	spin_unlock_irq(&mapping->tree_lock);
	return 0;
}

/*
 * Attempt to detach a locked page from its ->mapping.  If it is dirty or if
 * someone else has a ref on the page, abort and return 0.  If it was
 * successfully detached, return 1.  Assumes the caller has a single ref on
 * this page.
 */
int remove_mapping(struct address_space *mapping, struct page *page)
{
	if (__remove_mapping(mapping, page)) {
		/*
		 * Unfreezing the refcount with 1 rather than 2 effectively
		 * drops the pagecache ref for us without requiring another
		 * atomic operation.
		 */
		page_unfreeze_refs(page, 1);
		return 1;
	}
	return 0;
}

/**
 * putback_lru_page - put previously isolated page onto appropriate LRU list
 * @page: page to be put back to appropriate lru list
 *
 * Add previously isolated @page to appropriate LRU list.
 * Page may still be unevictable for other reasons.
 *
 * lru_lock must not be held, interrupts must be enabled.
 */
void putback_lru_page(struct page *page)
{
	int lru;
	int active = !!TestClearPageActive(page);
	int was_unevictable = PageUnevictable(page);

	VM_BUG_ON(PageLRU(page));

redo:
	ClearPageUnevictable(page);

	if (page_evictable(page, NULL)) {
		/*
		 * For evictable pages, we can use the cache.
		 * In event of a race, worst case is we end up with an
		 * unevictable page on [in]active list.
		 * We know how to handle that.
		 */
		lru = active + page_lru_base_type(page);
		lru_cache_add_lru(page, lru);
	} else {
		/*
		 * Put unevictable pages directly on zone's unevictable
		 * list.
		 */
		lru = LRU_UNEVICTABLE;
		add_page_to_unevictable_list(page);
		/*
		 * When racing with an mlock or AS_UNEVICTABLE clearing
		 * (page is unlocked) make sure that if the other thread
		 * does not observe our setting of PG_lru and fails
		 * isolation/check_move_unevictable_page,
		 * we see PG_mlocked/AS_UNEVICTABLE cleared below and move
		 * the page back to the evictable list.
		 *
		 * The other side is TestClearPageMlocked() or shmem_lock().
		 */
		smp_mb();
	}

	/*
	 * page's status can change while we move it among lru. If an evictable
	 * page is on unevictable list, it never be freed. To avoid that,
	 * check after we added it to the list, again.
	 */
	if (lru == LRU_UNEVICTABLE && page_evictable(page, NULL)) {
		if (!isolate_lru_page(page)) {
			put_page(page);
			goto redo;
		}
		/* This means someone else dropped this page from LRU
		 * So, it will be freed or putback to LRU again. There is
		 * nothing to do here.
		 */
	}

	if (was_unevictable && lru != LRU_UNEVICTABLE)
		count_vm_event(UNEVICTABLE_PGRESCUED);
	else if (!was_unevictable && lru == LRU_UNEVICTABLE)
		count_vm_event(UNEVICTABLE_PGCULLED);

	put_page(page);		/* drop ref from isolate */
}

#ifdef CONFIG_HCC_GMM
static int check_injection_flow(void)
{
	long i = 0, limit = GRPC_MAX_PAGES;

	if ((grpc_consumed_bytes() / PAGE_SIZE) < limit)
		return 0;

	if (current_is_kswapd())
		limit = limit / 2;
	else
		limit = 4 * limit / 5;

	while ((grpc_consumed_bytes() / PAGE_SIZE) > limit) {
		schedule();
		i++;
	}

	return 0;
}
#endif

enum page_references {
	PAGEREF_RECLAIM,
	PAGEREF_RECLAIM_CLEAN,
	PAGEREF_KEEP,
	PAGEREF_ACTIVATE,
};

static enum page_references page_check_references(struct page *page,
						  struct mem_cgroup_zone *mz,
						  struct scan_control *sc)
{
	int referenced_ptes, referenced_page;
#ifdef CONFIG_HCC_GMM
	unsigned long long vm_flags;
#else
	unsigned long vm_flags;
#endif

	referenced_ptes = page_referenced(page, 1, sc->target_mem_cgroup,
					  &vm_flags);
	referenced_page = TestClearPageReferenced(page);

	/*
	 * Mlock lost the isolation race with us.  Let try_to_unmap()
	 * move the page to the unevictable list.
	 */
	if (vm_flags & VM_LOCKED)
		return PAGEREF_RECLAIM;

	if (referenced_ptes) {
		if (PageAnon(page))
			return PAGEREF_ACTIVATE;
		/*
		 * All mapped pages start out with page table
		 * references from the instantiating fault, so we need
		 * to look twice if a mapped file page is used more
		 * than once.
		 *
		 * Mark it and spare it for another trip around the
		 * inactive list.  Another page table reference will
		 * lead to its activation.
		 *
		 * Note: the mark is set for activated pages as well
		 * so that recently deactivated but used pages are
		 * quickly recovered.
		 */
		SetPageReferenced(page);

		if (referenced_page)
			return PAGEREF_ACTIVATE;

		return PAGEREF_KEEP;
	}

	/* Reclaim if clean, defer dirty pages to writeback */
	if (referenced_page)
		return PAGEREF_RECLAIM_CLEAN;

	return PAGEREF_RECLAIM;
}

/*
 * shrink_page_list() returns the number of reclaimed pages
 */
static unsigned long shrink_page_list(struct list_head *page_list,
					struct scan_control *sc,
					struct mem_cgroup_zone *mz,
					enum pageout_io sync_writeback,
					int priority,
					unsigned long *ret_nr_dirty,
					unsigned long *ret_nr_writeback)
{
	LIST_HEAD(ret_pages);
	struct pagevec freed_pvec;
	int pgactivate = 0;
	unsigned long nr_dirty = 0;
	unsigned long nr_congested = 0;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_writeback = 0;

	cond_resched();

	pagevec_init(&freed_pvec, 1);
	while (!list_empty(page_list)) {
		enum page_references references;
		struct address_space *mapping;
		struct page *page;
		int may_enter_fs;

		cond_resched();

		page = lru_to_page(page_list);
		list_del(&page->lru);

#ifdef CONFIG_HCC_GMM
		if (PageMigratable(page))
			check_injection_flow();
#endif

		if (!trylock_page(page))
			goto keep;

		VM_BUG_ON(PageActive(page));
		VM_BUG_ON(page_zone(page) != mz->zone);

		sc->nr_scanned++;

		if (unlikely(!page_evictable(page, NULL)))
			goto cull_mlocked;

		if (!sc->may_unmap && page_mapped(page))
			goto keep_locked;

		/* Double the slab pressure for mapped and swapcache pages */
		if (page_mapped(page) || PageSwapCache(page))
			sc->nr_scanned++;

		may_enter_fs = (sc->gfp_mask & __GFP_FS) ||
			(PageSwapCache(page) && (sc->gfp_mask & __GFP_IO));

		if (PageWriteback(page)) {
			/*
			 * memcg doesn't have any dirty pages throttling so we
			 * could easily OOM just because too many pages are in
			 * writeback and there is nothing else to reclaim.
			 *
			 * Check __GFP_IO, certainly because a loop driver
			 * thread might enter reclaim, and deadlock if it waits
			 * on a page for which it is needed to do the write
			 * (loop masks off __GFP_IO|__GFP_FS for this reason);
			 * but more thought would probably show more reasons.
			 *
			 * Don't require __GFP_FS, since we're not going into
			 * the FS, just waiting on its writeback completion.
			 * Worryingly, ext4 gfs2 and xfs allocate pages with
			 * grab_cache_page_write_begin(,,AOP_FLAG_NOFS), so
			 * testing may_enter_fs here is liable to OOM on them.
			 */
			if (global_reclaim(sc) ||
			    !PageReclaim(page) || !(sc->gfp_mask & __GFP_IO)) {
				/*
				 * This is slightly racy - end_page_writeback()
				 * might have just cleared PageReclaim, then
				 * setting PageReclaim here end up interpreted
				 * as PageReadahead - but that does not matter
				 * enough to care.  What we do want is for this
				 * page to have PageReclaim set next time memcg
				 * reclaim reaches the tests above, so it will
				 * then wait_on_page_writeback() to avoid OOM;
				 * and it's also appropriate in global reclaim.
				 */
				SetPageReclaim(page);
				nr_writeback++;
				goto keep_locked;
			}
			wait_on_page_writeback(page);
		}

		references = page_check_references(page, mz, sc);
		switch (references) {
		case PAGEREF_ACTIVATE:
			goto activate_locked;
		case PAGEREF_KEEP:
			goto keep_locked;
		case PAGEREF_RECLAIM:
		case PAGEREF_RECLAIM_CLEAN:
			; /* try to reclaim the page below */
		}

#ifdef CONFIG_HCC_GMM
		if (PageMigratable(page) && (page_mapped(page))) {
			switch (try_to_flush_page(page)) {
			case SWAP_FAIL:
				goto activate_locked;
                        case SWAP_AGAIN:
                                goto keep_locked;
			case SWAP_MLOCK:
				goto cull_mlocked;
			case SWAP_FLUSH_FAIL:
				BUG(); /* TODO: Try a swap on disk */
                        case SWAP_SUCCESS:
                                ; /* try to free the page below */
                        }

			/*
			 *  TODO: check this code. We can probably
			 *  Reuse the code below in the
			 *  page_has_private if section.
			 */
			unlock_page(page);
			if (put_page_testzero(page))
				goto free_it;
			printk ("WARNING: page %p has count %d\n", page,
				page_count(page));
			nr_reclaimed++;
			continue;
		}
#endif
		/*
		 * Anonymous process memory has backing store?
		 * Try to allocate it some swap space here.
		 */
		if (PageAnon(page) && !PageSwapCache(page)) {
			if (!(sc->gfp_mask & __GFP_IO))
				goto keep_locked;
			if (!add_to_swap(page))
				goto activate_locked;
			may_enter_fs = 1;
		}

		mapping = page_mapping(page);

		/*
		 * The page is mapped into the page tables of one or more
		 * processes. Try to unmap it here.
		 */
		if (page_mapped(page) && mapping) {
			switch (try_to_unmap(page, TTU_UNMAP)) {
			case SWAP_FAIL:
				goto activate_locked;
			case SWAP_AGAIN:
				goto keep_locked;
			case SWAP_MLOCK:
				goto cull_mlocked;
			case SWAP_SUCCESS:
				; /* try to free the page below */
			}
		}

		if (PageDirty(page)) {
			nr_dirty++;

			/*
			 * Only kswapd can writeback filesystem pages to
			 * avoid risk of stack overflow but do not writeback
			 * unless under significant pressure.
			 */
			if (page_is_file_cache(page) &&
					(!current_is_kswapd() || priority >= DEF_PRIORITY - 2)) {
				/*
				 * Immediately reclaim when written back.
				 * Similar in principal to deactivate_page()
				 * except we already have the page isolated
				 * and know it's dirty
				 */
				SetPageReclaim(page);

				goto keep_locked;
			}

			if (references == PAGEREF_RECLAIM_CLEAN)
				goto keep_locked;
			if (!may_enter_fs)
				goto keep_locked;
			if (!sc->may_writepage)
				goto keep_locked;

			/* Page is dirty, try to write it out here */
			switch (pageout(page, mapping, sync_writeback)) {
			case PAGE_KEEP:
				nr_congested++;
				goto keep_locked;
			case PAGE_ACTIVATE:
				goto activate_locked;
			case PAGE_SUCCESS:
				if (PageWriteback(page) || PageDirty(page))
					goto keep;
				/*
				 * A synchronous write - probably a ramdisk.  Go
				 * ahead and try to reclaim the page.
				 */
				if (!trylock_page(page))
					goto keep;
				if (PageDirty(page) || PageWriteback(page))
					goto keep_locked;
				mapping = page_mapping(page);
			case PAGE_CLEAN:
				; /* try to free the page below */
			}
		}

		/*
		 * If the page has buffers, try to free the buffer mappings
		 * associated with this page. If we succeed we try to free
		 * the page as well.
		 *
		 * We do this even if the page is PageDirty().
		 * try_to_release_page() does not perform I/O, but it is
		 * possible for a page to have PageDirty set, but it is actually
		 * clean (all its buffers are clean).  This happens if the
		 * buffers were written out directly, with submit_bh(). ext3
		 * will do this, as well as the blockdev mapping.
		 * try_to_release_page() will discover that cleanness and will
		 * drop the buffers and mark the page clean - it can be freed.
		 *
		 * Rarely, pages can have buffers and no ->mapping.  These are
		 * the pages which were not successfully invalidated in
		 * truncate_complete_page().  We try to drop those buffers here
		 * and if that worked, and the page is no longer mapped into
		 * process address space (page_count == 1) it can be freed.
		 * Otherwise, leave the page on the LRU so it is swappable.
		 */
		if (page_has_private(page)) {
#ifdef CONFIG_HCC_GMM
			BUG_ON (page->obj_entry);
#endif
			if (!try_to_release_page(page, sc->gfp_mask))
				goto activate_locked;
			if (!mapping && page_count(page) == 1) {
				unlock_page(page);
				if (put_page_testzero(page))
					goto free_it;
				else {
					/*
					 * rare race with speculative reference.
					 * the speculative reference will free
					 * this page shortly, so we may
					 * increment nr_reclaimed here (and
					 * leave it off the LRU).
					 */
					nr_reclaimed++;
					continue;
				}
			}
		}

		if (!mapping || !__remove_mapping(mapping, page))
			goto keep_locked;

		/*
		 * At this point, we have no other references and there is
		 * no way to pick any more up (removed from LRU, removed
		 * from pagecache). Can use non-atomic bitops now (and
		 * we obviously don't have to worry about waking up a process
		 * waiting on the page lock, because there are no references.
		 */
		__clear_page_locked(page);
free_it:
		nr_reclaimed++;
		if (!pagevec_add(&freed_pvec, page)) {
			__pagevec_free(&freed_pvec);
			pagevec_reinit(&freed_pvec);
		}
		continue;

cull_mlocked:
		if (PageSwapCache(page))
			try_to_free_swap(page);
		unlock_page(page);
		putback_lru_page(page);
		continue;

activate_locked:
		/* Not a candidate for swapping, so reclaim swap space. */
		if (PageSwapCache(page) && vm_swap_full())
			try_to_free_swap(page);
		VM_BUG_ON(PageActive(page));
		SetPageActive(page);
		pgactivate++;
keep_locked:
		unlock_page(page);
keep:
		list_add(&page->lru, &ret_pages);
		VM_BUG_ON(PageLRU(page) || PageUnevictable(page));
	}

	/*
	 * Tag a zone as congested if all the dirty pages encountered were
	 * backed by a congested BDI. In this case, reclaimers should just
	 * back off and wait for congestion to clear because further reclaim
	 * will encounter the same problem
	 */
	if (nr_dirty && nr_dirty == nr_congested && global_reclaim(sc))
		zone_set_flag(mz->zone, ZONE_CONGESTED);

	list_splice(&ret_pages, page_list);
	if (pagevec_count(&freed_pvec))
		__pagevec_free(&freed_pvec);
	count_vm_events(PGACTIVATE, pgactivate);
	trace_mm_pagereclaim_free(nr_reclaimed);
        *ret_nr_dirty += nr_dirty;
        *ret_nr_writeback += nr_writeback;
	return nr_reclaimed;
}

/*
 * Attempt to remove the specified page from its LRU.  Only take this page
 * if it is of the appropriate PageActive status.  Pages which are being
 * freed elsewhere are also ignored.
 *
 * page:	page to consider
 * mode:	one of the LRU isolation modes defined above
 *
 * returns 0 on success, -ve errno on failure.
 */
int __isolate_lru_page(struct page *page, isolate_mode_t mode, int file)
{
	bool all_lru_mode;
	int ret = -EINVAL;

	/* Only take pages on the LRU. */
	if (!PageLRU(page))
		return ret;

	all_lru_mode = (mode & (ISOLATE_ACTIVE|ISOLATE_INACTIVE)) ==
		(ISOLATE_ACTIVE|ISOLATE_INACTIVE);

	/*
	 * When checking the active state, we need to be sure we are
	 * dealing with comparible boolean values.  Take the logical not
	 * of each.
	 */
	if (!all_lru_mode && !PageActive(page) != !(mode & ISOLATE_ACTIVE))
		return ret;

	if (!all_lru_mode && !!page_is_file_cache(page) != file)
		return ret;

	/*
	 * When this function is being called for lumpy reclaim, we
	 * initially look into all LRU pages, active, inactive and
	 * unevictable; only give shrink_page_list evictable pages.
	 */
	if (PageUnevictable(page))
		return ret;

	ret = -EBUSY;

	/*
	 * To minimise LRU disruption, the caller can indicate that it only
	 * wants to isolate pages it will be able to operate on without
	 * blocking - clean pages for the most part.
	 *
	 * ISOLATE_CLEAN means that only clean pages should be isolated. This
	 * is used by reclaim when it is cannot write to backing storage
	 *
	 * ISOLATE_ASYNC_MIGRATE is used to indicate that it only wants to pages
	 * that it is possible to migrate without blocking
	 */
	if (mode & (ISOLATE_CLEAN|ISOLATE_ASYNC_MIGRATE)) {
		/* All the caller can do on PageWriteback is block */
		if (PageWriteback(page))
			return ret;

		if (PageDirty(page)) {
			struct address_space *mapping;

			/* ISOLATE_CLEAN means only clean pages */
			if (mode & ISOLATE_CLEAN)
				return ret;

			/*
			 * Only pages without mappings or that have a
			 * ->migratepage callback are possible to migrate
			 * without blocking
			 */
			mapping = page_mapping(page);
			if (mapping && !mapping->a_ops->migratepage)
				return ret;
		}
	}

	if (likely(get_page_unless_zero(page))) {
		/*
		 * Be careful not to clear PageLRU until after we're
		 * sure the page is not being freed elsewhere -- the
		 * page release code relies on it.
		 */
		ClearPageLRU(page);
		ret = 0;
	}

	return ret;
}

/*
 * zone->lru_lock is heavily contended.  Some of the functions that
 * shrink the lists perform better by taking out a batch of pages
 * and working on them outside the LRU lock.
 *
 * For pagecache intensive workloads, this function is the hottest
 * spot in the kernel (apart from copy_*_user functions).
 *
 * Appropriate locks must be held before calling this function.
 *
 * @nr_to_scan:	The number of pages to look through on the list.
 * @src:	The LRU list to pull pages off.
 * @dst:	The temp list to put pages on to.
 * @scanned:	The number of pages that were scanned.
 * @order:	The caller's attempted allocation order
 * @mode:	One of the LRU isolation modes
 * @file:	True [1] if isolating file [!anon] pages
 *
 * returns how many pages were moved onto *@dst.
 */
static unsigned long isolate_lru_pages(unsigned long nr_to_scan,
		struct list_head *src, struct list_head *dst,
		unsigned long *scanned, int order, isolate_mode_t mode,
		int file)
{
	unsigned long nr_taken = 0;
	unsigned long nr_lumpy_taken = 0, nr_lumpy_dirty = 0, nr_lumpy_failed = 0;
	unsigned long scan;

	for (scan = 0; scan < nr_to_scan && !list_empty(src); scan++) {
		struct page *page;
		unsigned long pfn;
		unsigned long end_pfn;
		unsigned long page_pfn;
		int zone_id;

		page = lru_to_page(src);
		prefetchw_prev_lru_page(page, src, flags);

		VM_BUG_ON(!PageLRU(page));

		switch (__isolate_lru_page(page, mode, file)) {
		case 0:
			mem_cgroup_lru_del(page);
			list_move(&page->lru, dst);
			nr_taken += hpage_nr_pages(page);
			break;

		case -EBUSY:
			/* else it is being freed elsewhere */
			list_move(&page->lru, src);
			continue;

		default:
			BUG();
		}

		if (!order)
			continue;

		/*
		 * Attempt to take all pages in the order aligned region
		 * surrounding the tag page.  Only take those pages of
		 * the same active state as that tag page.  We may safely
		 * round the target page pfn down to the requested order
		 * as the mem_map is guarenteed valid out to MAX_ORDER,
		 * where that page is in a different zone we will detect
		 * it from its zone id and abort this block scan.
		 */
		zone_id = page_zone_id(page);
		page_pfn = page_to_pfn(page);
		pfn = page_pfn & ~((1 << order) - 1);
		end_pfn = pfn + (1 << order);
		for (; pfn < end_pfn; pfn++) {
			struct page *cursor_page;

			/* The target page is in the block, ignore it. */
			if (unlikely(pfn == page_pfn))
				continue;

			/* Avoid holes within the zone. */
			if (unlikely(!pfn_valid_within(pfn)))
				break;

			cursor_page = pfn_to_page(pfn);

			/* Check that we have not crossed a zone boundary. */
			if (unlikely(page_zone_id(cursor_page) != zone_id))
				break;

			/*
			 * If we don't have enough swap space, reclaiming of
			 * anon page which don't already have a swap slot is
			 * pointless.
			 */
			if (get_nr_swap_pages() <= 0 && PageAnon(cursor_page) &&
			    !PageSwapCache(cursor_page))
				break;

			if (__isolate_lru_page(cursor_page, mode, file) == 0) {
				unsigned int isolated_pages;

				mem_cgroup_lru_del(cursor_page);
				list_move(&cursor_page->lru, dst);
				isolated_pages = hpage_nr_pages(page);
				nr_taken += isolated_pages;
				nr_lumpy_taken += isolated_pages;
				if (PageDirty(cursor_page))
					nr_lumpy_dirty += isolated_pages;
				scan++;
				pfn += isolated_pages - 1;
			} else {
				/*
				 * Check if the page is freed already.
				 *
				 * We can't use page_count() as that
				 * requires compound_head and we don't
				 * have a pin on the page here. If a
				 * page is tail, we may or may not
				 * have isolated the head, so assume
				 * it's not free, it'd be tricky to
				 * track the head status without a
				 * page pin.
				 */
				if (!PageTail(cursor_page) &&
				    !atomic_read(&cursor_page->_count))
					continue;
				break;
			}
		}

		/* If we break out of the loop above, lumpy reclaim failed */
		if (pfn < end_pfn)
			nr_lumpy_failed++;
	}

	*scanned = scan;

	trace_mm_vmscan_lru_isolate(order,
			nr_to_scan, scan,
			nr_taken,
			nr_lumpy_taken, nr_lumpy_dirty, nr_lumpy_failed,
			mode);
	return nr_taken;
}

static unsigned long isolate_pages(unsigned long nr, struct mem_cgroup_zone *mz,
				   struct list_head *dst,
				   unsigned long *scanned, int order,
#ifdef CONFIG_HCC_GMM
				   isolate_mode_t mode, int active, int file,
				   int gdm)
#else
				   isolate_mode_t mode, int active, int file)
#endif
{
	struct lruvec *lruvec;
	int lru = LRU_BASE;

	lruvec = mem_cgroup_zone_lruvec(mz->zone, mz->mem_cgroup);
	if (active)
		lru += LRU_ACTIVE;
	if (file)
		lru += LRU_FILE;
#ifdef CONFIG_HCC_GMM
	if (gdm)
		lru += LRU_MIGR;
#endif
	return isolate_lru_pages(nr, &lruvec->lists[lru], dst,
				 scanned, order, mode, file);
}

/*
 * clear_active_flags() is a helper for shrink_active_list(), clearing
 * any active bits from the pages in the list.
 */
static unsigned long clear_active_flags(struct list_head *page_list,
					unsigned int *count)
{
	int nr_active = 0;
	int lru;
	struct page *page;

	list_for_each_entry(page, page_list, lru) {
		int numpages = hpage_nr_pages(page);
		lru = page_lru_base_type(page);
		if (PageActive(page)) {
			lru += LRU_ACTIVE;
			ClearPageActive(page);
			nr_active += numpages;
		}
		count[lru] += numpages;
	}

	return nr_active;
}

/**
 * isolate_lru_page - tries to isolate a page from its LRU list
 * @page: page to isolate from its LRU list
 *
 * Isolates a @page from an LRU list, clears PageLRU and adjusts the
 * vmstat statistic corresponding to whatever LRU list the page was on.
 *
 * Returns 0 if the page was removed from an LRU list.
 * Returns -EBUSY if the page was not on an LRU list.
 *
 * The returned page will have PageLRU() cleared.  If it was found on
 * the active list, it will have PageActive set.  If it was found on
 * the unevictable list, it will have the PageUnevictable bit set. That flag
 * may need to be cleared by the caller before letting the page go.
 *
 * The vmstat statistic corresponding to the list on which the page was
 * found will be decremented.
 *
 * Restrictions:
 * (1) Must be called with an elevated refcount on the page. This is a
 *     fundamentnal difference from isolate_lru_pages (which is called
 *     without a stable reference).
 * (2) the lru_lock must not be held.
 * (3) interrupts must be enabled.
 */
int isolate_lru_page(struct page *page)
{
	int ret = -EBUSY;

	if (PageLRU(page)) {
		struct zone *zone = page_zone(page);

		spin_lock_irq(&zone->lru_lock);
		if (PageLRU(page) && get_page_unless_zero(page)) {
			int lru = page_lru(page);
			ret = 0;
			ClearPageLRU(page);

			del_page_from_lru_list(zone, page, lru);
		}
		spin_unlock_irq(&zone->lru_lock);
	}
	return ret;
}

/*
 * Are there way too many processes in the direct reclaim path already?
 */
static int too_many_isolated(struct zone *zone, int file,
		struct scan_control *sc)
{
	unsigned long inactive, isolated;

	if (current_is_kswapd())
		return 0;

	if (!global_reclaim(sc))
		return 0;

	if (file) {
		inactive = zone_page_state(zone, NR_INACTIVE_FILE);
		isolated = zone_page_state(zone, NR_ISOLATED_FILE);
	} else {
		inactive = zone_page_state(zone, NR_INACTIVE_ANON);
		isolated = zone_page_state(zone, NR_ISOLATED_ANON);
	}

	/*
	 * GFP_NOIO/GFP_NOFS callers are allowed to isolate more pages, so they
	 * won't get blocked by normal direct-reclaimers, forming a circular
	 * deadlock.
	 */
	if ((sc->gfp_mask & GFP_IOFS) == GFP_IOFS)
		inactive >>= 3;

	return isolated > inactive;
}

/*
 * shrink_inactive_list() is a helper for shrink_zone().  It returns the number
 * of reclaimed pages
 */
static unsigned long shrink_inactive_list(unsigned long max_scan,
			struct mem_cgroup_zone *mz, struct scan_control *sc,
#ifdef CONFIG_HCC_GMM
			int priority, int file, int gdm)
#else
			int priority, int file)
#endif
{
	LIST_HEAD(page_list);
	struct pagevec pvec;
	unsigned long nr_scanned = 0;
	unsigned long nr_reclaimed = 0;
        unsigned long nr_dirty = 0;
        unsigned long nr_writeback = 0;
	struct zone_reclaim_stat *reclaim_stat = get_reclaim_stat(mz);
	struct zone *zone = mz->zone;
	int order = 0;
	bool stalled = false;

	if (!COMPACTION_BUILD)
		order = sc->order;

	while (unlikely(too_many_isolated(zone, file, sc))) {
		if (likely(sysctl_legacy_scan_congestion_wait)) {
			congestion_wait(BLK_RW_ASYNC, HZ/10);
		} else {
			if (stalled)
				return 0;

			/* wait a bit for the reclaimer. */
			msleep(100);
			stalled = true;
		}

		/* We are about to die and free our memory. Return now. */
		if (fatal_signal_pending(current))
			return SWAP_CLUSTER_MAX;
	}

	pagevec_init(&pvec, 1);

	lru_add_drain();
	spin_lock_irq(&zone->lru_lock);
	do {
		struct page *page;
		unsigned long nr_taken;
		unsigned long nr_scan;
		unsigned long nr_freed;
		unsigned long nr_active;
		unsigned int count[NR_LRU_LISTS] = { 0, };
		unsigned long nr_anon;
		unsigned long nr_file;
#ifdef CONFIG_HCC_GMM
		unsigned long nr_migr;
#endif

		if (global_reclaim(sc)) {
		nr_taken = isolate_pages(SWAP_CLUSTER_MAX, mz, &page_list,
					 &nr_scan, order,
#ifdef CONFIG_HCC_GMM
					 ISOLATE_INACTIVE, 0, file, gdm);
#else
					 ISOLATE_INACTIVE, 0, file);
#endif

			zone->pages_scanned += nr_scan;
			if (current_is_kswapd())
				__count_zone_vm_events(PGSCAN_KSWAPD, zone,
						       nr_scan);
			else
				__count_zone_vm_events(PGSCAN_DIRECT, zone,
						       nr_scan);
		}

		if (nr_taken == 0)
			goto done;

		nr_active = clear_active_flags(&page_list, count);
		__count_vm_events(PGDEACTIVATE, nr_active);

		__mod_zone_page_state(zone, NR_ACTIVE_FILE,
						-count[LRU_ACTIVE_FILE]);
		__mod_zone_page_state(zone, NR_INACTIVE_FILE,
						-count[LRU_INACTIVE_FILE]);
		__mod_zone_page_state(zone, NR_ACTIVE_ANON,
						-count[LRU_ACTIVE_ANON]);
		__mod_zone_page_state(zone, NR_INACTIVE_ANON,
						-count[LRU_INACTIVE_ANON]);
#ifdef CONFIG_HCC_GMM
		__mod_zone_page_state(zone, NR_ACTIVE_MIGR,
						-count[LRU_ACTIVE_MIGR]);
		__mod_zone_page_state(zone, NR_INACTIVE_MIGR,
						-count[LRU_INACTIVE_MIGR]);
#endif

		nr_anon = count[LRU_ACTIVE_ANON] + count[LRU_INACTIVE_ANON];
		nr_file = count[LRU_ACTIVE_FILE] + count[LRU_INACTIVE_FILE];
#ifdef CONFIG_HCC_GMM
		nr_migr = count[LRU_ACTIVE_MIGR] + count[LRU_INACTIVE_MIGR];
#endif
		__mod_zone_page_state(zone, NR_ISOLATED_ANON, nr_anon);
		__mod_zone_page_state(zone, NR_ISOLATED_FILE, nr_file);
#ifdef CONFIG_HCC_GMM
		__mod_zone_page_state(zone, NR_ISOLATED_MIGR, nr_migr);
#endif

		reclaim_stat->recent_scanned[0] += count[LRU_INACTIVE_ANON];
		reclaim_stat->recent_scanned[0] += count[LRU_ACTIVE_ANON];
		reclaim_stat->recent_scanned[1] += count[LRU_INACTIVE_FILE];
		reclaim_stat->recent_scanned[1] += count[LRU_ACTIVE_FILE];
#ifdef CONFIG_HCC_GMM
		reclaim_stat->recent_scanned[2] += count[LRU_INACTIVE_MIGR];
		reclaim_stat->recent_scanned[2] += count[LRU_ACTIVE_MIGR];
#endif

		spin_unlock_irq(&zone->lru_lock);

		nr_scanned += nr_scan;
		nr_freed = shrink_page_list(&page_list, sc, mz,
					PAGEOUT_IO_ASYNC, priority,
					&nr_dirty, &nr_writeback);

		nr_reclaimed += nr_freed;

		local_irq_disable();
		if (current_is_kswapd())
			__count_vm_events(KSWAPD_STEAL, nr_freed);
		__count_zone_vm_events(PGSTEAL, zone, nr_freed);

		spin_lock(&zone->lru_lock);
		/*
		 * Put back any unfreeable pages.
		 */
		while (!list_empty(&page_list)) {
			int lru;
			page = lru_to_page(&page_list);
			VM_BUG_ON(PageLRU(page));
			list_del(&page->lru);
			if (unlikely(!page_evictable(page, NULL))) {
				spin_unlock_irq(&zone->lru_lock);
				putback_lru_page(page);
				spin_lock_irq(&zone->lru_lock);
				continue;
			}
			SetPageLRU(page);
			lru = page_lru(page);
			add_page_to_lru_list(zone, page, lru);
			if (is_active_lru(lru)) {
#ifdef CONFIG_HCC_GMM
				int file = reclaim_stat_index(page);
#else
				int file = is_file_lru(lru);
#endif
				int numpages = hpage_nr_pages(page);
				reclaim_stat->recent_rotated[file] += numpages;
			}
			if (!pagevec_add(&pvec, page)) {
				spin_unlock_irq(&zone->lru_lock);
				__pagevec_release(&pvec);
				spin_lock_irq(&zone->lru_lock);
			}
		}
		__mod_zone_page_state(zone, NR_ISOLATED_ANON, -nr_anon);
		__mod_zone_page_state(zone, NR_ISOLATED_FILE, -nr_file);
#ifdef CONFIG_HCC_GMM
		__mod_zone_page_state(zone, NR_ISOLATED_MIGR, -nr_migr);
#endif

		/*
		 * If reclaim is isolating dirty pages under writeback, it implies
		 * that the long-lived page allocation rate is exceeding the page
		 * laundering rate. Either the global limits are not being effective
		 * at throttling processes due to the page distribution throughout
		 * zones or there is heavy usage of a slow backing device. The
		 * only option is to throttle from reclaim context which is not ideal
		 * as there is no guarantee the dirtying process is throttled in the
		 * same way balance_dirty_pages() manages.
		 *
		 * This scales the number of dirty pages that must be under writeback
		 * before throttling depending on priority. It is a simple backoff
		 * function that has the most effect in the range DEF_PRIORITY to
		 * DEF_PRIORITY-2 which is the priority reclaim is considered to be
		 * in trouble and reclaim is considered to be in trouble.
		 *
		 * DEF_PRIORITY   100% isolated pages must be PageWriteback to throttle
		 * DEF_PRIORITY-1  50% must be PageWriteback
		 * DEF_PRIORITY-2  25% must be PageWriteback, kswapd in trouble
		 * ...
		 * DEF_PRIORITY-6 For SWAP_CLUSTER_MAX isolated pages, throttle if any
		 *                     isolated page is PageWriteback
		 */
		if (nr_writeback && nr_writeback >=
			(nr_taken >> (DEF_PRIORITY-priority))) {
			spin_unlock_irq(&zone->lru_lock);
			wait_iff_congested(zone, BLK_RW_ASYNC, HZ/10);
			spin_lock_irq(&zone->lru_lock);
		}
  	} while (nr_scanned < max_scan);

done:
	spin_unlock_irq(&zone->lru_lock);
	pagevec_release(&pvec);
	trace_mm_pagereclaim_shrinkinactive(nr_scanned, file, 
				nr_reclaimed, priority);
	return nr_reclaimed;
}

/*
 * We are about to scan this zone at a certain priority level.  If that priority
 * level is smaller (ie: more urgent) than the previous priority, then note
 * that priority level within the zone.  This is done so that when the next
 * process comes in to scan this zone, it will immediately start out at this
 * priority level rather than having to build up its own scanning priority.
 * Here, this priority affects only the reclaim-mapped threshold.
 */
static inline void note_zone_scanning_priority(struct zone *zone, int priority)
{
	if (priority < zone->prev_priority)
		zone->prev_priority = priority;
}

/*
 * This moves pages from the active list to the inactive list.
 *
 * We move them the other way if the page is referenced by one or more
 * processes, from rmap.
 *
 * If the pages are mostly unmapped, the processing is fast and it is
 * appropriate to hold zone->lru_lock across the whole operation.  But if
 * the pages are mapped, the processing is slow (page_referenced()) so we
 * should drop zone->lru_lock around each page.  It's impossible to balance
 * this, so instead we remove the pages from the LRU while processing them.
 * It is safe to rely on PG_active against the non-LRU pages in here because
 * nobody will play with that bit on a non-LRU page.
 *
 * The downside is that we have to touch page->_count against each page.
 * But we had to alter page->flags anyway.
 */

static void move_active_pages_to_lru(struct zone *zone,
				     struct list_head *list,
				     enum lru_list lru)
{
	unsigned long pgmoved = 0;
	struct pagevec pvec;
	struct page *page;

	pagevec_init(&pvec, 1);

	while (!list_empty(list)) {
		struct lruvec *lruvec;

		page = lru_to_page(list);

		VM_BUG_ON(PageLRU(page));
		SetPageLRU(page);

		lruvec = mem_cgroup_lru_add_list(zone, page, lru);
		list_move(&page->lru, &lruvec->lists[lru]);
		pgmoved += hpage_nr_pages(page);

		if (!pagevec_add(&pvec, page) || list_empty(list)) {
			spin_unlock_irq(&zone->lru_lock);
			if (buffer_heads_over_limit)
				pagevec_strip(&pvec);
			__pagevec_release(&pvec);
			spin_lock_irq(&zone->lru_lock);
		}
	}
	__mod_zone_page_state(zone, NR_LRU_BASE + lru, pgmoved);
	if (!is_active_lru(lru))
		__count_vm_events(PGDEACTIVATE, pgmoved);
}

static void shrink_active_list(unsigned long nr_pages,
			       struct mem_cgroup_zone *mz,
			       struct scan_control *sc,
#ifdef CONFIG_HCC_GMM
			       int priority, int file, int gdm)
#else
			       int priority, int file)
#endif
{
	unsigned long nr_taken;
	unsigned long pgscanned;
#ifdef CONFIG_HCC_GMM
	unsigned long long vm_flags;
#else
	unsigned long vm_flags;
#endif
	LIST_HEAD(l_hold);	/* The pages which were snipped off */
	LIST_HEAD(l_active);
	LIST_HEAD(l_inactive);
	struct page *page;
	struct zone_reclaim_stat *reclaim_stat = get_reclaim_stat(mz);
	unsigned long nr_rotated = 0;
	int order = 0;
	struct zone *zone = mz->zone;

	if (!COMPACTION_BUILD)
		order = sc->order;

	lru_add_drain();
	spin_lock_irq(&zone->lru_lock);

	nr_taken = isolate_pages(nr_pages, mz, &l_hold,
				 &pgscanned, order,
#ifdef CONFIG_HCC_GMM
				 ISOLATE_ACTIVE, 1, file, gdm);
#else
				 ISOLATE_ACTIVE, 1, file);
#endif

	if (global_reclaim(sc))
		zone->pages_scanned += pgscanned;

#ifdef CONFIG_HCC_GMM
	reclaim_stat->recent_scanned[RECLAIM_STAT_INDEX(file, gdm)] += nr_taken;
#else
	reclaim_stat->recent_scanned[file] += nr_taken;
#endif

	__count_zone_vm_events(PGREFILL, zone, pgscanned);
	if (file)
		__mod_zone_page_state(zone, NR_ACTIVE_FILE, -nr_taken);
	else
#ifdef CONFIG_HCC_GMM
	if (gdm)
		__mod_zone_page_state(zone, NR_ACTIVE_MIGR, -nr_taken);
	else
#endif
		__mod_zone_page_state(zone, NR_ACTIVE_ANON, -nr_taken);
	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, nr_taken);
	spin_unlock_irq(&zone->lru_lock);

	while (!list_empty(&l_hold)) {
		cond_resched();
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		if (unlikely(!page_evictable(page, NULL))) {
			putback_lru_page(page);
			continue;
		}

		if (page_referenced(page, 0, sc->target_mem_cgroup,
				    &vm_flags)) {
			nr_rotated += hpage_nr_pages(page);
			/*
			 * Identify referenced, file-backed active pages and
			 * give them one more trip around the active list. So
			 * that executable code get better chances to stay in
			 * memory under moderate memory pressure.  Anon pages
			 * are not likely to be evicted by use-once streaming
			 * IO, plus JVM can create lots of anon VM_EXEC pages,
			 * so we ignore them here.
			 */
			if ((vm_flags & VM_EXEC) && page_is_file_cache(page)) {
				list_add(&page->lru, &l_active);
				continue;
			}
		}

		ClearPageActive(page);	/* we are de-activating */
		list_add(&page->lru, &l_inactive);
	}

	/*
	 * Move pages back to the lru list.
	 */
	spin_lock_irq(&zone->lru_lock);
	/*
	 * Count referenced pages from currently used mappings as rotated,
	 * even though only some of them are actually re-activated.  This
	 * helps balance scan pressure between file and anonymous pages in
	 * get_scan_ratio.
	 */
#ifdef CONFIG_HCC_GMM
	reclaim_stat->recent_rotated[RECLAIM_STAT_INDEX(file, gdm)] += nr_rotated;
#else
	reclaim_stat->recent_rotated[file] += nr_rotated;
#endif

	move_active_pages_to_lru(zone, &l_active,
					BUILD_LRU_ID(1 /* active */, file, gdm));
	move_active_pages_to_lru(zone, &l_inactive,
					BUILD_LRU_ID(0 /* inactive */, file, gdm));

	__mod_zone_page_state(zone, NR_ISOLATED_ANON + file, -nr_taken);
	spin_unlock_irq(&zone->lru_lock);
	trace_mm_pagereclaim_shrinkactive(pgscanned, file, priority);  
}

static int inactive_anon_is_low_global(struct zone *zone)
{
	unsigned long active, inactive;

	active = zone_page_state(zone, NR_ACTIVE_ANON);
	inactive = zone_page_state(zone, NR_INACTIVE_ANON);

	if (inactive * zone->inactive_ratio < active)
		return 1;

	return 0;
}

/**
 * inactive_anon_is_low - check if anonymous pages need to be deactivated
 * @zone: zone to check
 * @sc:   scan control of this context
 *
 * Returns true if the zone does not have enough inactive anon pages,
 * meaning some active anon pages need to be deactivated.
 */
static int inactive_anon_is_low(struct mem_cgroup_zone *mz)
{
	if (!scanning_global_lru(mz))
		return mem_cgroup_inactive_anon_is_low(mz->mem_cgroup,
						       mz->zone);

	return inactive_anon_is_low_global(mz->zone);
}

static int inactive_file_is_low_global(struct zone *zone)
{
	unsigned long active, inactive;

	active = zone_page_state(zone, NR_ACTIVE_FILE);
	inactive = zone_page_state(zone, NR_INACTIVE_FILE);

	return (active > inactive);
}

/**
 * inactive_file_is_low - check if file pages need to be deactivated
 * @mz: memory cgroup and zone to check
 *
 * When the system is doing streaming IO, memory pressure here
 * ensures that active file pages get deactivated, until more
 * than half of the file pages are on the inactive list.
 *
 * Once we get to that situation, protect the system's working
 * set from being evicted by disabling active file page aging.
 *
 * This uses a different ratio than the anonymous pages, because
 * the page cache uses a use-once replacement algorithm.
 */
static int inactive_file_is_low(struct mem_cgroup_zone *mz)
{
	if (!scanning_global_lru(mz))
		return mem_cgroup_inactive_file_is_low(mz->mem_cgroup,
						       mz->zone);

	return inactive_file_is_low_global(mz->zone);
}

#ifdef CONFIG_HCC_GMM
static int inactive_gdm_is_low_global(struct zone *zone)
{
	unsigned long active, inactive;

	active = zone_page_state(zone, NR_ACTIVE_MIGR);
	inactive = zone_page_state(zone, NR_INACTIVE_MIGR);

	if (inactive * zone->inactive_ratio < active)
		return 1;

	return 0;
}

static int inactive_gdm_is_low(struct mem_cgroup_zone *mz)
{
	int low;

	if (scanning_global_lru(mz))
		low = inactive_gdm_is_low_global(mz->zone);
	else
		BUG();
	return low;
}
#endif

#ifdef CONFIG_HCC_GMM
static int inactive_list_is_low(struct mem_cgroup_zone *mz, int file,
				int gdm)
#else
static int inactive_list_is_low(struct mem_cgroup_zone *mz, int file)
#endif
{
	if (file)
		return inactive_file_is_low(mz);
#ifdef CONFIG_HCC_GMM
	else if (gdm)
		return inactive_gdm_is_low(mz);
#endif
	else
		return inactive_anon_is_low(mz);
}

static unsigned long shrink_list(enum lru_list lru, unsigned long nr_to_scan,
				 struct mem_cgroup_zone *mz,
				 struct scan_control *sc, int priority)
{
	int file = is_file_lru(lru);
#ifdef CONFIG_HCC_GMM
	int gdm = is_gdm_lru(lru);
#endif

	if (is_active_lru(lru)) {
#ifdef CONFIG_HCC_GMM
		if (inactive_list_is_low(mz, file, gdm))
		    shrink_active_list(nr_to_scan, mz, sc, priority, file, gdm);
#else
		if (inactive_list_is_low(mz, file))
		    shrink_active_list(nr_to_scan, mz, sc, priority, file);
#endif
		return 0;
	}

#ifdef CONFIG_HCC_GMM
	return shrink_inactive_list(nr_to_scan, mz, sc, priority, file, gdm);
#else
	return shrink_inactive_list(nr_to_scan, mz, sc, priority, file);
#endif
}

/*
 * Determine how aggressively the anon and file LRU lists should be
 * scanned.  The relative value of each set of LRU lists is determined
 * by looking at the fraction of the pages scanned we did rotate back
 * onto the active list instead of evict.
 *
 * percent[0] specifies how much pressure to put on ram/swap backed
 * memory, while percent[1] determines pressure on the file LRUs.
 */
static void get_scan_ratio(struct mem_cgroup_zone *mz, struct scan_control *sc,
					unsigned long *percent)
{
#ifdef CONFIG_HCC_GMM
	unsigned long gdm, gdm_prio, kp;
#endif
	unsigned long anon, file, free;
#ifndef CONFIG_HCC_GMM
	unsigned long zonefile;
#endif
	unsigned long anon_prio, file_prio;
	unsigned long ap, fp;
	struct zone_reclaim_stat *reclaim_stat = get_reclaim_stat(mz);

	anon  = zone_nr_lru_pages(mz, LRU_ACTIVE_ANON) +
		zone_nr_lru_pages(mz, LRU_INACTIVE_ANON);
	file  = zone_nr_lru_pages(mz, LRU_ACTIVE_FILE) +
		zone_nr_lru_pages(mz, LRU_INACTIVE_FILE);
#ifdef CONFIG_HCC_GMM
	gdm  = zone_nr_lru_pages(mz, LRU_ACTIVE_MIGR) +
		zone_nr_lru_pages(mz, LRU_INACTIVE_MIGR);
#else
	if (global_reclaim(sc)) {
		free  = zone_page_state(mz->zone, NR_FREE_PAGES);
		zonefile =
		    zone_page_state(mz->zone, NR_LRU_BASE + LRU_ACTIVE_FILE) +
		    zone_page_state(mz->zone, NR_LRU_BASE + LRU_INACTIVE_FILE);
		/* If we have very few page cache pages,
		   force-scan anon pages. */
		if (unlikely(zonefile + free <= high_wmark_pages(mz->zone))) {
			percent[0] = 100;
			percent[1] = 0;
			return;
		}
	}
#endif
	/*
	 * OK, so we have swap space and a fair amount of page cache
	 * pages.  We use the recently rotated / recently scanned
	 * ratios to determine how valuable each cache is.
	 *
	 * Because workloads change over time (and to avoid overflow)
	 * we keep these statistics as a floating average, which ends
	 * up weighing recent references more than old ones.
	 *
	 * anon in [0], file in [1]
	 */
	if (unlikely(reclaim_stat->recent_scanned[0] > anon / 4)) {
		spin_lock_irq(&mz->zone->lru_lock);
		reclaim_stat->recent_scanned[0] /= 2;
		reclaim_stat->recent_rotated[0] /= 2;
		spin_unlock_irq(&mz->zone->lru_lock);
	}

	if (unlikely(reclaim_stat->recent_scanned[1] > file / 4)) {
		spin_lock_irq(&mz->zone->lru_lock);
		reclaim_stat->recent_scanned[1] /= 2;
		reclaim_stat->recent_rotated[1] /= 2;
		spin_unlock_irq(&mz->zone->lru_lock);
	}

#ifdef CONFIG_HCC_GMM
	if (unlikely(reclaim_stat->recent_scanned[2] > gdm / 4)) {
		spin_lock_irq(&mz->zone->lru_lock);
		reclaim_stat->recent_scanned[2] /= 2;
		reclaim_stat->recent_rotated[2] /= 2;
		spin_unlock_irq(&mz->zone->lru_lock);
	}
#endif

	/*
	 * With swappiness at 100, anonymous and file have the same priority.
	 * This scanning priority is essentially the inverse of IO cost.
	 */
	anon_prio = sc->swappiness;
	file_prio = 200 - sc->swappiness;
#ifdef CONFIG_HCC_GMM
	if (!sc->may_swap || (get_nr_swap_pages() <= 0))
		anon_prio = 0;
	if (scanning_global_lru(mz)) {
		free  = zone_page_state(mz->zone, NR_FREE_PAGES);
		/* If we have very few page cache pages,
		   force-scan anon pages. */
		if (unlikely(file + free <= high_wmark_pages(mz->zone)))
			file_prio = 0;
	}
	gdm_prio = 400 - anon_prio - file_prio;
#endif
	/*
	 * The amount of pressure on anon vs file pages is inversely
	 * proportional to the fraction of recently scanned pages on
	 * each list that were recently referenced and in active use.
	 */
	ap = anon_prio * (reclaim_stat->recent_scanned[0] + 1);
	ap /= reclaim_stat->recent_rotated[0] + 1;

	fp = file_prio * (reclaim_stat->recent_scanned[1] + 1);
	fp /= reclaim_stat->recent_rotated[1] + 1;

#ifdef CONFIG_HCC_GMM
	kp = gdm_prio * (reclaim_stat->recent_scanned[2] + 1);
	kp /= reclaim_stat->recent_rotated[2] + 1;

	/* Normalize to percentages */
	percent[0] = 100 * ap / (ap + fp + kp + 1);
	percent[1] = 100 * fp / (ap + fp + kp + 1);
	percent[2] = 100 - percent[0] - percent[1];
#else

	/* Normalize to percentages */
	percent[0] = 100 * ap / (ap + fp + 1);
	percent[1] = 100 - percent[0];
#endif
}

/*
 * Smallish @nr_to_scan's are deposited in @nr_saved_scan,
 * until we collected @swap_cluster_max pages to scan.
 */
static unsigned long nr_scan_try_batch(unsigned long nr_to_scan,
				       unsigned long *nr_saved_scan)
{
	unsigned long nr;

	*nr_saved_scan += nr_to_scan;
	nr = *nr_saved_scan;

	if (nr >= SWAP_CLUSTER_MAX)
		*nr_saved_scan = 0;
	else
		nr = 0;

	return nr;
}

/*
 * This is a basic per-zone page freer.  Used by both kswapd and direct reclaim.
 */
static void shrink_mem_cgroup_zone(int priority, struct mem_cgroup_zone *mz,
				   struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	unsigned long nr_to_scan;
#ifdef CONFIG_HCC_GMM
	unsigned long percent[3];	/* anon @ 0; file @ 1; gdm @ 2 */
#else
	unsigned long percent[2];	/* anon @ 0; file @ 1 */
#endif
	enum lru_list l;
	unsigned long nr_reclaimed = 0;
	unsigned long nr_to_reclaim = sc->nr_to_reclaim;
#ifndef CONFIG_HCC_GMM
	int noswap = 0;
#endif
	struct zone_reclaim_stat *reclaim_stat = get_reclaim_stat(mz);

#ifndef CONFIG_HCC_GMM
	/* If we have no swap space, do not bother scanning anon pages. */
	if (!sc->may_swap || (get_nr_swap_pages() <= 0)) {
		noswap = 1;
		percent[0] = 0;
		percent[1] = 100;
	} else
#endif
	{
		get_scan_ratio(mz, sc, percent);
	}

	for_each_evictable_lru(l) {
#ifdef CONFIG_HCC_GMM
		int file = RECLAIM_STAT_INDEX(is_file_lru(l), is_gdm_lru(l));
#else
		int file = is_file_lru(l);
#endif
		unsigned long scan;

		scan = zone_nr_lru_pages(mz, l);
#ifdef CONFIG_HCC_GMM
		if (priority ||
#else
		if (priority || noswap ||
#endif
		    (!sc->swappiness && !sc->oom_force_anon_scan)) {
			scan >>= priority;
			scan = (scan * percent[file]) / 100;
		}
		nr[l] = nr_scan_try_batch(scan,
					  &reclaim_stat->nr_saved_scan[l]);
	}

	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_FILE] ||
#ifdef CONFIG_HCC_GMM
	       nr[LRU_INACTIVE_MIGR] || nr[LRU_INACTIVE_FILE]) {
#else
					nr[LRU_INACTIVE_FILE]) {
#endif
		for_each_evictable_lru(l) {
			if (nr[l]) {
				nr_to_scan = min_t(unsigned long,
						   nr[l], SWAP_CLUSTER_MAX);
				nr[l] -= nr_to_scan;

				nr_reclaimed += shrink_list(l, nr_to_scan,
							    mz, sc, priority);
			}
		}
		/*
		 * On large memory systems, scan >> priority can become
		 * really large. This is fine for the starting priority;
		 * we want to put equal scanning pressure on each zone.
		 * However, if the VM has a harder time of freeing pages,
		 * with multiple processes reclaiming pages, the total
		 * freeing target can get unreasonably large.
		 */
		if (nr_reclaimed >= nr_to_reclaim && priority < DEF_PRIORITY)
			break;
	}

	sc->nr_reclaimed += nr_reclaimed;
	trace_mm_pagereclaim_shrinkzone(nr_reclaimed, priority);

	/*
	 * Even if we did not try to evict anon pages at all, we want to
	 * rebalance the anon lru active/inactive ratio.
	 */
#ifdef CONFIG_HCC_GMM
	if (get_nr_swap_pages() > 0) {
		if (inactive_anon_is_low(mz))
			shrink_active_list(SWAP_CLUSTER_MAX, mz, sc, priority, 0, 0);
		if (inactive_gdm_is_low(mz))
			shrink_active_list(SWAP_CLUSTER_MAX, mz, sc, priority, 0, 1);
	}
#else
	if (inactive_anon_is_low(mz) && get_nr_swap_pages() > 0)
		shrink_active_list(SWAP_CLUSTER_MAX, mz, sc, priority, 0);
#endif

	throttle_vm_writeout(sc->gfp_mask);
}

/* Use reclaim/compaction for costly allocs or under memory pressure */
static bool in_reclaim_compaction(int priority, struct scan_control *sc)
{
	if (COMPACTION_BUILD && sc->order &&
			(sc->order > PAGE_ALLOC_COSTLY_ORDER ||
			 priority < DEF_PRIORITY - 2))
		return true;

	return false;
}

/*
 * Reclaim/compaction is used for high-order allocation requests. It reclaims
 * order-0 pages before compacting the zone. should_continue_reclaim() returns
 * true if more pages should be reclaimed such that when the page allocator
 * calls try_to_compact_zone() that it will have enough free pages to succeed.
 * It will give up earlier than that if there is difficulty reclaiming pages.
 */
static inline bool should_continue_reclaim(struct zone *zone,
					unsigned long nr_reclaimed,
					unsigned long nr_scanned,
					int priority,
					struct scan_control *sc)
{
	unsigned long pages_for_compaction;
	unsigned long inactive_lru_pages;

	/* If not in reclaim/compaction mode, stop */
	if (!in_reclaim_compaction(priority, sc))
		return false;

	/* Consider stopping depending on scan and reclaim activity */
	if (sc->gfp_mask & __GFP_REPEAT) {
		/*
		 * For __GFP_REPEAT allocations, stop reclaiming if the
		 * full LRU list has been scanned and we are still failing
		 * to reclaim pages. This full LRU scan is potentially
		 * expensive but a __GFP_REPEAT caller really wants to succeed
		 */
		if (!nr_reclaimed && !nr_scanned)
			return false;
	} else {
		/*
		 * For non-__GFP_REPEAT allocations which can presumably
		 * fail without consequence, stop if we failed to reclaim
		 * any pages from the last SWAP_CLUSTER_MAX number of
		 * pages that were scanned. This will return to the
		 * caller faster at the risk reclaim/compaction and
		 * the resulting allocation attempt fails
		 */
		if (!nr_reclaimed)
			return false;
	}

	/*
	 * If we have not reclaimed enough pages for compaction and the
	 * inactive lists are large enough, continue reclaiming
	 */
	pages_for_compaction = (2UL << sc->order);
	inactive_lru_pages = zone_page_state(zone, NR_INACTIVE_FILE);
	if (get_nr_swap_pages() > 0)
		inactive_lru_pages += zone_page_state(zone, NR_INACTIVE_ANON);
	if (sc->nr_reclaimed < pages_for_compaction &&
			inactive_lru_pages > pages_for_compaction)
		return true;

	/* If compaction would go ahead or the allocation would succeed, stop */
	switch (compaction_suitable(zone, sc->order)) {
	case COMPACT_PARTIAL:
	case COMPACT_CONTINUE:
		return false;
	default:
		return true;
	}
}

static void shrink_zone(int priority, struct zone *zone,
			struct scan_control *sc)
{
	unsigned long nr_reclaimed, nr_scanned;

	do {
		struct mem_cgroup *root = sc->target_mem_cgroup;
		struct mem_cgroup_reclaim_cookie reclaim = {
			.zone = zone,
			.priority = priority,
		};
		struct mem_cgroup *memcg;

		nr_reclaimed = sc->nr_reclaimed;
		nr_scanned = sc->nr_scanned;

		memcg = mem_cgroup_iter(root, NULL, &reclaim);
		do {
			struct mem_cgroup_zone mz = {
				.mem_cgroup = memcg,
				.zone = zone,
			};

			shrink_mem_cgroup_zone(priority, &mz, sc);
			/*
			 * Limit reclaim has historically picked one
			 * memcg and scanned it with decreasing
			 * priority levels until nr_to_reclaim had
			 * been reclaimed.  This priority cycle is
			 * thus over after a single memcg.
			 *
			 * Direct reclaim and kswapd, on the other
			 * hand, have to scan all memory cgroups to
			 * fulfill the overall scan target for the
			 * zone.
			 */
			if (!global_reclaim(sc)) {
				mem_cgroup_iter_break(root, memcg);
				break;
			}
			memcg = mem_cgroup_iter(root, memcg, &reclaim);
		} while (memcg);
	} while (should_continue_reclaim(zone, sc->nr_reclaimed - nr_reclaimed,
					 sc->nr_scanned - nr_scanned, priority,
					 sc));
}

/* Returns true if compaction should go ahead for a high-order request */
static inline bool compaction_ready(struct zone *zone, struct scan_control *sc)
{
	unsigned long balance_gap, watermark;
	bool watermark_ok;

	/* Do not consider compaction for orders reclaim is meant to satisfy */
	if (sc->order <= PAGE_ALLOC_COSTLY_ORDER)
		return false;

	/*
	 * Compaction takes time to run and there are potentially other
	 * callers using the pages just freed. Continue reclaiming until
	 * there is a buffer of free pages available to give compaction
	 * a reasonable chance of completing and allocating the page
	 */
	balance_gap = min(low_wmark_pages(zone),
		(zone->present_pages + KSWAPD_ZONE_BALANCE_GAP_RATIO-1) /
			KSWAPD_ZONE_BALANCE_GAP_RATIO);
	watermark = high_wmark_pages(zone) + balance_gap + (2UL << sc->order);
	watermark_ok = zone_watermark_ok_safe(zone, 0, watermark, 0, 0);

	/*
	 * If compaction is deferred, reclaim up to a point where
	 * compaction will have a chance of success when re-enabled
	 */
	if (compaction_deferred(zone))
		return watermark_ok;

	/* If compaction is not ready to start, keep reclaiming */
	if (!compaction_suitable(zone, sc->order))
		return false;

	return watermark_ok;
}

/*
 * This is the direct reclaim path, for page-allocating processes.  We only
 * try to reclaim pages from zones which will satisfy the caller's allocation
 * request.
 *
 * We reclaim from a zone even if that zone is over high_wmark_pages(zone).
 * Because:
 * a) The caller may be trying to free *extra* pages to satisfy a higher-order
 *    allocation or
 * b) The target zone may be at high_wmark_pages(zone) but the lower zones
 *    must go *over* high_wmark_pages(zone) to satisfy the `incremental min'
 *    zone defense algorithm.
 *
 * If a zone is deemed to be full of pinned pages then just give it a light
 * scan then give up on it.
 *
 * This function returns true if a zone is being reclaimed for a costly
 * high-order allocation and compaction is ready to begin. This indicates to
 * the caller that it should consider retrying the allocation instead of
 * further reclaim.
 */
static bool shrink_zones(int priority, struct zonelist *zonelist,
					struct scan_control *sc)
{
	enum zone_type high_zoneidx = gfp_zone(sc->gfp_mask);
	struct zoneref *z;
	struct zone *zone;
	bool aborted_reclaim = false;

	sc->all_unreclaimable = 1;
	for_each_zone_zonelist_nodemask(zone, z, zonelist, high_zoneidx,
					sc->nodemask) {
		if (!populated_zone(zone))
			continue;
		/*
		 * Take care memory controller reclaiming has small influence
		 * to global LRU.
		 */
		if (global_reclaim(sc)) {
			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;
			note_zone_scanning_priority(zone, priority);

			if (zone_is_all_unreclaimable(zone) &&
						priority != DEF_PRIORITY)
				continue;	/* Let kswapd poll it */
			sc->all_unreclaimable = 0;
			if (COMPACTION_BUILD) {
				/*
				 * If we already have plenty of memory free for
				 * compaction in this zone, don't free any more.
				 * Even though compaction is invoked for any
				 * non-zero order, only frequent costly order
				 * reclamation is disruptive enough to become a
				 * noticable problem, like transparent huge page
				 * allocations.
				 */
				if (compaction_ready(zone, sc)) {
					aborted_reclaim = true;
					continue;
				}
			}
		} else {
			/*
			 * Ignore cpuset limitation here. We just want to reduce
			 * # of used pages by us regardless of memory shortage.
			 */
			sc->all_unreclaimable = 0;
			mem_cgroup_note_reclaim_priority(sc->target_mem_cgroup,
							priority);
		}

		shrink_zone(priority, zone, sc);
	}

	return aborted_reclaim;
}

/*
 * This is the main entry point to direct page reclaim.
 *
 * If a full scan of the inactive list fails to free enough memory then we
 * are "out of memory" and something needs to be killed.
 *
 * If the caller is !__GFP_FS then the probability of a failure is reasonably
 * high - the zone may be full of dirty or under-writeback pages, which this
 * caller can't do much about.  We kick the writeback threads and take explicit
 * naps in the hope that some of these pages can be written.  But if the
 * allocating task holds filesystem locks which prevent writeout this might not
 * work, and the allocation attempt will fail.
 *
 * returns:	0, if no pages reclaimed
 * 		else, the number of pages reclaimed
 */
static unsigned long do_try_to_free_pages(struct zonelist *zonelist,
					struct scan_control *sc)
{
	int priority;
	unsigned long ret = 0;
	unsigned long total_scanned = 0;
	struct reclaim_state *reclaim_state = current->reclaim_state;
	unsigned long lru_pages = 0;
	struct zoneref *z;
	struct zone *zone;
	enum zone_type high_zoneidx = gfp_zone(sc->gfp_mask);
	unsigned long writeback_threshold;
	bool aborted_reclaim;

	get_mems_allowed();
	delayacct_freepages_start();

	if (global_reclaim(sc))
		count_vm_event(ALLOCSTALL);
	/*
	 * mem_cgroup will not do shrink_slab.
	 */
	if (global_reclaim(sc)) {
		for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {

			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;

			lru_pages += zone_reclaimable_pages(zone);
		}
	}

	for (priority = DEF_PRIORITY; priority >= 0; priority--) {
retry:
		sc->nr_scanned = 0;
		if (!priority)
			disable_swap_token();
		aborted_reclaim = shrink_zones(priority, zonelist, sc);

		/*
		 * Don't shrink slabs when reclaiming memory from
		 * over limit cgroups
		 */
		if (global_reclaim(sc)) {
			shrink_slab(sc->nr_scanned, sc->gfp_mask, lru_pages);
			if (reclaim_state) {
				sc->nr_reclaimed += reclaim_state->reclaimed_slab;
				reclaim_state->reclaimed_slab = 0;
			}
		}
		total_scanned += sc->nr_scanned;
		if (sc->nr_reclaimed >= sc->nr_to_reclaim) {
			ret = sc->nr_reclaimed;
			goto out;
		}

		/*
		 * Try to write back as many pages as we just scanned.  This
		 * tends to cause slow streaming writers to write data to the
		 * disk smoothly, at the dirtying rate, which is nice.   But
		 * that's undesirable in laptop mode, where we *want* lumpy
		 * writeout.  So in laptop mode, write out the whole world.
		 */
		writeback_threshold = sc->nr_to_reclaim + sc->nr_to_reclaim / 2;
		if (total_scanned > writeback_threshold) {
			wakeup_flusher_threads(laptop_mode ? 0 : total_scanned);
			sc->may_writepage = 1;
		}

		/* Take a nap, wait for some writeback to complete */
		if (!sc->hibernation_mode && sc->nr_scanned &&
		    priority < DEF_PRIORITY - 2) {
			struct zone *preferred_zone;

			first_zones_zonelist(zonelist, gfp_zone(sc->gfp_mask),
						&cpuset_current_mems_allowed,
						&preferred_zone);
			wait_iff_congested(preferred_zone, BLK_RW_ASYNC, HZ/10);
		}

		/*
		 * When swappiness == 0, and under heavy pagecache pressure,
		 * direct reclaim may fail to reclaim cache pages.
		 * Let's try once more and force scan of anonymous pages this
		 * time to avoid OOM kill if possible.
		 */
		if (!priority && !sc->swappiness && !sc->nr_reclaimed &&
		    !sc->oom_force_anon_scan &&
		    sc->may_swap && (get_nr_swap_pages() > 0)) {
			sc->oom_force_anon_scan = true;
			goto retry;
		}
	}
	/* top priority shrink_zones still had more to do? don't OOM, then */
	if (!sc->all_unreclaimable && global_reclaim(sc))
		ret = sc->nr_reclaimed;
out:
	/*
	 * Now that we've scanned all the zones at this priority level, note
	 * that level within the zone so that the next thread which performs
	 * scanning of this zone will immediately start out at this priority
	 * level.  This affects only the decision whether or not to bring
	 * mapped pages onto the inactive list.
	 */
	if (priority < 0)
		priority = 0;

#ifdef CONFIG_NUMA
	trace_mm_directreclaim_reclaimall(zonelist[0]._zonerefs->zone->node,
						sc->nr_reclaimed, priority);
#else
	trace_mm_directreclaim_reclaimall(0, sc->nr_reclaimed, priority);
#endif
	if (global_reclaim(sc)) {
		for_each_zone_zonelist(zone, z, zonelist, high_zoneidx) {

			if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
				continue;

			zone->prev_priority = priority;
		}
	} else
		mem_cgroup_record_reclaim_priority(sc->target_mem_cgroup,
						   priority);

	delayacct_freepages_end();
	put_mems_allowed();

	/* Aborted reclaim to try compaction? don't OOM, then */
	if (aborted_reclaim)
		return 1;

	return ret;
}

unsigned long try_to_free_pages(struct zonelist *zonelist, int order,
				gfp_t gfp_mask, nodemask_t *nodemask)
{
	unsigned long nr_reclaimed;
	struct scan_control sc = {
		.gfp_mask = gfp_mask,
		.may_writepage = !laptop_mode,
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.may_unmap = 1,
		.may_swap = 1,
		.swappiness = vm_swappiness,
		.order = order,
		.target_mem_cgroup = NULL,
		.nodemask = nodemask,
		.oom_force_anon_scan = false,
	};

	trace_mm_vmscan_direct_reclaim_begin(order,
				sc.may_writepage,
				gfp_mask);

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	trace_mm_vmscan_direct_reclaim_end(nr_reclaimed);

	return nr_reclaimed;
}

#ifdef CONFIG_CGROUP_MEM_RES_CTLR

unsigned long mem_cgroup_shrink_node_zone(struct mem_cgroup *mem,
						gfp_t gfp_mask, bool noswap,
						unsigned int swappiness,
						struct zone *zone, int nid)
{
	struct scan_control sc = {
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = !noswap,
		.swappiness = swappiness,
		.order = 0,
		.target_mem_cgroup = mem,
		.oom_force_anon_scan = false,
	};
	struct mem_cgroup_zone mz = {
		.mem_cgroup = mem,
		.zone = zone,
	};
	nodemask_t nm  = nodemask_of_node(nid);

	sc.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
			(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK);
	sc.nodemask = &nm;
	sc.nr_reclaimed = 0;
	sc.nr_scanned = 0;
	/*
	 * NOTE: Although we can get the priority field, using it
	 * here is not a good idea, since it limits the pages we can scan.
	 * if we don't reclaim here, the shrink_zone from balance_pgdat
	 * will pick up pages from other mem cgroup's as well. We hack
	 * the priority and make it zero.
	 */
	shrink_mem_cgroup_zone(0, &mz, &sc);
	return sc.nr_reclaimed;
}

unsigned long try_to_free_mem_cgroup_pages(struct mem_cgroup *mem_cont,
					   gfp_t gfp_mask,
					   bool noswap,
					   unsigned int swappiness)
{
	struct zonelist *zonelist;
	struct scan_control sc = {
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = !noswap,
		.nr_to_reclaim = SWAP_CLUSTER_MAX,
		.swappiness = swappiness,
		.order = 0,
		.target_mem_cgroup = mem_cont,
		.nodemask = NULL, /* we don't care the placement */
		.oom_force_anon_scan = false,
	};

	sc.gfp_mask = (gfp_mask & GFP_RECLAIM_MASK) |
			(GFP_HIGHUSER_MOVABLE & ~GFP_RECLAIM_MASK);
	zonelist = NODE_DATA(numa_node_id())->node_zonelists;
	return do_try_to_free_pages(zonelist, &sc);
}
#endif

/* is kswapd sleeping prematurely? */
static int sleeping_prematurely(pg_data_t *pgdat, int order, long remaining)
{
	int i;

	/* If a direct reclaimer woke kswapd within HZ/10, it's premature */
	if (remaining)
		return 1;

	/* If after HZ/10, a zone is below the high mark, it's premature */
	for (i = 0; i < pgdat->nr_zones; i++) {
		struct zone *zone = pgdat->node_zones + i;

		if (!populated_zone(zone))
			continue;

		if (zone_is_all_unreclaimable(zone))
			continue;

		if (!zone_watermark_ok_safe(zone, order, high_wmark_pages(zone),
								0, 0))
			return 1;
	}

	return 0;
}

static void age_active_anon(struct zone *zone, struct scan_control *sc,
			    int priority)
{
	struct mem_cgroup *memcg;

	if (!total_swap_pages)
		return;

	memcg = mem_cgroup_iter(NULL, NULL, NULL);
	do {
		struct mem_cgroup_zone mz = {
			.mem_cgroup = memcg,
			.zone = zone,
		};

		if (inactive_anon_is_low(&mz))
			shrink_active_list(SWAP_CLUSTER_MAX, &mz,
#ifndef CONFIG_HCC_GMM
					   sc, priority, 0);
#else
					   sc, priority, 0, 0);
		/* Do the same on gdm lru pages */
		if (inactive_gdm_is_low(&mz))
			shrink_active_list(SWAP_CLUSTER_MAX, &mz,
					   sc, priority, 0, 1);
#endif

		memcg = mem_cgroup_iter(NULL, memcg, NULL);
	} while (memcg);
}

/*
 * For kswapd, balance_pgdat() will work across all this node's zones until
 * they are all at high_wmark_pages(zone).
 *
 * Returns the number of pages which were actually freed.
 *
 * There is special handling here for zones which are full of pinned pages.
 * This can happen if the pages are all mlocked, or if they are all used by
 * device drivers (say, ZONE_DMA).  Or if they are all in use by hugetlb.
 * What we do is to detect the case where all pages in the zone have been
 * scanned twice and there has been zero successful reclaim.  Mark the zone as
 * dead and from now on, only perform a short scan.  Basically we're polling
 * the zone for when the problem goes away.
 *
 * kswapd scans the zones in the highmem->normal->dma direction.  It skips
 * zones which have free_pages > high_wmark_pages(zone), but once a zone is
 * found to have free_pages <= high_wmark_pages(zone), we scan that zone and the
 * lower zones regardless of the number of free pages in the lower zones. This
 * interoperates with the page allocator fallback scheme to ensure that aging
 * of pages is balanced across the zones.
 */
static unsigned long balance_pgdat(pg_data_t *pgdat, int order)
{
	int all_zones_ok;
	int priority;
	int i;
	unsigned long total_scanned;
	unsigned long total_reclaimed = 0;
	struct reclaim_state *reclaim_state = current->reclaim_state;
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.may_unmap = 1,
		.may_swap = 1,
		/*
		 * kswapd doesn't want to be bailed out while reclaim. because
		 * we want to put equal scanning pressure on each zone.
		 */
		.nr_to_reclaim = ULONG_MAX,
		.swappiness = vm_swappiness,
		.order = order,
		.target_mem_cgroup = NULL,
		.oom_force_anon_scan = false,
	};
	/*
	 * temp_priority is used to remember the scanning priority at which
	 * this zone was successfully refilled to
	 * free_pages == high_wmark_pages(zone).
	 */
	int temp_priority[MAX_NR_ZONES];

loop_again:
	total_scanned = 0;
	sc.nr_reclaimed = 0;
	sc.may_writepage = !laptop_mode;
	count_vm_event(PAGEOUTRUN);

	for (i = 0; i < pgdat->nr_zones; i++)
		temp_priority[i] = DEF_PRIORITY;

	for (priority = DEF_PRIORITY; priority >= 1; priority--) {
		int end_zone = 0;	/* Inclusive.  0 = ZONE_DMA */
		unsigned long lru_pages = 0;
		int has_under_min_watermark_zone = 0;

		/* The swap token gets in the way of swapout... */
		if (!priority)
			disable_swap_token();

		all_zones_ok = 1;

		/*
		 * Scan in the highmem->dma direction for the highest
		 * zone which needs scanning
		 */
		for (i = pgdat->nr_zones - 1; i >= 0; i--) {
			struct zone *zone = pgdat->node_zones + i;

			if (!populated_zone(zone))
				continue;

			if (zone_is_all_unreclaimable(zone) &&
			    priority != DEF_PRIORITY)
				continue;

			/*
			 * Do some background aging of the anon list, to give
			 * pages a chance to be referenced before reclaiming.
			 */
			age_active_anon(zone, &sc, priority);

			if (!zone_watermark_ok_safe(zone, order,
					high_wmark_pages(zone), 0, 0)) {
				end_zone = i;
				break;
			}
		}
		if (i < 0)
			goto out;

		for (i = 0; i <= end_zone; i++) {
			struct zone *zone = pgdat->node_zones + i;

			lru_pages += zone_reclaimable_pages(zone);
		}

		/*
		 * Now scan the zone in the dma->highmem direction, stopping
		 * at the last zone which needs scanning.
		 *
		 * We do this because the page allocator works in the opposite
		 * direction.  This prevents the page allocator from allocating
		 * pages behind kswapd's direction of progress, which would
		 * cause too much scanning of the lower zones.
		 */
		for (i = 0; i <= end_zone; i++) {
			struct zone *zone = pgdat->node_zones + i;
			int nr_slab;
			int nid, zid;
			unsigned long balance_gap;
			bool contended = false;

			if (!populated_zone(zone))
				continue;

			if (zone_is_all_unreclaimable(zone) &&
					priority != DEF_PRIORITY)
				continue;

			if (!zone_watermark_ok(zone, order,
					high_wmark_pages(zone), end_zone, 0))
				all_zones_ok = 0;
			temp_priority[i] = priority;
			sc.nr_scanned = 0;
			note_zone_scanning_priority(zone, priority);

			nid = pgdat->node_id;
			zid = zone_idx(zone);
			/*
			 * Call soft limit reclaim before calling shrink_zone.
			 * For now we ignore the return value
			 */
			mem_cgroup_soft_limit_reclaim(zone, order, sc.gfp_mask,
							nid, zid);
			/*
			 * We put equal pressure on every zone, unless
			 * one zone has way too many pages free
			 * already. The "too many pages" is defined
			 * as the high wmark plus a "gap" where the
			 * gap is either the low watermark or 1%
			 * of the zone, whichever is smaller.
			 */
			balance_gap = min(low_wmark_pages(zone),
				(zone->present_pages +
					KSWAPD_ZONE_BALANCE_GAP_RATIO-1) /
				KSWAPD_ZONE_BALANCE_GAP_RATIO);
			if (!zone_watermark_ok_safe(zone, order,
					high_wmark_pages(zone) + balance_gap,
					end_zone, 0))
				shrink_zone(priority, zone, &sc);
			reclaim_state->reclaimed_slab = 0;
			nr_slab = shrink_slab(sc.nr_scanned, GFP_KERNEL,
						lru_pages);
			sc.nr_reclaimed += reclaim_state->reclaimed_slab;
			total_scanned += sc.nr_scanned;

			if (zone_is_all_unreclaimable(zone))
				continue;
			if (nr_slab == 0 && zone->pages_scanned >=
					(zone_reclaimable_pages(zone) * 6))
					zone_set_flag(zone,
						      ZONE_ALL_UNRECLAIMABLE);
			/*
			 * If we've done a decent amount of scanning and
			 * the reclaim ratio is low, start doing writepage
			 * even in laptop mode
			 */
			if (total_scanned > SWAP_CLUSTER_MAX * 2 &&
			    total_scanned > sc.nr_reclaimed + sc.nr_reclaimed / 2)
				sc.may_writepage = 1;

			/*
			 * Compact the zone for higher orders to reduce
			 * latencies for higher-order allocations that
			 * would ordinarily call try_to_compact_pages()
			 */
			if (sc.order > PAGE_ALLOC_COSTLY_ORDER)
				compact_zone_order(zone, sc.order, sc.gfp_mask, 0,
						&contended);

			if (!zone_watermark_ok_safe(zone, order,
					high_wmark_pages(zone), end_zone, 0)) {
				/*
				 * We are still under min water mark. it mean we have
				 * GFP_ATOMIC allocation failure risk. Hurry up!
				 */
				if (!zone_watermark_ok_safe(zone, order,
					    min_wmark_pages(zone), end_zone, 0))
					has_under_min_watermark_zone = 1;
			} else {
				/*
				 * If a zone reaches its high watermark,
				 * consider it to be no longer congested. It's
				 * possible there are dirty pages backed by
				 * congested BDIs but as pressure is relieved,
				 * spectulatively avoid congestion waits
				 */
				zone_clear_flag(zone, ZONE_CONGESTED);
                        }


		}
		total_reclaimed += sc.nr_reclaimed;
		if (all_zones_ok)
			break;		/* kswapd: all done */
		/*
		 * OK, kswapd is getting into trouble.  Take a nap, then take
		 * another pass across the zones.
		 */
		if (total_scanned && (priority < DEF_PRIORITY - 2)) {
			if (has_under_min_watermark_zone)
				count_vm_event(KSWAPD_SKIP_CONGESTION_WAIT);
			else
				congestion_wait(BLK_RW_ASYNC, HZ/10);
		}

		/*
		 * We do this so kswapd doesn't build up large priorities for
		 * example when it is freeing in parallel with allocators. It
		 * matches the direct reclaim path behaviour in terms of impact
		 * on zone->*_priority.
		 */
		if (sc.nr_reclaimed >= SWAP_CLUSTER_MAX)
			break;
		cond_resched();
	}
out:
	/*
	 * Note within each zone the priority level at which this zone was
	 * brought into a happy state.  So that the next thread which scans this
	 * zone will start out at that priority level.
	 */
	for (i = 0; i < pgdat->nr_zones; i++) {
		struct zone *zone = pgdat->node_zones + i;

		zone->prev_priority = temp_priority[i];
	}
	if (!all_zones_ok) {
		cond_resched();

		try_to_freeze();

		/*
		 * Fragmentation may mean that the system cannot be
		 * rebalanced for high-order allocations in all zones.
		 * At this point, if nr_reclaimed < SWAP_CLUSTER_MAX,
		 * it means the zones have been fully scanned and are still
		 * not balanced. For high-order allocations, there is
		 * little point trying all over again as kswapd may
		 * infinite loop.
		 *
		 * Instead, recheck all watermarks at order-0 as they
		 * are the most important. If watermarks are ok, kswapd will go
		 * back to sleep. High-order users can still perform direct
		 * reclaim if they wish.
		 */
		if (sc.nr_reclaimed < SWAP_CLUSTER_MAX)
			order = sc.order = 0;

		goto loop_again;
	}

	trace_mm_kswapd_ran(pgdat, total_reclaimed);
	return sc.nr_reclaimed;
}

/*
 * The background pageout daemon, started as a kernel thread
 * from the init process.
 *
 * This basically trickles out pages so that we have _some_
 * free memory available even if there is no other activity
 * that frees anything up. This is needed for things like routing
 * etc, where we otherwise might have all activity going on in
 * asynchronous contexts that cannot page things out.
 *
 * If there are applications that are active memory-allocators
 * (most normal use), this basically shouldn't matter.
 */
static int kswapd(void *p)
{
	unsigned long order;
	pg_data_t *pgdat = (pg_data_t*)p;
	struct task_struct *tsk = current;
	DEFINE_WAIT(wait);
	struct reclaim_state reclaim_state = {
		.reclaimed_slab = 0,
	};
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	lockdep_set_current_reclaim_state(GFP_KERNEL);

	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);
	current->reclaim_state = &reclaim_state;

	/*
	 * Tell the memory management that we're a "memory allocator",
	 * and that if we need more memory we should get access to it
	 * regardless (see "__alloc_pages()"). "kswapd" should
	 * never get caught in the normal page freeing logic.
	 *
	 * (Kswapd normally doesn't need memory anyway, but sometimes
	 * you need a small amount of memory in order to be able to
	 * page out something else, and this flag essentially protects
	 * us from recursively trying to free more memory as we're
	 * trying to free the first piece of memory in the first place).
	 */
	tsk->flags |= PF_MEMALLOC | PF_SWAPWRITE | PF_KSWAPD;
	set_freezable();

	order = 0;
	for ( ; ; ) {
		unsigned long new_order;

		prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
		new_order = pgdat->kswapd_max_order;
		pgdat->kswapd_max_order = 0;
		if (order < new_order) {
			/*
			 * Don't sleep if someone wants a larger 'order'
			 * allocation
			 */
			order = new_order;
		} else {
			if (!freezing(current)) {
				long remaining = 0;

				/* Try to sleep for a short interval */
				if (!sleeping_prematurely(pgdat, order, remaining)) {
					remaining = schedule_timeout(HZ/10);
					finish_wait(&pgdat->kswapd_wait, &wait);
					prepare_to_wait(&pgdat->kswapd_wait, &wait, TASK_INTERRUPTIBLE);
				}

				/*
				 * After a short sleep, check if it was a
				 * premature sleep. If not, then go fully
				 * to sleep until explicitly woken up
				 */
				if (!sleeping_prematurely(pgdat, order, remaining)) {
					trace_mm_vmscan_kswapd_sleep(pgdat->node_id);

					/*
					 * vmstat counters are not perfectly
					 * accurate and the estimated value
					 * for counters such as NR_FREE_PAGES
					 * can deviate from the true value by
					 * nr_online_cpus * threshold. To
					 * avoid the zone watermarks being
					 * breached while under pressure, we
					 * reduce the per-cpu vmstat threshold
					 * while kswapd is awake and restore
					 * them before going back to sleep.
					 */
					set_pgdat_percpu_threshold(pgdat,
						calculate_normal_threshold);

					schedule();
					set_pgdat_percpu_threshold(pgdat,
						calculate_pressure_threshold);
				} else {
					if (remaining)
						count_vm_event(KSWAPD_LOW_WMARK_HIT_QUICKLY);
					else
						count_vm_event(KSWAPD_HIGH_WMARK_HIT_QUICKLY);
				}
			}

			order = pgdat->kswapd_max_order;
		}
		finish_wait(&pgdat->kswapd_wait, &wait);

		if (!try_to_freeze()) {
			/* We can speed up thawing tasks if we don't call
			 * balance_pgdat after returning from the refrigerator
			 */
			trace_mm_vmscan_kswapd_wake(pgdat->node_id, order);
			balance_pgdat(pgdat, order);
		}
	}
	return 0;
}

/*
 * A zone is low on free memory, so wake its kswapd task to service it.
 */
void wakeup_kswapd(struct zone *zone, int order)
{
	pg_data_t *pgdat;

	if (!populated_zone(zone))
		return;

	if (!cpuset_zone_allowed_hardwall(zone, GFP_KERNEL))
		return;
	pgdat = zone->zone_pgdat;
	if (pgdat->kswapd_max_order < order)
		pgdat->kswapd_max_order = order;
	if (!waitqueue_active(&pgdat->kswapd_wait))
		return;
	if (zone_watermark_ok_safe(zone, order, low_wmark_pages(zone), 0, 0))
		return;

	trace_mm_vmscan_wakeup_kswapd(pgdat->node_id, zone_idx(zone), order);
	wake_up_interruptible(&pgdat->kswapd_wait);
}

/*
 * The reclaimable count would be mostly accurate.
 * The less reclaimable pages may be
 * - mlocked pages, which will be moved to unevictable list when encountered
 * - mapped pages, which may require several travels to be reclaimed
 * - dirty pages, which is not "instantly" reclaimable
 */
unsigned long global_reclaimable_pages(void)
{
	int nr;

	nr = global_page_state(NR_ACTIVE_FILE) +
	     global_page_state(NR_INACTIVE_FILE);

	if (get_nr_swap_pages() > 0) {
#ifdef CONFIG_HCC_GMM
		nr += global_page_state(NR_ACTIVE_MIGR) +
		      global_page_state(NR_INACTIVE_MIGR);
#endif
		nr += global_page_state(NR_ACTIVE_ANON) +
		      global_page_state(NR_INACTIVE_ANON);
	}

	return nr;
}

unsigned long zone_reclaimable_pages(struct zone *zone)
{
	int nr;

	nr = zone_page_state(zone, NR_ACTIVE_FILE) +
	     zone_page_state(zone, NR_INACTIVE_FILE);

	if (get_nr_swap_pages() > 0) {
#ifdef CONFIG_HCC_GMM
		nr += zone_page_state(zone, NR_ACTIVE_MIGR) +
		      zone_page_state(zone, NR_INACTIVE_MIGR);
#endif
		nr += zone_page_state(zone, NR_ACTIVE_ANON) +
		      zone_page_state(zone, NR_INACTIVE_ANON);
	}

	return nr;
}

#ifdef CONFIG_HIBERNATION
/*
 * Try to free `nr_to_reclaim' of memory, system-wide, and return the number of
 * freed pages.
 *
 * Rather than trying to age LRUs the aim is to preserve the overall
 * LRU order by reclaiming preferentially
 * inactive > active > active referenced > active mapped
 */
unsigned long shrink_all_memory(unsigned long nr_to_reclaim)
{
	struct reclaim_state reclaim_state;
	struct scan_control sc = {
		.gfp_mask = GFP_HIGHUSER_MOVABLE,
		.may_swap = 1,
		.may_unmap = 1,
		.may_writepage = 1,
		.nr_to_reclaim = nr_to_reclaim,
		.hibernation_mode = 1,
		.swappiness = vm_swappiness,
		.order = 0,
		.oom_force_anon_scan = false,
	};
	struct zonelist * zonelist = node_zonelist(numa_node_id(), sc.gfp_mask);
	struct task_struct *p = current;
	unsigned long nr_reclaimed;

	p->flags |= PF_MEMALLOC;
	lockdep_set_current_reclaim_state(sc.gfp_mask);
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	nr_reclaimed = do_try_to_free_pages(zonelist, &sc);

	p->reclaim_state = NULL;
	lockdep_clear_current_reclaim_state();
	p->flags &= ~PF_MEMALLOC;

	return nr_reclaimed;
}
#endif /* CONFIG_HIBERNATION */

/* It's optimal to keep kswapds on the same CPUs as their memory, but
   not required for correctness.  So if the last cpu in a node goes
   away, we get changed to run anywhere: as the first one comes back,
   restore their cpu bindings. */
static int __devinit cpu_callback(struct notifier_block *nfb,
				  unsigned long action, void *hcpu)
{
	int nid;

	if (action == CPU_ONLINE || action == CPU_ONLINE_FROZEN) {
		for_each_node_state(nid, N_HIGH_MEMORY) {
			pg_data_t *pgdat = NODE_DATA(nid);
			const struct cpumask *mask;

			mask = cpumask_of_node(pgdat->node_id);

			if (cpumask_any_and(cpu_online_mask, mask) < nr_cpu_ids)
				/* One of our CPUs online: restore mask */
				set_cpus_allowed_ptr(pgdat->kswapd, mask);
		}
	}
	return NOTIFY_OK;
}

/*
 * This kswapd start function will be called by init and node-hot-add.
 * On node-hot-add, kswapd will moved to proper cpus if cpus are hot-added.
 */
int kswapd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	int ret = 0;

	if (pgdat->kswapd)
		return 0;

	pgdat->kswapd = kthread_run(kswapd, pgdat, "kswapd%d", nid);
	if (IS_ERR(pgdat->kswapd)) {
		/* failure at boot is fatal */
		BUG_ON(system_state == SYSTEM_BOOTING);
		printk("Failed to start kswapd on node %d\n",nid);
		ret = -1;
	}
	return ret;
}

static int __init kswapd_init(void)
{
	int nid;

	swap_setup();
	for_each_node_state(nid, N_HIGH_MEMORY)
 		kswapd_run(nid);
	hotcpu_notifier(cpu_callback, 0);
	return 0;
}

module_init(kswapd_init)

#ifdef CONFIG_NUMA
/*
 * Zone reclaim mode
 *
 * If non-zero call zone_reclaim when the number of free pages falls below
 * the watermarks.
 */
int zone_reclaim_mode __read_mostly;

#define RECLAIM_OFF 0
#define RECLAIM_ZONE (1<<0)	/* Run shrink_inactive_list on the zone */
#define RECLAIM_WRITE (1<<1)	/* Writeout pages during reclaim */
#define RECLAIM_SWAP (1<<2)	/* Swap pages out during reclaim */

/*
 * Priority for ZONE_RECLAIM. This determines the fraction of pages
 * of a node considered for each zone_reclaim. 4 scans 1/16th of
 * a zone.
 */
#define ZONE_RECLAIM_PRIORITY 4

/*
 * Percentage of pages in a zone that must be unmapped for zone_reclaim to
 * occur.
 */
int sysctl_min_unmapped_ratio = 1;

/*
 * If the number of slab pages in a zone grows beyond this percentage then
 * slab reclaim needs to occur.
 */
int sysctl_min_slab_ratio = 5;

static inline unsigned long zone_unmapped_file_pages(struct zone *zone)
{
	unsigned long file_mapped = zone_page_state(zone, NR_FILE_MAPPED);
	unsigned long file_lru = zone_page_state(zone, NR_INACTIVE_FILE) +
		zone_page_state(zone, NR_ACTIVE_FILE);

	/*
	 * It's possible for there to be more file mapped pages than
	 * accounted for by the pages on the file LRU lists because
	 * tmpfs pages accounted for as ANON can also be FILE_MAPPED
	 */
	return (file_lru > file_mapped) ? (file_lru - file_mapped) : 0;
}

/* Work out how many page cache pages we can reclaim in this reclaim_mode */
static long zone_pagecache_reclaimable(struct zone *zone)
{
	long nr_pagecache_reclaimable;
	long delta = 0;

	/*
	 * If RECLAIM_SWAP is set, then all file pages are considered
	 * potentially reclaimable. Otherwise, we have to worry about
	 * pages like swapcache and zone_unmapped_file_pages() provides
	 * a better estimate
	 */
	if (zone_reclaim_mode & RECLAIM_SWAP)
		nr_pagecache_reclaimable = zone_page_state(zone, NR_FILE_PAGES);
	else
		nr_pagecache_reclaimable = zone_unmapped_file_pages(zone);

	/* If we can't clean pages, remove dirty pages from consideration */
	if (!(zone_reclaim_mode & RECLAIM_WRITE))
		delta += zone_page_state(zone, NR_FILE_DIRTY);

	/* Watch for any possible underflows due to delta */
	if (unlikely(delta > nr_pagecache_reclaimable))
		delta = nr_pagecache_reclaimable;

	return nr_pagecache_reclaimable - delta;
}

/*
 * Try to free up some pages from this zone through reclaim.
 */
static int __zone_reclaim(struct zone *zone, gfp_t gfp_mask, unsigned int order)
{
	/* Minimum pages needed in order to stay on node */
	const unsigned long nr_pages = 1 << order;
	struct task_struct *p = current;
	struct reclaim_state reclaim_state;
	int priority = ZONE_RECLAIM_PRIORITY;
	struct scan_control sc = {
		.may_writepage = !!(zone_reclaim_mode & RECLAIM_WRITE),
		.may_unmap = !!(zone_reclaim_mode & RECLAIM_SWAP),
		.may_swap = 1,
		.nr_to_reclaim = max_t(unsigned long, nr_pages,
				       SWAP_CLUSTER_MAX),
		.gfp_mask = gfp_mask,
		.swappiness = vm_swappiness,
		.order = order,
		.oom_force_anon_scan = false,
	};
	unsigned long slab_reclaimable;

	/*
	 * RHEL6: we have removed the ZONE_RECLAIM_LOCKED scheme in order to
	 * allow reclaim threads performing concurrent scans for a given zone.
	 * This bailout is now required here to avoid time wasting zone scans
	 * when a thread is about to start scanning a zone that cannot satisfy
	 * the scan requirements anymore. It's better to give up and go scan
	 * another zone in fallback list to prevent wasting cycles on a scan
	 * that will not produce good results for now.
	 */
	if (zone_pagecache_reclaimable(zone) < sc.nr_to_reclaim)
		return ZONE_RECLAIM_NOSCAN;

	disable_swap_token();
	cond_resched();

	/*
	 * Zone reclaim reclaims unmapped file backed pages and
	 * slab pages if we are over the defined limits.
	 *
	 * A small portion of unmapped file backed pages is needed for
	 * file I/O otherwise pages read by file I/O will be immediately
	 * thrown out if the zone is overallocated. So we do not reclaim
	 * if less than a specified percentage of the zone is used by
	 * unmapped file backed pages.
	 */
	if (zone_pagecache_reclaimable(zone) <= zone->min_unmapped_pages &&
	    zone_page_state(zone, NR_SLAB_RECLAIMABLE) <= zone->min_slab_pages)
		return ZONE_RECLAIM_FULL;

	if (zone_is_all_unreclaimable(zone))
		return ZONE_RECLAIM_FULL;

	/*
	 * We need to be able to allocate from the reserves for RECLAIM_SWAP
	 * and we also need to be able to write out pages for RECLAIM_WRITE
	 * and RECLAIM_SWAP.
	 */
	p->flags |= PF_MEMALLOC | PF_SWAPWRITE;
	reclaim_state.reclaimed_slab = 0;
	p->reclaim_state = &reclaim_state;

	if (zone_pagecache_reclaimable(zone) > zone->min_unmapped_pages) {
		/*
		 * Free memory by calling shrink zone with increasing
		 * priorities until we have enough memory freed.
		 */
		priority = ZONE_RECLAIM_PRIORITY;
		do {
			note_zone_scanning_priority(zone, priority);
			shrink_zone(priority, zone, &sc);
			priority--;
		} while (priority >= 0 && sc.nr_reclaimed < nr_pages);
	}

	slab_reclaimable = zone_page_state(zone, NR_SLAB_RECLAIMABLE);
	if (slab_reclaimable > zone->min_slab_pages) {
		/*
		 * shrink_slab() does not currently allow us to determine how
		 * many pages were freed in this zone. So we take the current
		 * number of slab pages and shake the slab until it is reduced
		 * by the same nr_pages that we used for reclaiming unmapped
		 * pages.
		 *
		 * Note that shrink_slab will free memory on all zones and may
		 * take a long time.
		 */
		while (shrink_slab(sc.nr_scanned, gfp_mask, order) &&
			zone_page_state(zone, NR_SLAB_RECLAIMABLE) >
				slab_reclaimable - nr_pages)
			;

		/*
		 * Update nr_reclaimed by the number of slab pages we
		 * reclaimed from this zone.
		 */
		sc.nr_reclaimed += slab_reclaimable -
			zone_page_state(zone, NR_SLAB_RECLAIMABLE);
	}

	p->reclaim_state = NULL;
	current->flags &= ~(PF_MEMALLOC | PF_SWAPWRITE);
	trace_mm_directreclaim_reclaimzone(zone->node,
				sc.nr_reclaimed, priority);
	return sc.nr_reclaimed >= nr_pages;
}

static int zone_reclaim_compact(struct zone *preferred_zone,
				struct zone *zone, gfp_t gfp_mask,
				unsigned int order,
				bool sync_compaction,
				bool *need_compaction)
{
	bool contended;

	if (compaction_deferred(preferred_zone) ||
	    !order ||
	    (gfp_mask & (__GFP_FS|__GFP_IO)) != (__GFP_FS|__GFP_IO)) {
		*need_compaction = false;
		return COMPACT_SKIPPED;
	}

	*need_compaction = true;
	return compact_zone_order(zone, order,
				  gfp_mask,
				  sync_compaction,
				  &contended);
}

int zone_reclaim(struct zone *preferred_zone, struct zone *zone,
		 gfp_t gfp_mask, unsigned int order,
		 unsigned long mark, int classzone_idx, int alloc_flags)
{
	int node_id;
	int ret, c_ret;
	bool sync_compaction = false, need_compaction = false;

	/*
	 * Do not scan if the allocation should not be delayed.
	 */
	if (!(gfp_mask & __GFP_WAIT) || (current->flags & PF_MEMALLOC))
		return ZONE_RECLAIM_NOSCAN;

	/*
	 * Only run zone reclaim on the local zone or on zones that do not
	 * have associated processors. This will favor the local processor
	 * over remote processors and spread off node memory allocations
	 * as wide as possible.
	 */
	node_id = zone_to_nid(zone);
	if (node_state(node_id, N_CPU) && node_id != numa_node_id())
		return ZONE_RECLAIM_NOSCAN;

repeat_compaction:
	/*
	 * If this allocation may be satisfied by memory compaction,
	 * run compaction before reclaim.
	 */
	c_ret = zone_reclaim_compact(preferred_zone,
				     zone, gfp_mask, order,
				     sync_compaction,
				     &need_compaction);
	if (need_compaction &&
	    c_ret != COMPACT_SKIPPED &&
	    zone_watermark_ok(zone, order, mark,
			      classzone_idx,
			      alloc_flags)) {
#ifdef CONFIG_COMPACTION
		zone->compact_considered = 0;
		zone->compact_defer_shift = 0;
#endif
		return ZONE_RECLAIM_SUCCESS;
	}

	/*
	 * reclaim if compaction failed because not enough memory was
	 * available or if compaction didn't run (order 0) or didn't
	 * succeed.
	 */
	ret = __zone_reclaim(zone, gfp_mask, order);
	if (ret == ZONE_RECLAIM_SUCCESS) {
		if (zone_watermark_ok(zone, order, mark,
				      classzone_idx,
				      alloc_flags))
			return ZONE_RECLAIM_SUCCESS;

		/*
		 * If compaction run but it was skipped and reclaim was
		 * successful keep going.
		 */
		if (need_compaction && c_ret == COMPACT_SKIPPED) {
			/*
			 * If it's ok to wait for I/O we can as well run sync
			 * compaction
			 */
			sync_compaction = !!(zone_reclaim_mode &
					     (RECLAIM_WRITE|RECLAIM_SWAP));
			cond_resched();
			goto repeat_compaction;
		}
	}
	if (need_compaction)
		defer_compaction(preferred_zone);

	if (!ret)
		count_vm_event(PGSCAN_ZONE_RECLAIM_FAILED);

	return ret;
}
#endif

/*
 * page_evictable - test whether a page is evictable
 * @page: the page to test
 * @vma: the VMA in which the page is or will be mapped, may be NULL
 *
 * Test whether page is evictable--i.e., should be placed on active/inactive
 * lists vs unevictable list.  The vma argument is !NULL when called from the
 * fault path to determine how to instantate a new page.
 *
 * Reasons page might not be evictable:
 * (1) page's mapping marked unevictable
 * (2) page is part of an mlocked VMA
 *
 */
int page_evictable(struct page *page, struct vm_area_struct *vma)
{

	if (mapping_unevictable(page_mapping(page)))
		return 0;

	if (PageMlocked(page) || (vma && is_mlocked_vma(vma, page)))
		return 0;

	return 1;
}

#ifdef CONFIG_SHMEM
/**
 * check_move_unevictable_page - check page for evictability and move to appropriate zone lru list
 * @page: page to check evictability and move to appropriate lru list
 * @zone: zone page is in
 *
 * Checks a page for evictability and moves the page to the appropriate
 * zone lru list.
 *
 * Restrictions: zone->lru_lock must be held, page must be on LRU and must
 * have PageUnevictable set.
 *
 * This function is only used for SysV IPC SHM_UNLOCK.
 */
static void check_move_unevictable_page(struct page *page, struct zone *zone)
{
	struct lruvec *lruvec;

	VM_BUG_ON(PageActive(page));
retry:
	ClearPageUnevictable(page);
	if (page_evictable(page, NULL)) {
		enum lru_list l = page_lru_base_type(page);

		__dec_zone_state(zone, NR_UNEVICTABLE);
		lruvec = mem_cgroup_lru_move_lists(zone, page,
						   LRU_UNEVICTABLE, l);
		list_move(&page->lru, &lruvec->lists[l]);
		__inc_zone_state(zone, NR_INACTIVE_ANON + l);
		__count_vm_event(UNEVICTABLE_PGRESCUED);
	} else {
		/*
		 * rotate unevictable list
		 */
		SetPageUnevictable(page);
		lruvec = mem_cgroup_lru_move_lists(zone, page, LRU_UNEVICTABLE,
						   LRU_UNEVICTABLE);
		list_move(&page->lru, &lruvec->lists[LRU_UNEVICTABLE]);
		if (page_evictable(page, NULL))
			goto retry;
	}
}

/**
 * scan_mapping_unevictable_pages - scan an address space for evictable pages
 * @mapping: struct address_space to scan for evictable pages
 *
 * Scan all pages in mapping.  Check unevictable pages for
 * evictability and move them to the appropriate zone lru list.
 *
 * This function is only used for SysV IPC SHM_UNLOCK.
 */
void scan_mapping_unevictable_pages(struct address_space *mapping)
{
	pgoff_t next = 0;
	pgoff_t end   = (i_size_read(mapping->host) + PAGE_CACHE_SIZE - 1) >>
			 PAGE_CACHE_SHIFT;
	struct zone *zone;
	struct pagevec pvec;

	if (mapping->nrpages == 0)
		return;

	pagevec_init(&pvec, 0);
	while (next < end &&
		pagevec_lookup(&pvec, mapping, next, PAGEVEC_SIZE)) {
		int i;
		int pg_scanned = 0;

		zone = NULL;

		for (i = 0; i < pagevec_count(&pvec); i++) {
			struct page *page = pvec.pages[i];
			pgoff_t page_index = page->index;
			struct zone *pagezone = page_zone(page);

			pg_scanned++;
			if (page_index > next)
				next = page_index;
			next++;

			if (pagezone != zone) {
				if (zone)
					spin_unlock_irq(&zone->lru_lock);
				zone = pagezone;
				spin_lock_irq(&zone->lru_lock);
			}

			if (PageLRU(page) && PageUnevictable(page))
				check_move_unevictable_page(page, zone);
		}
		if (zone)
			spin_unlock_irq(&zone->lru_lock);
		pagevec_release(&pvec);

		count_vm_events(UNEVICTABLE_PGSCANNED, pg_scanned);
		cond_resched();
	}
}
#else
void scan_mapping_unevictable_pages(struct address_space *mapping)
{
}
#endif /* CONFIG_SHMEM */

/**
 * scan_zone_unevictable_pages - check unevictable list for evictable pages
 * @zone - zone of which to scan the unevictable list
 *
 * Scan @zone's unevictable LRU lists to check for pages that have become
 * evictable.  Move those that have to @zone's inactive list where they
 * become candidates for reclaim, unless shrink_inactive_zone() decides
 * to reactivate them.  Pages that are still unevictable are rotated
 * back onto @zone's unevictable list.
 */
#define SCAN_UNEVICTABLE_BATCH_SIZE 16UL /* arbitrary lock hold batch size */
static void scan_zone_unevictable_pages(struct zone *zone)
{
	struct list_head *l_unevictable = &zone->lruvec.lists[LRU_UNEVICTABLE];
	unsigned long scan;
	unsigned long nr_to_scan = zone_page_state(zone, NR_UNEVICTABLE);

	while (nr_to_scan > 0) {
		unsigned long batch_size = min(nr_to_scan,
						SCAN_UNEVICTABLE_BATCH_SIZE);

		spin_lock_irq(&zone->lru_lock);
		for (scan = 0;  scan < batch_size; scan++) {
			struct page *page = lru_to_page(l_unevictable);

			if (!trylock_page(page))
				continue;

			prefetchw_prev_lru_page(page, l_unevictable, flags);

			if (likely(PageLRU(page) && PageUnevictable(page)))
				check_move_unevictable_page(page, zone);

			unlock_page(page);
		}
		spin_unlock_irq(&zone->lru_lock);

		nr_to_scan -= batch_size;
	}
}


/**
 * scan_all_zones_unevictable_pages - scan all unevictable lists for evictable pages
 *
 * A really big hammer:  scan all zones' unevictable LRU lists to check for
 * pages that have become evictable.  Move those back to the zones'
 * inactive list where they become candidates for reclaim.
 * This occurs when, e.g., we have unswappable pages on the unevictable lists,
 * and we add swap to the system.  As such, it runs in the context of a task
 * that has possibly/probably made some previously unevictable pages
 * evictable.
 */
static void scan_all_zones_unevictable_pages(void)
{
	struct zone *zone;

	for_each_zone(zone) {
		scan_zone_unevictable_pages(zone);
	}
}

/*
 * scan_unevictable_pages [vm] sysctl handler.  On demand re-scan of
 * all nodes' unevictable lists for evictable pages
 */
unsigned long scan_unevictable_pages;

int scan_unevictable_handler(struct ctl_table *table, int write,
			   void __user *buffer,
			   size_t *length, loff_t *ppos)
{
	proc_doulongvec_minmax(table, write, buffer, length, ppos);

	if (write && *(unsigned long *)table->data)
		scan_all_zones_unevictable_pages();

	scan_unevictable_pages = 0;
	return 0;
}

/*
 * per node 'scan_unevictable_pages' attribute.  On demand re-scan of
 * a specified node's per zone unevictable lists for evictable pages.
 */

static ssize_t read_scan_unevictable_node(struct sys_device *dev,
					  struct sysdev_attribute *attr,
					  char *buf)
{
	return sprintf(buf, "0\n");	/* always zero; should fit... */
}

static ssize_t write_scan_unevictable_node(struct sys_device *dev,
					   struct sysdev_attribute *attr,
					const char *buf, size_t count)
{
	struct zone *node_zones = NODE_DATA(dev->id)->node_zones;
	struct zone *zone;
	unsigned long res;
	unsigned long req = strict_strtoul(buf, 10, &res);

	if (!req)
		return 1;	/* zero is no-op */

	for (zone = node_zones; zone - node_zones < MAX_NR_ZONES; ++zone) {
		if (!populated_zone(zone))
			continue;
		scan_zone_unevictable_pages(zone);
	}
	return 1;
}


static SYSDEV_ATTR(scan_unevictable_pages, S_IRUGO | S_IWUSR,
			read_scan_unevictable_node,
			write_scan_unevictable_node);

int scan_unevictable_register_node(struct node *node)
{
	return sysdev_create_file(&node->sysdev, &attr_scan_unevictable_pages);
}

void scan_unevictable_unregister_node(struct node *node)
{
	sysdev_remove_file(&node->sysdev, &attr_scan_unevictable_pages);
}

