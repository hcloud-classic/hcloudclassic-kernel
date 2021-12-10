#ifndef LINUX_MM_INLINE_H
#define LINUX_MM_INLINE_H

#include <linux/huge_mm.h>

/**
 * page_is_file_cache - should the page be on a file LRU or anon LRU?
 * @page: the page to test
 *
 * Returns 1 if @page is page cache page backed by a regular filesystem,
 * or 0 if @page is anonymous, tmpfs or otherwise ram or swap backed.
 * Used by functions that manipulate the LRU lists, to sort a page
 * onto the right LRU list.
 *
 * We would like to get this info without a page flag, but the state
 * needs to survive until the page is last deleted from the LRU, which
 * could be as far down as __page_cache_release.
 */
static inline int page_is_file_cache(struct page *page)
{
	return !PageSwapBacked(page);
}

#ifdef CONFIG_HCC_GMM
static inline int page_is_migratable(struct page *page)
{
	return PageMigratable(page);
}
#endif

static inline void
add_page_to_lru_list(struct zone *zone, struct page *page, enum lru_list l)
{
	struct lruvec *lruvec;

	lruvec = mem_cgroup_lru_add_list(zone, page, l);
	list_add(&page->lru, &lruvec->lists[l]);
	__mod_zone_page_state(zone, NR_LRU_BASE + l, hpage_nr_pages(page));
}

static inline void
del_page_from_lru_list(struct zone *zone, struct page *page, enum lru_list l)
{
	mem_cgroup_lru_del_list(page, l);
	list_del(&page->lru);
	__mod_zone_page_state(zone, NR_LRU_BASE + l, -hpage_nr_pages(page));
}

/**
 * page_lru_base_type - which LRU list type should a page be on?
 * @page: the page to test
 *
 * Used for LRU list index arithmetic.
 *
 * Returns the base LRU type - file or anon - @page should be on.
 */
static inline enum lru_list page_lru_base_type(struct page *page)
{
#ifdef CONFIG_HCC_GMM
	BUG_ON(page_is_migratable(page) && page_is_file_cache(page));

	if (page_is_migratable(page))
		return LRU_INACTIVE_MIGR;
	else
#endif
	if (page_is_file_cache(page))
		return LRU_INACTIVE_FILE;
	return LRU_INACTIVE_ANON;
}

static inline void
del_page_from_lru(struct zone *zone, struct page *page)
{
	enum lru_list l;

	if (PageUnevictable(page)) {
		__ClearPageUnevictable(page);
		l = LRU_UNEVICTABLE;
	} else {
		l = page_lru_base_type(page);
		if (PageActive(page)) {
			__ClearPageActive(page);
			l += LRU_ACTIVE;
		}
	}
	mem_cgroup_lru_del_list(page, l);
	list_del(&page->lru);
	__mod_zone_page_state(zone, NR_LRU_BASE + l, -hpage_nr_pages(page));
}

/**
 * page_lru - which LRU list should a page be on?
 * @page: the page to test
 *
 * Returns the LRU list a page should be on, as an index
 * into the array of LRU lists.
 */
static inline enum lru_list page_lru(struct page *page)
{
	enum lru_list lru;

	if (PageUnevictable(page))
		lru = LRU_UNEVICTABLE;
	else {
		lru = page_lru_base_type(page);
		if (PageActive(page))
			lru += LRU_ACTIVE;
	}

	return lru;
}

#ifdef CONFIG_HCC_GMM
#define BUILD_LRU_ID(active,file,gdm) (LRU_BASE + LRU_MIGR * gdm + LRU_FILE * file + active)
#define RECLAIM_STAT_INDEX(file,gdm) (file + 2 * gdm)
static inline int reclaim_stat_index(struct page *page)
{
	return RECLAIM_STAT_INDEX(page_is_file_cache(page),
				  page_is_migratable(page));
}
#endif

#endif
