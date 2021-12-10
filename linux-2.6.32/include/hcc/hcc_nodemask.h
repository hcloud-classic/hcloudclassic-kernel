#ifndef __HCC_NODEMASK_H
#define __HCC_NODEMASK_H

/*
 * This file is nearly a copy/paste of linux/cpumask.h (2.6.20)
 * Btw this code is very closed to the NUMA related code linux/nodemask.h
 * It will be a good idea to check if can merge these two files
 *
 * nodemasks provide a bitmap suitable for representing the
 * set of nodes in a system, one bit position per node number.
 *
 * See detailed comments in the file linux/bitmap.h describing the
 * data type on which these hcc_nodemasks are based.
 *
 * For details of hcc_nodemask_scnprintf() and hcc_nodemask_parse_user(),
 * see bitmap_scnprintf() and bitmap_parse_user() in lib/bitmap.c.
 * For details of hcc_nodelist_scnprintf() and hcc_nodelist_parse(), see
 * bitmap_scnlistprintf() and bitmap_parselist(), also in bitmap.c.
 * For details of hcc_node_remap(), see bitmap_bitremap in lib/bitmap.c
 * For details of hcc_nodes_remap(), see bitmap_remap in lib/bitmap.c.
 *
 * The available nodemask operations are:
 *
 * void hcc_node_set(node, mask)		turn on bit 'node' in mask
 * void hcc_node_clear(node, mask)		turn off bit 'node' in mask
 * void hcc_nodes_setall(mask)		set all bits
 * void hcc_nodes_clear(mask)		clear all bits
 * int hcc_node_isset(node, mask)		true iff bit 'node' set in mask
 * int hcc_node_test_and_set(node, mask)	test and set bit 'node' in mask
 *
 * void hcc_nodes_and(dst, src1, src2)	dst = src1 & src2  [intersection]
 * void hcc_nodes_or(dst, src1, src2)	dst = src1 | src2  [union]
 * void hcc_nodes_xor(dst, src1, src2)	dst = src1 ^ src2
 * void hcc_nodes_andnot(dst, src1, src2)	dst = src1 & ~src2
 * void hcc_nodes_complement(dst, src)	dst = ~src
 *
 * int hcc_nodes_equal(mask1, mask2)		Does mask1 == mask2?
 * int hcc_nodes_intersects(mask1, mask2)	Do mask1 and mask2 intersect?
 * int hcc_nodes_subset(mask1, mask2)	Is mask1 a subset of mask2?
 * int hcc_nodes_empty(mask)			Is mask empty (no bits sets)?
 * int hcc_nodes_full(mask)			Is mask full (all bits sets)?
 * int hcc_nodes_weight(mask)		Hamming weigh - number of set bits
 *
 * void hcc_nodes_shift_right(dst, src, n)	Shift right
 * void hcc_nodes_shift_left(dst, src, n)	Shift left
 *
 * int first_hcc_node(mask)			Number lowest set bit, or HCC_MAX_NODES
 * int next_hcc_node(node, mask)		Next node past 'node', or HCC_MAX_NODES
 *
 * hcc_nodemask_t hcc_nodemask_of_node(node)	Return nodemask with bit 'node' set
 * HCC_NODE_MASK_ALL				Initializer - all bits set
 * HCC_NODE_MASK_NONE			Initializer - no bits set
 * unsigned long *hcc_nodes_addr(mask)	Array of unsigned long's in mask
 *
 * int hcc_nodemask_scnprintf(buf, len, mask) Format nodemask for printing
 * int hcc_nodemask_parse_user(ubuf, ulen, mask)	Parse ascii string as nodemask
 * int hcc_nodelist_scnprintf(buf, len, mask) Format nodemask as list for printing
 * int hcc_nodelist_parse(buf, map)		Parse ascii string as nodelist
 * int hcc_node_remap(oldbit, old, new)	newbit = map(old, new)(oldbit)
 * int hcc_nodes_remap(dst, src, old, new)	*dst = map(old, new)(src)
 *
 * for_each_hcc_node_mask(node, mask)		for-loop node over mask
 *
 * int num_online_hcc_nodes()		Number of online NODEs
 * int num_possible_hcc_nodes()		Number of all possible NODEs
 * int num_present_hcc_nodes()		Number of present NODEs
 *
 * int hcc_node_online(node)			Is some node online?
 * int hcc_node_possible(node)		Is some node possible?
 * int hcc_node_present(node)			Is some node present (can schedule)?
 *
 * int any_online_hcc_node(mask)		First online node in mask
 *
 * for_each_possible_hcc_node(node)		for-loop node over node_possible_map
 * for_each_online_hcc_node(node)		for-loop node over node_online_map
 * for_each_present_hcc_node(node)		for-loop node over node_present_map
 *
 * Subtlety:
 * 1) The 'type-checked' form of node_isset() causes gcc (3.3.2, anyway)
 *    to generate slightly worse code.  Note for example the additional
 *    40 lines of assembly code compiling the "for each possible node"
 *    loops buried in the disk_stat_read() macros calls when compiling
 *    drivers/block/genhd.c (arch i386, CONFIG_SMP=y).  So use a simple
 *    one-line #define for node_isset(), instead of wrapping an inline
 *    inside a macro, the way we do the other calls.
 */

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/bitmap.h>
#include <hcc/sys/types.h>
#if HCC_MAX_NODES <= 1
/* hcc_node_id is used for some macros in this special case */
#include <hcc/hcc_init.h>
#endif


typedef struct { DECLARE_BITMAP(bits, HCC_MAX_NODES); } hcc_nodemask_t;
typedef struct { DECLARE_BITMAP(bits, HCC_HARD_MAX_NODES); } __hcc_nodemask_t;

extern hcc_nodemask_t _unused_hcc_nodemask_arg_;

#define hcc_node_set(node, dst) __hcc_node_set((node), &(dst))
static inline void __hcc_node_set(int node, volatile hcc_nodemask_t *dstp)
{
	set_bit(node, dstp->bits);
}

#define hcc_node_clear(node, dst) __hcc_node_clear((node), &(dst))
static inline void __hcc_node_clear(int node, volatile hcc_nodemask_t *dstp)
{
	clear_bit(node, dstp->bits);
}

#define hcc_nodes_setall(dst) __hcc_nodes_setall(&(dst))
static inline void __hcc_nodes_setall(hcc_nodemask_t *dstp)
{
	bitmap_fill(dstp->bits, HCC_MAX_NODES);
}

#define hcc_nodes_clear(dst) __hcc_nodes_clear(&(dst))
static inline void __hcc_nodes_clear(hcc_nodemask_t *dstp)
{
	bitmap_zero(dstp->bits, HCC_MAX_NODES);
}

#define hcc_nodes_copy(dst, src) __hcc_nodes_copy(&(dst), &(src))
static inline void __hcc_nodes_copy(hcc_nodemask_t *dstp, const hcc_nodemask_t *srcp)
{
	bitmap_copy(dstp->bits, srcp->bits, HCC_MAX_NODES);
}

/* No static inline type checking - see Subtlety (1) above. */
#define hcc_node_isset(node, hcc_nodemask) test_bit((node), (hcc_nodemask).bits)
#define __hcc_node_isset(node, hcc_nodemask) test_bit((node), (hcc_nodemask)->bits)

#define hcc_node_test_and_set(node, hcc_nodemask) __hcc_node_test_and_set((node), &(hcc_nodemask))
static inline int __hcc_node_test_and_set(int node, hcc_nodemask_t *addr)
{
	return test_and_set_bit(node, addr->bits);
}

#define hcc_nodes_and(dst, src1, src2) __hcc_nodes_and(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hcc_nodes_and(hcc_nodemask_t *dstp, const hcc_nodemask_t *src1p,
					const hcc_nodemask_t *src2p, int nbits)
{
	bitmap_and(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hcc_nodes_or(dst, src1, src2) __hcc_nodes_or(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hcc_nodes_or(hcc_nodemask_t *dstp, const hcc_nodemask_t *src1p,
					const hcc_nodemask_t *src2p, int nbits)
{
	bitmap_or(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hcc_nodes_xor(dst, src1, src2) __hcc_nodes_xor(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hcc_nodes_xor(hcc_nodemask_t *dstp, const hcc_nodemask_t *src1p,
					const hcc_nodemask_t *src2p, int nbits)
{
	bitmap_xor(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hcc_nodes_andnot(dst, src1, src2) \
				__hcc_nodes_andnot(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hcc_nodes_andnot(hcc_nodemask_t *dstp, const hcc_nodemask_t *src1p,
					const hcc_nodemask_t *src2p, int nbits)
{
	bitmap_andnot(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hcc_nodes_complement(dst, src) __hcc_nodes_complement(&(dst), &(src), HCC_MAX_NODES)
static inline void __hcc_nodes_complement(hcc_nodemask_t *dstp,
					const hcc_nodemask_t *srcp, int nbits)
{
	bitmap_complement(dstp->bits, srcp->bits, nbits);
}

#define hcc_nodes_equal(src1, src2) __hcc_nodes_equal(&(src1), &(src2))
static inline int __hcc_nodes_equal(const hcc_nodemask_t *src1p,
				   const hcc_nodemask_t *src2p)
{
	return bitmap_equal(src1p->bits, src2p->bits, HCC_MAX_NODES);
}

#define hcc_nodes_intersects(src1, src2) __hcc_nodes_intersects(&(src1), &(src2), HCC_MAX_NODES)
static inline int __hcc_nodes_intersects(const hcc_nodemask_t *src1p,
					const hcc_nodemask_t *src2p, int nbits)
{
	return bitmap_intersects(src1p->bits, src2p->bits, nbits);
}

#define hcc_nodes_subset(src1, src2) __hcc_nodes_subset(&(src1), &(src2), HCC_MAX_NODES)
static inline int __hcc_nodes_subset(const hcc_nodemask_t *src1p,
					const hcc_nodemask_t *src2p, int nbits)
{
	return bitmap_subset(src1p->bits, src2p->bits, nbits);
}

#define hcc_nodes_empty(src) __hcc_nodes_empty(&(src))
static inline int __hcc_nodes_empty(const hcc_nodemask_t *srcp)
{
	return bitmap_empty(srcp->bits, HCC_MAX_NODES);
}

#define hcc_nodes_full(nodemask) __hcc_nodes_full(&(nodemask), HCC_MAX_NODES)
static inline int __hcc_nodes_full(const hcc_nodemask_t *srcp, int nbits)
{
	return bitmap_full(srcp->bits, nbits);
}

#define hcc_nodes_weight(nodemask) __hcc_nodes_weight(&(nodemask))
static inline int __hcc_nodes_weight(const hcc_nodemask_t *srcp)
{
	return bitmap_weight(srcp->bits, HCC_MAX_NODES);
}

#define hcc_nodes_shift_right(dst, src, n) \
			__hcc_nodes_shift_right(&(dst), &(src), (n), HCC_MAX_NODES)
static inline void __hcc_nodes_shift_right(hcc_nodemask_t *dstp,
					const hcc_nodemask_t *srcp, int n, int nbits)
{
	bitmap_shift_right(dstp->bits, srcp->bits, n, nbits);
}

#define hcc_nodes_shift_left(dst, src, n) \
			__hcc_nodes_shift_left(&(dst), &(src), (n), HCC_MAX_NODES)
static inline void __hcc_nodes_shift_left(hcc_nodemask_t *dstp,
					const hcc_nodemask_t *srcp, int n, int nbits)
{
	bitmap_shift_left(dstp->bits, srcp->bits, n, nbits);
}

#define first_hcc_node(src) __first_hcc_node(&(src))
static inline int __first_hcc_node(const hcc_nodemask_t *srcp)
{
	return min_t(int, HCC_MAX_NODES, find_first_bit(srcp->bits, HCC_MAX_NODES));
}

#define next_hcc_node(n, src) __next_hcc_node((n), &(src))
static inline int __next_hcc_node(int n, const hcc_nodemask_t *srcp)
{
	return min_t(int, HCC_MAX_NODES,find_next_bit(srcp->bits, HCC_MAX_NODES, n+1));
}

#define hcc_nodemask_of_node(node)						\
({									\
	typeof(_unused_hcc_nodemask_arg_) m;					\
	if (sizeof(m) == sizeof(unsigned long)) {			\
		m.bits[0] = 1UL<<(node);					\
	} else {							\
		hcc_nodes_clear(m);						\
		hcc_node_set((node), m);					\
	}								\
	m;								\
})

#define HCC_NODE_MASK_LAST_WORD BITMAP_LAST_WORD_MASK(HCC_MAX_NODES)

#if HCC_MAX_NODES <= BITS_PER_LONG

#define HCC_NODE_MASK_ALL							\
(hcc_nodemask_t) { {								\
	[BITS_TO_LONGS(HCC_MAX_NODES)-1] = HCC_NODE_MASK_LAST_WORD			\
} }

#else

#define HCC_NODE_MASK_ALL							\
(hcc_nodemask_t) { {								\
	[0 ... BITS_TO_LONGS(HCC_MAX_NODES)-2] = ~0UL,			\
	[BITS_TO_LONGS(HCC_MAX_NODES)-1] = HCC_NODE_MASK_LAST_WORD			\
} }

#endif

#define HCC_NODE_MASK_NONE							\
(hcc_nodemask_t) { {								\
	[0 ... BITS_TO_LONGS(HCC_MAX_NODES)-1] =  0UL				\
} }

#define HCC_NODE_MASK_NODE0							\
(hcc_nodemask_t) { {								\
	[0] =  1UL							\
} }

#define hcc_nodes_addr(src) ((src).bits)

#define hcc_nodemask_scnprintf(buf, len, src) \
			__hcc_nodemask_scnprintf((buf), (len), &(src), HCC_MAX_NODES)
static inline int __hcc_nodemask_scnprintf(char *buf, int len,
					const hcc_nodemask_t *srcp, int nbits)
{
	return bitmap_scnprintf(buf, len, srcp->bits, nbits);
}

#define hcc_nodemask_parse_user(ubuf, ulen, dst) \
			__hcc_nodemask_parse_user((ubuf), (ulen), &(dst), HCC_MAX_NODES)
static inline int __hcc_nodemask_parse_user(const char __user *buf, int len,
					hcc_nodemask_t *dstp, int nbits)
{
	return bitmap_parse_user(buf, len, dstp->bits, nbits);
}

#define hcc_nodelist_scnprintf(buf, len, src) \
			__hcc_nodelist_scnprintf((buf), (len), &(src), HCC_MAX_NODES)
static inline int __hcc_nodelist_scnprintf(char *buf, int len,
					const hcc_nodemask_t *srcp, int nbits)
{
	return bitmap_scnlistprintf(buf, len, srcp->bits, nbits);
}

#define hcc_nodelist_parse(buf, dst) __hcc_nodelist_parse((buf), &(dst), HCC_MAX_NODES)
static inline int __hcc_nodelist_parse(const char *buf, hcc_nodemask_t *dstp, int nbits)
{
	return bitmap_parselist(buf, dstp->bits, nbits);
}

#define hcc_node_remap(oldbit, old, new) \
		__hcc_node_remap((oldbit), &(old), &(new), HCC_MAX_NODES)
static inline int __hcc_node_remap(int oldbit,
		const hcc_nodemask_t *oldp, const hcc_nodemask_t *newp, int nbits)
{
	return bitmap_bitremap(oldbit, oldp->bits, newp->bits, nbits);
}

#define hcc_nodes_remap(dst, src, old, new) \
		__hcc_nodes_remap(&(dst), &(src), &(old), &(new), HCC_MAX_NODES)
static inline void __hcc_nodes_remap(hcc_nodemask_t *dstp, const hcc_nodemask_t *srcp,
		const hcc_nodemask_t *oldp, const hcc_nodemask_t *newp, int nbits)
{
	bitmap_remap(dstp->bits, srcp->bits, oldp->bits, newp->bits, nbits);
}

#if HCC_MAX_NODES > 1
#define for_each_hcc_node_mask(node, mask)		\
	for ((node) = first_hcc_node(mask);		\
		(node) < HCC_MAX_NODES;		\
		(node) = next_hcc_node((node), (mask)))
#define __for_each_hcc_node_mask(node, mask)		\
	for ((node) = __first_hcc_node(mask);		\
		(node) < HCC_MAX_NODES;		\
		(node) = __next_hcc_node((node), (mask)))

#else /* HCC_MAX_NODES == 1 */
#define for_each_hcc_node_mask(node, mask)		\
	for ((node) = hcc_node_id; (node) < (hcc_node_id+1); (node)++, (void)mask)
#define __for_each_hcc_node_mask(node, mask)		\
	for ((node) = hcc_node_id; (node) < (hcc_node_id+1); (node)++, (void)mask)
#endif /* HCC_MAX_NODES */

#define next_hcc_node_in_ring(node, v) __next_hcc_node_in_ring(node, &(v))
static inline hcc_node_t __next_hcc_node_in_ring(hcc_node_t node,
						      const hcc_nodemask_t *v)
{
	hcc_node_t res;
	res = __next_hcc_node(node, v);

	if (res < HCC_MAX_NODES)
		return res;

	return __first_hcc_node(v);
}

#define nth_hcc_node(node, v) __nth_hcc_node(node, &(v))
static inline hcc_node_t __nth_hcc_node(hcc_node_t node,
					     const hcc_nodemask_t *v)
{
	hcc_node_t iter;

	iter = __first_hcc_node(v);
	while (node > 0) {
		iter = __next_hcc_node(iter, v);
		node--;
	}

	return iter;
}

/** Return true if the index is the only one set in the vector */
#define hcc_node_is_unique(node, v) __hcc_node_is_unique(node, &(v))
static inline int __hcc_node_is_unique(hcc_node_t node,
				      const hcc_nodemask_t *v)
{
  int i;
  
  i = __first_hcc_node(v);
  if(i != node) return 0;
  
  i = __next_hcc_node(node, v);
  if(i != HCC_MAX_NODES) return 0;
  
  return 1;
}

/*
 * hcc_node_online_map: list of nodes available as object injection target
 * hcc_node_present_map: list of nodes ready to be added in a cluster
 * hcc_node_possible_map: list of nodes that may join the cluster in the future
 */

extern hcc_nodemask_t hcc_node_possible_map;
extern hcc_nodemask_t hcc_node_online_map;
extern hcc_nodemask_t hcc_node_present_map;

#if HCC_MAX_NODES > 1
#define num_online_hcc_nodes()	hcc_nodes_weight(hcc_node_online_map)
#define num_possible_hcc_nodes()	hcc_nodes_weight(hcc_node_possible_map)
#define num_present_hcc_nodes()	hcc_nodes_weight(hcc_node_present_map)
#define hcc_node_online(node)	hcc_node_isset((node), hcc_node_online_map)
#define hcc_node_possible(node)	hcc_node_isset((node), hcc_node_possible_map)
#define hcc_node_present(node)	hcc_node_isset((node), hcc_node_present_map)

#define any_online_hcc_node(mask) __any_online_hcc_node(&(mask))
int __any_online_hcc_node(const hcc_nodemask_t *mask);

#else

#define num_online_hcc_nodes()	1
#define num_possible_hcc_nodes()	1
#define num_present_hcc_nodes()	1
#define hcc_node_online(node)		((node) == hcc_node_id)
#define hcc_node_possible(node)	((node) == hcc_node_id)
#define hcc_node_present(node)	((node) == hcc_node_id)

#define any_online_hcc_node(mask)		hcc_node_id
#endif

#define for_each_possible_hcc_node(node)  for_each_hcc_node_mask((node), hcc_node_possible_map)
#define for_each_online_hcc_node(node)  for_each_hcc_node_mask((node), hcc_node_online_map)
#define for_each_present_hcc_node(node) for_each_hcc_node_mask((node), hcc_node_present_map)

#define set_hcc_node_possible(node) hcc_node_set(node, hcc_node_possible_map)
#define set_hcc_node_online(node)   hcc_node_set(node, hcc_node_online_map)
#define set_hcc_node_present(node)  hcc_node_set(node, hcc_node_present_map)

#define clear_hcc_node_possible(node) hcc_node_clear(node, hcc_node_possible_map)
#define clear_hcc_node_online(node)   hcc_node_clear(node, hcc_node_online_map)
#define clear_hcc_node_present(node)  hcc_node_clear(node, hcc_node_present_map)

#define nth_possible_hcc_node(node) nth_hcc_node(node, hcc_node_possible_map)
#define nth_online_hcc_node(node) nth_hcc_node(node, hcc_node_online_map)
#define nth_present_hcc_node(node) nth_hcc_node(node, hcc_node_present_map)

#define hcc_node_next_possible(node) next_hcc_node(node, hcc_node_possible_map)
#define hcc_node_next_online(node) next_hcc_node(node, hcc_node_online_map)
#define hcc_node_next_present(node) next_hcc_node(node, hcc_node_present_map)

#define hcc_node_next_possible_in_ring(node) next_hcc_node_in_ring(node, hcc_node_possible_map)
#define hcc_node_next_online_in_ring(node) next_hcc_node_in_ring(node, hcc_node_online_map)
#define hcc_node_next_present_in_ring(node) next_hcc_node_in_ring(node, hcc_node_present_map)

#endif /* __HCC_NODEMASK_H */
