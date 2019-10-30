#ifndef __HCCNODEMASK__
#define __HCCNODEMASK__

#include <linux/bitmap.h>
#include <hcc/sys/types.h>

typedef struct { DECLARE_BITMAP(bits, HCC_MAX_NODES); } hccnodemask_t;
typedef struct { DECLARE_BITMAP(bits, HCC_HARD_MAX_NODES); } __hccnodemask_t;

extern hccnodemask_t _unused_hccnodemask_arg_;

#define hccnode_set(node, dst) __hccnode_set((node), &(dst))
static inline void __hccnode_set(int node, volatile hccnodemask_t *dstp)
{
    set_bit(node, dstp->bits);
}

#define hccnode_clear(node, dst) __hccnode_clear((node), &(dst))
static inline void __hccnode_clear(int node, volatile hccnodemask_t *dstp)
{
    clear_bit(node, dstp->bits);
}

#define hccnodes_clear(dst) __hccnodes_clear(&(dst))
static inline void __hccnodes_clear(hccnodemask_t *dstp)
{
    bitmap_zero(dstp->bits, HCC_MAX_NODES);
}

#define hccnodes_setall(dst) __hccnodes_setall(&(dst))
static inline void __hccnodes_setall(hccnodemask_t *dstp)
{
    bitmap_fill(dstp->bits, HCC_MAX_NODES);
}

#define hccnodes_copy(dst, src) __hccnodes_copy(&(dst), &(src))
static inline void __hccnodes_copy(hccnodemask_t *dstp, const hccnodemask_t *srcp)
{
    bitmap_copy(dstp->bits, srcp->bits, HCC_MAX_NODES);
}

#define hccnode_isset(node, hccnodemask) test_bit((node), (hccnodemask).bits)
#define __hccnode_isset(node, hccnodemask) test_bit((node), (hccnodemask)->bits)

#define hccnode_test_and_set(node, hccnodemask) __hccnode_test_and_set((node), &(hccnodemask))
static inline int __hccnode_test_and_set(int node, hccnodemask_t *addr)
{
    return test_and_set_bit(node, addr->bits);
}

#define hccnodes_and(dst, src1, src2) __hccnodes_and(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hccnodes_and(hccnodemask_t *dstp, const hccnodemask_t *src1p,
                                  const hccnodemask_t *src2p, int nbits)
{
    bitmap_and(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hccnodes_or(dst, src1, src2) __hccnodes_or(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hccnodes_or(hccnodemask_t *dstp, const hccnodemask_t *src1p,
                                 const hccnodemask_t *src2p, int nbits)
{
    bitmap_or(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hccnodes_xor(dst, src1, src2) __hccnodes_xor(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hccnodes_xor(hccnodemask_t *dstp, const hccnodemask_t *src1p,
                                  const hccnodemask_t *src2p, int nbits)
{
    bitmap_xor(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hccnodes_andnot(dst, src1, src2) \
				__hccnodes_andnot(&(dst), &(src1), &(src2), HCC_MAX_NODES)
static inline void __hccnodes_andnot(hccnodemask_t *dstp, const hccnodemask_t *src1p,
                                     const hccnodemask_t *src2p, int nbits)
{
    bitmap_andnot(dstp->bits, src1p->bits, src2p->bits, nbits);
}

#define hccnodes_complement(dst, src) __hccnodes_complement(&(dst), &(src), HCC_MAX_NODES)
static inline void __hccnodes_complement(hccnodemask_t *dstp,
                                         const hccnodemask_t *srcp, int nbits)
{
    bitmap_complement(dstp->bits, srcp->bits, nbits);
}

#define hccnodes_equal(src1, src2) __hccnodes_equal(&(src1), &(src2))
static inline int __hccnodes_equal(const hccnodemask_t *src1p,
                                   const hccnodemask_t *src2p)
{
    return bitmap_equal(src1p->bits, src2p->bits, HCC_MAX_NODES);
}

#define hccnodes_intersects(src1, src2) __hccnodes_intersects(&(src1), &(src2), HCC_MAX_NODES)
static inline int __hccnodes_intersects(const hccnodemask_t *src1p,
                                        const hccnodemask_t *src2p, int nbits)
{
    return bitmap_intersects(src1p->bits, src2p->bits, nbits);
}

#define hccnodes_subset(src1, src2) __hccnodes_subset(&(src1), &(src2), HCC_MAX_NODES)
static inline int __hccnodes_subset(const hccnodemask_t *src1p,
                                    const hccnodemask_t *src2p, int nbits)
{
    return bitmap_subset(src1p->bits, src2p->bits, nbits);
}

#define hccnodes_empty(src) __hccnodes_empty(&(src))
static inline int __hccnodes_empty(const hccnodemask_t *srcp)
{
    return bitmap_empty(srcp->bits, HCC_MAX_NODES);
}

#define hccnodes_full(nodemask) __hccnodes_full(&(nodemask), HCC_MAX_NODES)
static inline int __hccnodes_full(const hccnodemask_t *srcp, int nbits)
{
    return bitmap_full(srcp->bits, nbits);
}

#define hccnodes_weight(nodemask) __hccnodes_weight(&(nodemask))
static inline int __hccnodes_weight(const hccnodemask_t *srcp)
{
    return bitmap_weight(srcp->bits, HCC_MAX_NODES);
}

#define hccnodes_shift_right(dst, src, n) \
			__hccnodes_shift_right(&(dst), &(src), (n), HCC_MAX_NODES)
static inline void __hccnodes_shift_right(hccnodemask_t *dstp,
                                          const hccnodemask_t *srcp, int n, int nbits)
{
    bitmap_shift_right(dstp->bits, srcp->bits, n, nbits);
}

#define hccnodes_shift_left(dst, src, n) \
			__hccnodes_shift_left(&(dst), &(src), (n), HCC_MAX_NODES)
static inline void __hccnodes_shift_left(hccnodemask_t *dstp,
                                         const hccnodemask_t *srcp, int n, int nbits)
{
    bitmap_shift_left(dstp->bits, srcp->bits, n, nbits);
}

#define first_hccnode(src) __first_hccnode(&(src))
static inline int __first_hccnode(const hccnodemask_t *srcp)
{
    return min_t(int, HCC_MAX_NODES, find_first_bit(srcp->bits, HCC_MAX_NODES));
}

#define next_hccnode(n, src) __next_hccnode((n), &(src))
static inline int __next_hccnode(int n, const hccnodemask_t *srcp)
{
    return min_t(int, HCC_MAX_NODES,find_next_bit(srcp->bits, HCC_MAX_NODES, n+1));
}

#if HCC_MAX_NODES > 1
#define for_each_hccnode_mask(node, mask)		\
	for ((node) = first_hccnode(mask);		\
		(node) < HCC_MAX_NODES;		\
		(node) = next_hccnode((node), (mask)))
#define __for_each_hccnode_mask(node, mask)		\
	for ((node) = __first_hccnode(mask);		\
		(node) < HCC_MAX_NODES;		\
		(node) = __next_hccnode((node), (mask)))
#endif

#endif