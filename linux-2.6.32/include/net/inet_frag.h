#ifndef __NET_FRAG_H__
#define __NET_FRAG_H__

#include <linux/rbtree.h>

/* RedHat kABI: cannot change netns_frags, because its is part of
 * structs netns_ipv4, netns_ipv6 and netns_nf_frag.  Which in turn
 * is part of (include/net/net_namespace.h) struct net.
 */
struct netns_frags {

/* Compile time catch, elements in struct that are not used any longer */
#ifdef __GENKSYMS__
	int			nqueues;
	atomic_t		mem;
#else
	int			nqueues_kabi_build_err_not_used;
	atomic_t		mem_kabi_build_err_not_used;
#endif

	/* RedHat abusing lru_list.next pointer for kABI workaround */
	struct list_head	lru_list;

	/* sysctls */
	int			timeout;
	int			high_thresh;
	int			low_thresh;
};

struct netns_frags_priv {
	struct list_head        lru_list;
	spinlock_t              lru_lock;
	int			nqueues;
	/* Its important for performance to keep lru_list and mem on
	 * separate cachelines
	 */
	atomic_t		mem ____cacheline_aligned_in_smp;
};
#define netns_frags_priv(nf) ((struct netns_frags_priv *)(nf)->lru_list.next)

struct inet_frag_queue {
	spinlock_t		lock;
	struct timer_list	timer;      /* when will this queue expire? */
	struct list_head	lru_list;   /* lru list member */
	struct hlist_node	list;
	atomic_t		refcnt;
	struct sk_buff		*fragments;  /* Used in IPv6. */
	struct rb_root		rb_fragments; /* Used in IPv4. */
	struct sk_buff		*fragments_tail;
	struct sk_buff		*last_run_head;
	ktime_t			stamp;
	int			len;        /* total length of orig datagram */
	int			meat;
	__u8			last_in;    /* first/last segment arrived? */

#define INET_FRAG_COMPLETE	4
#define INET_FRAG_FIRST_IN	2
#define INET_FRAG_LAST_IN	1

	u16			max_size;

	struct netns_frags	*net;
};

#define INETFRAGS_HASHSZ	1024

struct inet_frag_bucket {
	struct hlist_head	chain;
	spinlock_t		chain_lock;
};

struct inet_frags {
	struct inet_frag_bucket	hash[INETFRAGS_HASHSZ];
	/* This rwlock is a global lock (seperate per IPv4, IPv6 and
	 * netfilter). Important to keep this on a seperate cacheline.
	 * Its primarily a rebuild protection rwlock.
	 */
	rwlock_t		lock ____cacheline_aligned_in_smp;
	int			secret_interval;
	struct timer_list	secret_timer;
	u32			rnd;
	int			qsize;

	unsigned int		(*hashfn)(struct inet_frag_queue *);
	bool			(*match)(struct inet_frag_queue *q, void *arg);
	void			(*constructor)(struct inet_frag_queue *q,
						void *arg);
	void			(*destructor)(struct inet_frag_queue *);
	void			(*skb_free)(struct sk_buff *);
	void			(*frag_expire)(unsigned long data);
};

void inet_frags_init(struct inet_frags *);
void inet_frags_fini(struct inet_frags *);

int  inet_frags_init_net(struct netns_frags *nf);
void inet_frags_exit_net(struct netns_frags *nf, struct inet_frags *f);

void inet_frag_kill(struct inet_frag_queue *q, struct inet_frags *f);
void inet_frag_destroy(struct inet_frag_queue *q,
				struct inet_frags *f, int *work);
int inet_frag_evictor(struct netns_frags *nf, struct inet_frags *f, bool force);
struct inet_frag_queue *inet_frag_find(struct netns_frags *nf,
		struct inet_frags *f, void *key, unsigned int hash)
	__releases(&f->lock);

/* Free all skbs in the queue; return the sum of their truesizes. */
unsigned int inet_frag_rbtree_purge(struct rb_root *root);

static inline void inet_frag_put(struct inet_frag_queue *q, struct inet_frags *f)
{
	if (atomic_dec_and_test(&q->refcnt))
		inet_frag_destroy(q, f, NULL);
}

/* Memory Tracking Functions. */

static inline int frag_mem_limit(struct netns_frags *nf)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(nf);
	return atomic_read(&nf_priv->mem);
}

static inline void sub_frag_mem_limit(struct inet_frag_queue *q, int i)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(q->net);
	atomic_sub(i, &nf_priv->mem);
}

static inline void add_frag_mem_limit(struct inet_frag_queue *q, int i)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(q->net);
	atomic_add(i, &nf_priv->mem);
}

static inline void init_frag_mem_limit(struct netns_frags *nf)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(nf);
	atomic_set(&nf_priv->mem, 0);
}

static inline int sum_frag_mem_limit(struct netns_frags *nf)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(nf);

	return atomic_read(&nf_priv->mem);
}

static inline void inet_frag_lru_move(struct inet_frag_queue *q)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(q->net);
	spin_lock(&nf_priv->lru_lock);
	if (!list_empty(&nf_priv->lru_list))
		list_move_tail(&q->lru_list, &nf_priv->lru_list);
	spin_unlock(&nf_priv->lru_lock);
}

static inline void inet_frag_lru_del(struct inet_frag_queue *q)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(q->net);
	spin_lock(&nf_priv->lru_lock);
	list_del_init(&q->lru_list);
	nf_priv->nqueues--;
	spin_unlock(&nf_priv->lru_lock);
}

static inline void inet_frag_lru_add(struct netns_frags *nf,
				     struct inet_frag_queue *q)
{
	struct netns_frags_priv *nf_priv = netns_frags_priv(nf);
	spin_lock(&nf_priv->lru_lock);
	list_add_tail(&q->lru_list, &nf_priv->lru_list);
	nf_priv->nqueues++;
	spin_unlock(&nf_priv->lru_lock);
}
#endif
