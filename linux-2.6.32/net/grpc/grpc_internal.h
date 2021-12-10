#ifndef __GRPC_INTERNAL__
#define __GRPC_INTERNAL__

#include <linux/uio.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/radix-tree.h>
#include <linux/slab.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <net/grpc/grpc.h>

#define __GRPC_HEADER_FLAGS_SIGNAL    (1<<0)
#define __GRPC_HEADER_FLAGS_SIGACK    (1<<1)
#define __GRPC_HEADER_FLAGS_SRV_REPLY (1<<3)
#define __GRPC_HEADER_FLAGS_CANCEL_PACK (1<<4)

enum {
	__GRPC_FLAGS_EMERGENCY_BUF = __GRPC_FLAGS_MAX,
	__GRPC_FLAGS_NEW_DESC_ID,
	__GRPC_FLAGS_CLOSED,
};

#define GRPC_FLAGS_EMERGENCY_BUF	(1<<__GRPC_FLAGS_EMERGENCY_BUF)
#define GRPC_FLAGS_NEW_DESC_ID	(1<<__GRPC_FLAGS_NEW_DESC_ID)
#define GRPC_FLAGS_CLOSED	(1<<__GRPC_FLAGS_CLOSED)

struct grpc_desc_send {
	atomic_t seq_id;
	spinlock_t lock;
	struct list_head list_desc_head;
	void *emergency_send_buf;
	int flags;
};

struct grpc_desc_recv {
	atomic_t seq_id;
	atomic_t nbunexpected;
	unsigned long received_packets;      // bitfield
	struct list_head list_desc_head;
	struct list_head list_provided_head;
	struct list_head list_signal_head;
	struct grpc_desc_elem *iter;
	struct grpc_desc_elem *iter_provided;
	int flags;
};

struct __grpc_synchro_tree {
	spinlock_t lock;
	struct radix_tree_root rt;
};

enum ____grpc_synchro_flags {
	/* __grpc_synchro has been removed from its radix tree */
	____GRPC_SYNCHRO_DEAD,
};

#define __GRPC_SYNCHRO_DEAD (1<<____GRPC_SYNCHRO_DEAD)

struct __grpc_synchro {
	atomic_t usage;
	atomic_t v;
	struct list_head list_waiting_head;
	spinlock_t lock;
	unsigned long key;
	struct __grpc_synchro_tree *tree;
	int flags;
};

struct grpc_synchro {
	int max;
	int order;
	unsigned long mask_packets;          // bitfield
	union {
		struct __grpc_synchro tab;
		struct __grpc_synchro_tree tree;
	} nodes[HCC_MAX_NODES];
	struct list_head list_synchro;
	char label[16];
};

struct grpc_service {
	enum grpc_target target;
	enum grpc_handler handler;
	grpc_handler_t h;
	struct grpc_synchro *synchro;
	enum grpcid id;
	unsigned long flags;
};

struct __grpc_header {
	hcc_node_t from;
	hcc_node_t client;
	unsigned long desc_id;
	unsigned long seq_id;
	unsigned long link_seq_id;
	unsigned long link_ack_id;
	enum grpcid grpcid;
	int flags;
};

struct grpc_desc_elem {
	unsigned long seq_id;
	void* raw;
	void* data;
	size_t size;
	struct list_head list_desc_elem;
	int flags;
};

struct grpc_tx_elem {
	hcc_nodemask_t nodes;
	hcc_node_t index;
	hcc_node_t link_seq_index;
	void *data;
	struct iovec iov[2];
	struct __grpc_header h;
	unsigned long *link_seq_id;
	struct list_head tx_queue;
};

extern struct grpc_service** grpc_services;

struct hashtable_t;
extern struct hashtable_t* desc_srv[HCC_MAX_NODES];
extern struct hashtable_t* desc_clt;
extern unsigned long grpc_desc_id;
extern unsigned long grpc_desc_done_id[HCC_MAX_NODES];
extern spinlock_t grpc_desc_done_lock[HCC_MAX_NODES];

extern struct kmem_cache* grpc_desc_cachep;
extern struct kmem_cache* grpc_desc_send_cachep;
extern struct kmem_cache* grpc_desc_recv_cachep;
extern struct kmem_cache* grpc_desc_elem_cachep;
extern struct kmem_cache* grpc_tx_elem_cachep;
extern struct kmem_cache* __grpc_synchro_cachep;

extern unsigned long grpc_mask[GRPCID_MAX/(sizeof(unsigned long)*8)+1];
extern spinlock_t waiting_desc_lock;
extern struct list_head waiting_desc;

extern struct list_head list_synchro_head;

extern unsigned long grpc_link_send_seq_id[HCC_MAX_NODES];
extern unsigned long grpc_link_send_ack_id[HCC_MAX_NODES];
extern unsigned long grpc_link_recv_seq_id[HCC_MAX_NODES];

struct grpc_desc* grpc_desc_alloc(void);
struct grpc_desc_send* grpc_desc_send_alloc(void);
struct grpc_desc_recv* grpc_desc_recv_alloc(void);
void grpc_desc_elem_free(struct grpc_desc_elem *elem);

void grpc_desc_get(struct grpc_desc* desc);
void grpc_desc_put(struct grpc_desc* desc);

void grpc_do_signal(struct grpc_desc *desc,
		   struct grpc_desc_elem *signal_elem);
void grpc_signal_deliver_pending(struct grpc_desc *desc,
				struct grpc_desc_recv *desc_recv);
int __grpc_signalack(struct grpc_desc* desc);

int grpc_handle_new(struct grpc_desc* desc);
void grpc_wake_up_thread(struct grpc_desc *desc);

void grpc_new_desc_id_lock(void);
void grpc_new_desc_id_unlock(void);
int __grpc_emergency_send_buf_alloc(struct grpc_desc *desc, size_t size);
void __grpc_emergency_send_buf_free(struct grpc_desc *desc);
int __grpc_send_ll(struct grpc_desc* desc,
		  hcc_nodemask_t *nodes,
		  unsigned long seq_id,
		  int __flags,
		  const void* data, size_t size,
		  int grpc_flags);

void __grpc_put_raw_data(void *raw);
void __grpc_get_raw_data(void *raw);

void __grpc_synchro_free(struct grpc_desc *desc);
int grpc_synchro_lookup(struct grpc_desc* desc);

int comlayer_init(void);
void comlayer_enable(void);
int comlayer_enable_dev(const char *name);
void comlayer_disable(void);
int comlayer_disable_dev(const char *name);
int thread_pool_init(void);
int grpclayer_init(void);
int grpc_monitor_init(void);

#define grpc_link_seq_id(p, node) \
  __asm__ __volatile__( \
    "lock xadd %%eax, %1" \
    :"=a" (p), "=m" (grpc_link_send_seq_id[node]) \
    :"a" (1) : "memory")

#define grpc_desc_set_id(p) \
  __asm__ __volatile__( \
    "lock xadd %%eax, %1" \
    :"=a" (p), "=m" (grpc_desc_id) \
    :"a" (1) : "memory")

#endif

static inline
int __grpc_synchro_get(struct __grpc_synchro *__grpc_synchro){
	return !atomic_inc_not_zero(&__grpc_synchro->usage);
}

static inline
void __grpc_synchro_put(struct __grpc_synchro *__grpc_synchro){

	if(!atomic_dec_and_test(&__grpc_synchro->usage))
		return;

	// Check if we are in a tree
	// If we are, we need to free the data
	if(__grpc_synchro->tree){
		spin_lock_bh(&__grpc_synchro->tree->lock);

		/* Maybe another CPU or a softIRQ had to replace __grpc_synchro
		 * in the radix tree (see grpc_synchro_lookup_order1())
		 */
		if (likely(!(__grpc_synchro->flags & __GRPC_SYNCHRO_DEAD)))
			radix_tree_delete(&__grpc_synchro->tree->rt,
					  __grpc_synchro->key);

		spin_unlock_bh(&__grpc_synchro->tree->lock);

		kmem_cache_free(__grpc_synchro_cachep,
				__grpc_synchro);
	}
}
