/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#ifndef __RPC_INTERNAL__
#define __RPC_INTERNAL__

#include <linux/uio.h>
#include <hcc/sys/types.h>
#include <net/hccgrpc/rpc.h>
#include <linux/radix-tree.h>


#define __RPC_HEADER_FLAGS_SIGNAL    (1<<0)
#define __RPC_HEADER_FLAGS_SIGACK    (1<<1)
#define __RPC_HEADER_FLAGS_SRV_REPLY (1<<3)
#define __RPC_HEADER_FLAGS_CANCEL_PACK (1<<4)

enum {
    __RPC_FLAGS_EMERGENCY_BUF = __RPC_FLAGS_MAX,
    __RPC_FLAGS_NEW_DESC_ID,
    __RPC_FLAGS_CLOSED,
};

#define RPC_FLAGS_EMERGENCY_BUF	(1<<__RPC_FLAGS_EMERGENCY_BUF)
#define RPC_FLAGS_NEW_DESC_ID	(1<<__RPC_FLAGS_NEW_DESC_ID)
#define RPC_FLAGS_CLOSED	(1<<__RPC_FLAGS_CLOSED)

struct rpc_desc_send {
    atomic_t seq_id;
    spinlock_t lock;
    struct list_head list_desc_head;
    void *emergency_send_buf;
    int flags;
};

struct rpc_desc_recv {
    atomic_t seq_id;
    atomic_t nbunexpected;
    unsigned long received_packets;
    struct list_head list_desc_head;
    struct list_head list_provided_head;
    struct list_head list_signal_head;
    struct rpc_desc_elem *iter;
    struct rpc_desc_elem *iter_provided;
    int flags;
};

extern unsigned long rpc_desc_id;

extern struct kmem_cache* rpc_desc_cachep;
extern struct kmem_cache* rpc_desc_send_cachep;
extern struct kmem_cache* rpc_desc_recv_cachep;
extern struct kmem_cache* rpc_desc_elem_cachep;
extern struct kmem_cache* rpc_tx_elem_cachep;
extern struct kmem_cache* __rpc_synchro_cachep;

extern unsigned long rpc_mask[RPCID_MAX/(sizeof(unsigned long)*8)+1];
extern spinlock_t waiting_desc_lock;
extern struct list_head waiting_desc;

extern struct list_head list_synchro_head;

extern unsigned long rpc_link_send_seq_id[HCC_MAX_NODES];
extern unsigned long rpc_link_send_ack_id[HCC_MAX_NODES];
extern unsigned long rpc_link_recv_seq_id[HCC_MAX_NODES];

struct rpc_desc* rpc_desc_alloc(void);
struct rpc_desc_send* rpc_desc_send_alloc(void);
struct rpc_desc_recv* rpc_desc_recv_alloc(void);
void rpc_desc_elem_free(struct rpc_desc_elem *elem);

void rpc_desc_get(struct rpc_desc* desc);
void rpc_desc_put(struct rpc_desc* desc);

void rpc_do_signal(struct rpc_desc *desc,
                   struct rpc_desc_elem *signal_elem);
void rpc_signal_deliver_pending(struct rpc_desc *desc,
                                struct rpc_desc_recv *desc_recv);
int __rpc_signalack(struct rpc_desc* desc);

int rpc_handle_new(struct rpc_desc* desc);
void rpc_wake_up_thread(struct rpc_desc *desc);

void rpc_new_desc_id_lock(void);
void rpc_new_desc_id_unlock(void);
int __rpc_emergency_send_buf_alloc(struct rpc_desc *desc, size_t size);
void __rpc_emergency_send_buf_free(struct rpc_desc *desc);
int __rpc_send_ll(struct rpc_desc* desc,
                  hccnodemask_t *nodes,
                  unsigned long seq_id,
                  int __flags,
                  const void* data, size_t size,
                  int rpc_flags);

void __rpc_put_raw_data(void *raw);
void __rpc_get_raw_data(void *raw);

void __rpc_synchro_free(struct rpc_desc *desc);
int rpc_synchro_lookup(struct rpc_desc* desc);

struct __rpc_synchro_tree {
    spinlock_t lock;
    struct radix_tree_root rt;
};

enum ____rpc_synchro_flags {
    ____RPC_SYNCHRO_DEAD,
};

#define __RPC_SYNCHRO_DEAD (1<<____RPC_SYNCHRO_DEAD)

struct __rpc_synchro {
    atomic_t usage;
    atomic_t v;
    struct list_head list_waiting_head;
    spinlock_t lock;
    unsigned long key;
    struct __rpc_synchro_tree *tree;
    int flags;
};

struct rpc_synchro {
    int max;
    int order;
    unsigned long mask_packets;
    union {
        struct __rpc_synchro tab;
        struct __rpc_synchro_tree tree;
    } nodes[HCC_MAX_NODES];
    struct list_head list_synchro;
    char label[16];
};

struct rpc_service {
    enum rpc_target target;
    enum rpc_handler handler;
    rpc_handler_t h;
    struct rpc_synchro *synchro;
    enum rpcid id;
    unsigned long flags;
};

struct __rpc_header {
    hcc_node_t from;
    hcc_node_t client;
    unsigned long desc_id;
    unsigned long seq_id;
    unsigned long link_seq_id;
    unsigned long link_ack_id;
    enum rpcid rpcid;
    int flags;
};
struct rpc_desc_elem {
    unsigned long seq_id;
    void* raw;
    void* data;
    size_t size;
    struct list_head list_desc_elem;
    int flags;
};
struct rpc_tx_elem {
    hccnodemask_t nodes;
    hcc_node_t index;
    hcc_node_t link_seq_index;
    void *data;
    struct iovec iov[2];
    struct __rpc_header h;
    unsigned long *link_seq_id;
    struct list_head tx_queue;
};
extern struct rpc_service** rpc_services;
struct hashtable_t;
extern struct hashtable_t* desc_srv[HCC_MAX_NODES];

extern struct hashtable_t* desc_clt;
extern unsigned long rpc_desc_id;
extern unsigned long rpc_desc_done_id[HCC_MAX_NODES];

extern spinlock_t rpc_desc_done_lock[HCC_MAX_NODES];

static inline
int __rpc_synchro_get(struct __rpc_synchro *__rpc_synchro){
    return !atomic_inc_not_zero(&__rpc_synchro->usage);
}
int rpclayer_init(void);

int worker_pool_init(void);

#define rpc_link_seq_id(p, node) \
  __asm__ __volatile__( \
    "lock xadd %%eax, %1" \
    :"=a" (p), "=m" (rpc_link_send_seq_id[node]) \
    :"a" (1) : "memory")

#define rpc_desc_set_id(p) \
  __asm__ __volatile__( \
    "lock xadd %%eax, %1" \
    :"=a" (p), "=m" (rpc_desc_id) \
    :"a" (1) : "memory")

#endif

static inline
void __rpc_synchro_put(struct __rpc_synchro *__rpc_synchro)
{
    if(!atomic_dec_and_test(&__rpc_synchro->usage))
        return;

    if(__rpc_synchro->tree){
        spin_lock_bh(&__rpc_synchro->tree->lock);

        if (likely(!(__rpc_synchro->flags & __RPC_SYNCHRO_DEAD)))
            radix_tree_delete(&__rpc_synchro->tree->rt,
                              __rpc_synchro->key);

        spin_unlock_bh(&__rpc_synchro->tree->lock);

        kmem_cache_free(__rpc_synchro_cachep,
                        __rpc_synchro);
    }
}