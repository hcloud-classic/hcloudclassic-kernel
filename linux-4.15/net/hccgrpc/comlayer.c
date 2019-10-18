/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#include <linux/kernel.h>
#include <linux/tipc.h>
#include <net/tipc.h>

#include <linux/irqflags.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/sysrq.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <linux/workqueue.h>
#include <linux/net_namespace.h>
#include <linux/sched/signal.h>
#include <hcc/sys/types.h>
#include "rpc_internal.h"
#include <hcc/lib/hashtable.h>
#include <net/hccgrpc/rpc.h>

#define TIPC_HCC_SERVER_TYPE (1+TIPC_RESERVED_TYPES)
struct tipc_name_seq tipc_seq;

#define ACK_CLEANUP_WINDOW_SIZE 100
#define MAX_CONSECUTIVE_RECV 1000

#define REJECT_BACKOFF (HZ / 2)

#define ACK_CLEANUP_WINDOW_SIZE__LOWMEM_MODE 20
#define MAX_CONSECUTIVE_RECV__LOWMEM_MODE 20

struct tx_manager {

    struct list_head delayed_tx_queue;
    struct delayed_work delayed_tx_work;
    struct list_head not_retx_queue;
    struct delayed_work cleanup_not_retx_work;
    struct list_head retx_queue;
    struct rpc_tx_elem *retx_iter;
    struct delayed_work retx_work;
    struct delayed_work unreachable_work;
    struct delayed_work reachable_work;

};

struct rx_manager {

    hcc_node_t from;
    struct sk_buff_head rx_queue;
    struct delayed_work run_rx_queue_work;

};

static DEFINE_PER_CPU(struct tx_manager, tipc_tx_manager);

static DEFINE_SPINLOCK(tipc_tx_queue_lock);
static void tipc_send_ack_worker(struct work_struct *work);
static DECLARE_DELAYED_WORK(tipc_ack_work, tipc_send_ack_worker);
struct rx_manager tipc_rx_manager[HCC_MAX_NODES];

struct workqueue_struct *hcccom_wq;
#ifdef CONFIG_64BIT


static atomic64_t consumed_bytes;

static inline void consumed_bytes_add(long load)
{
	atomic64_add(load, &consumed_bytes);
}

static inline void consumed_bytes_sub(long load)
{
	atomic64_sub(load, &consumed_bytes);
}

s64 rpc_consumed_bytes(void)
{
	return atomic64_read(&consumed_bytes);
}

#else /* !CONFIG_64BIT */
static s64 consumed_bytes;

static DEFINE_SPINLOCK(consumed_bytes_lock);
static inline void consumed_bytes_add(long load)
{
    unsigned long flags;

    spin_lock_irqsave(&consumed_bytes_lock, flags);
    consumed_bytes += load;
    spin_unlock_irqrestore(&consumed_bytes_lock, flags);
}

static inline void consumed_bytes_sub(long load)
{
    unsigned long flags;

    spin_lock_irqsave(&consumed_bytes_lock, flags);
    consumed_bytes -= load;
    spin_unlock_irqrestore(&consumed_bytes_lock, flags);
}

s64 rpc_consumed_bytes(void)
{
    unsigned long flags;
    s64 ret;

    spin_lock_irqsave(&consumed_bytes_lock, flags);
    ret = consumed_bytes;
    spin_unlock_irqrestore(&consumed_bytes_lock, flags);

    return ret;
}

#endif /* !CONFIG_64BIT */

u32 tipc_user_ref = 0;
u32 tipc_port_ref;
//DEFINE_PER_CPU(u32, tipc_send_ref);
DEFINE_PER_CPU(struct socket, tipc_send_ref);
struct tipc_name_seq tipc_seq;

hccnodemask_t nodes_requiring_ack;
unsigned long last_cleanup_ack[HCC_MAX_NODES];
static int ack_cleanup_window_size;
static int consecutive_recv[HCC_MAX_NODES];
static int max_consecutive_recv[HCC_MAX_NODES];

void __rpc_put_raw_data(void *data)
{
    kfree_skb((struct sk_buff*)data);
}

void __rpc_get_raw_data(void *data)
{
    skb_get((struct sk_buff*)data);
}

static
inline int __send_iovec(hcc_node_t node, int nr_iov, struct iovec *iov)
{
//    struct tipc_name name = {
//            .type = TIPC_HCC_SERVER_TYPE,
//            .instance = node
//    };
//    struct __rpc_header *h = iov[0].iov_base;
//    int err;
//
//    h->link_ack_id = rpc_link_recv_seq_id[node] - 1;
//    lockdep_off();
//    err = tipc_sendmsg(&per_cpu(tipc_send_ref, smp_processor_id()),
//                         iov->addr, (int)iov->len);
//
//    err = tipc_send2name(per_cpu(tipc_send_ref, smp_processor_id()),
//                         &name, 0,
//                         nr_iov, iov);
//
//    lockdep_on();
//    if (!err)
//        consecutive_recv[node] = 0;
//    return err;
    return 0; // cgs
}

static
inline int send_iovec(hcc_node_t node, int nr_iov, struct iovec *iov)
{
    int err;

    local_bh_disable();
    err = __send_iovec(node, nr_iov, iov);
    local_bh_enable();

    return err;
}

static struct rpc_tx_elem *__rpc_tx_elem_alloc(size_t size, int nr_dest)
{
    struct rpc_tx_elem *elem;

    elem = kmem_cache_alloc(rpc_tx_elem_cachep, GFP_ATOMIC);
    if (!elem)
        goto oom;
    consumed_bytes_add(size);
    elem->data = kmalloc(size, GFP_ATOMIC);
    if (!elem->data)
        goto oom_free_elem;
    elem->link_seq_id = kmalloc(sizeof(*elem->link_seq_id) * nr_dest,
                                GFP_ATOMIC);
    elem->iov[1].iov_len = size;
    if (!elem->link_seq_id)
        goto oom_free_data;

    return elem;

    oom_free_data:
    kfree(elem->data);
    oom_free_elem:
    consumed_bytes_sub(size);
    kmem_cache_free(rpc_tx_elem_cachep, elem);
    oom:
    return NULL;
}

static void __rpc_tx_elem_free(struct rpc_tx_elem *elem)
{
    kfree(elem->link_seq_id);
    kfree(elem->data);
    consumed_bytes_sub(elem->iov[1].iov_len);
    kmem_cache_free(rpc_tx_elem_cachep, elem);
}

static int __rpc_tx_elem_send(struct rpc_tx_elem *elem, int link_seq_index,
                              hcc_node_t node)
{
    int err = 0;

    elem->h.link_seq_id = elem->link_seq_id[link_seq_index];
    if (elem->h.link_seq_id <= rpc_link_send_ack_id[node])
        goto out;

    err = send_iovec(node, ARRAY_SIZE(elem->iov), elem->iov);

    out:
    return err;
}

static
void tipc_send_ack_worker(struct work_struct *work)
{
    struct iovec iov[1];
    struct __rpc_header h;
    hcc_node_t node;
    int err;

    if (next_hccnode(0, nodes_requiring_ack) > HCC_MAX_NODES)
        return;

    h.from = HCC_NODE_ID;
    h.rpcid = RPC_ACK;
    h.flags = 0;

    iov[0].iov_base = &h;
    iov[0].iov_len = sizeof(h);

    for_each_hccnode_mask(node, nodes_requiring_ack) {
        err = send_iovec(node, ARRAY_SIZE(iov), iov);
        if (!err)
            hccnode_clear(node, nodes_requiring_ack);
    }
}

static void tipc_delayed_tx_worker(struct work_struct *work)
{
    struct tx_manager *manager = container_of(work, struct tx_manager, delayed_tx_work.work);
    LIST_HEAD(queue);
    LIST_HEAD(not_retx_queue);
    struct rpc_tx_elem *iter;
    struct rpc_tx_elem *safe;

    lockdep_off();

    spin_lock_bh(&tipc_tx_queue_lock);
    list_splice_init(&manager->delayed_tx_queue, &queue);
    spin_unlock_bh(&tipc_tx_queue_lock);

    if(list_empty(&queue))
        goto exit_empty;

    list_for_each_entry_safe(iter, safe, &queue, tx_queue){
        hccnodemask_t nodes;
        hcc_node_t link_seq_index, node;

        link_seq_index = iter->link_seq_index;
        if (link_seq_index) {
            hccnodes_setall(nodes);
            hccnodes_shift_left(nodes, nodes, iter->index);
            hccnodes_and(nodes, nodes, iter->nodes);
        } else {
            hccnodes_copy(nodes, iter->nodes);
        }
        for_each_hccnode_mask(node, nodes){
            int err;

            err = __rpc_tx_elem_send(iter, link_seq_index, node);
            if (err < 0) {
                iter->index = node;
                iter->link_seq_index = link_seq_index;

                goto exit;
            }

            link_seq_index++;
        }
        iter->index = 0;
        iter->link_seq_index = 0;

        list_move_tail(&iter->tx_queue, &not_retx_queue);
    }

    exit:
    if (!list_empty(&queue)) {
        spin_lock_bh(&tipc_tx_queue_lock);
        list_splice(&queue, &manager->delayed_tx_queue);
        list_splice(&not_retx_queue, manager->not_retx_queue.prev);
        spin_unlock_bh(&tipc_tx_queue_lock);
    } else {
        if (likely(!list_empty(&not_retx_queue))) {
            spin_lock_bh(&tipc_tx_queue_lock);
            list_splice(&not_retx_queue, manager->not_retx_queue.prev);
            spin_unlock_bh(&tipc_tx_queue_lock);
        }
    }

    exit_empty:
    lockdep_on();
}

static void tipc_retx_worker(struct work_struct *work)
{
    struct tx_manager *manager = container_of(work, struct tx_manager, retx_work.work);
    LIST_HEAD(queue);
    LIST_HEAD(not_retx_queue);
    struct rpc_tx_elem *iter;
    struct rpc_tx_elem *safe;

    lockdep_off();

    spin_lock_bh(&tipc_tx_queue_lock);
    list_splice_init(&manager->retx_queue, &queue);
    iter = manager->retx_iter;
    manager->retx_iter = NULL;
    spin_unlock_bh(&tipc_tx_queue_lock);

    if(list_empty(&queue))
        goto exit_empty;

    if(!iter) {
        iter = list_entry(&queue,
        struct rpc_tx_elem,
        tx_queue);
    } else {
        iter = list_entry(iter->tx_queue.prev, struct rpc_tx_elem, tx_queue);
    }

    list_for_each_entry_safe_continue(iter, safe, &queue, tx_queue){
        hccnodemask_t nodes;
        hcc_node_t link_seq_index, node;

        link_seq_index = iter->link_seq_index;
        if (link_seq_index) {
            hccnodes_setall(nodes);
            hccnodes_shift_left(nodes, nodes, iter->index);
            hccnodes_and(nodes, nodes, iter->nodes);
        } else {
            hccnodes_copy(nodes, iter->nodes);
        }
        for_each_hccnode_mask(node, nodes){
            int err;

            err = __rpc_tx_elem_send(iter, link_seq_index, node);
            if (err < 0) {
                iter->index = node;
                iter->link_seq_index = link_seq_index;

                goto exit;
            }

            link_seq_index++;
        }

        iter->index = 0;
        iter->link_seq_index = 0;

        list_move_tail(&iter->tx_queue, &not_retx_queue);
    }

    iter = NULL;

    exit:
    if (!list_empty(&not_retx_queue)){
        spin_lock_bh(&tipc_tx_queue_lock);
        list_splice(&not_retx_queue, &manager->not_retx_queue);
        spin_unlock_bh(&tipc_tx_queue_lock);
    }

    if (!list_empty(&queue)) {
        spin_lock_bh(&tipc_tx_queue_lock);
        list_splice(&queue, &manager->retx_queue);

        if (iter)
            manager->retx_iter = iter;
        spin_unlock_bh(&tipc_tx_queue_lock);
    }

    exit_empty:
    lockdep_on();
}

static void tipc_cleanup_not_retx_worker(struct work_struct *work)
{
    struct tx_manager *manager = container_of(work, struct tx_manager, cleanup_not_retx_work.work);
    struct rpc_tx_elem *iter;
    struct rpc_tx_elem *safe;
    LIST_HEAD(queue);
    int node;

    spin_lock_bh(&tipc_tx_queue_lock);
    list_splice_init(&manager->not_retx_queue, &queue);
    spin_unlock_bh(&tipc_tx_queue_lock);

    list_for_each_entry_safe(iter, safe, &queue, tx_queue){
        int need_to_free, link_seq_index;

        need_to_free = 0;
        link_seq_index = 0;

        for_each_hccnode_mask(node, iter->nodes){

            iter->h.link_seq_id = iter->link_seq_id[link_seq_index];

            if (iter->h.link_seq_id >
                rpc_link_send_ack_id[node])
                goto next_iter;

            link_seq_index++;
        }
        need_to_free = 1;

        next_iter:
        if(need_to_free){
            list_del(&iter->tx_queue);
            __rpc_tx_elem_free(iter);
        }
    }

    if (!list_empty(&queue)) {
        spin_lock_bh(&tipc_tx_queue_lock);
        list_splice(&queue, &manager->not_retx_queue);
        spin_unlock_bh(&tipc_tx_queue_lock);
    }

}

static
void tipc_unreachable_node_worker(struct work_struct *work){
}

static
void tipc_reachable_node_worker(struct work_struct *work){
    struct tx_manager *manager = container_of(work, struct tx_manager, reachable_work.work);

    spin_lock_bh(&tipc_tx_queue_lock);
    list_splice_init(&manager->not_retx_queue, &manager->retx_queue);
    spin_unlock_bh(&tipc_tx_queue_lock);

    queue_delayed_work_on(smp_processor_id(), hcccom_wq,
                          &manager->retx_work, 0);
}

#define MAX_EMERGENCY_SEND 2

int __rpc_emergency_send_buf_alloc(struct rpc_desc *desc, size_t size)
{
    struct rpc_tx_elem **elem;
    int nr_dest;
    int err = 0;
    int i;

    elem = kmalloc(sizeof(*elem) * MAX_EMERGENCY_SEND, GFP_ATOMIC);
    if (!elem)
        goto oom;
    nr_dest = hccnodes_weight(desc->nodes);
    for (i = 0; i < MAX_EMERGENCY_SEND; i++) {
        elem[i] = __rpc_tx_elem_alloc(size, nr_dest);
        if (!elem[i])
            goto oom_free_elems;
    }
    desc->desc_send->emergency_send_buf = elem;

    out:
    return err;

    oom_free_elems:
    for (i--; i >= 0; i--)
        __rpc_tx_elem_free(elem[i]);
    kfree(elem);
    oom:
    err = -ENOMEM;
    goto out;
}

void __rpc_emergency_send_buf_free(struct rpc_desc *desc)
{
    struct rpc_tx_elem **elem = desc->desc_send->emergency_send_buf;
    int i;

    /* does not buy a lot, but still can help debug */
    desc->desc_send->emergency_send_buf = NULL;
    for (i = 0; i < MAX_EMERGENCY_SEND; i++)
        if (elem[i])
            /* emergency send buf was not used */
            __rpc_tx_elem_free(elem[i]);
    kfree(elem);
}

static struct rpc_tx_elem *next_emergency_send_buf(struct rpc_desc *desc)
{
    struct rpc_tx_elem **elems = desc->desc_send->emergency_send_buf;
    struct rpc_tx_elem *buf = NULL;
    int i;

    for (i = 0; i < MAX_EMERGENCY_SEND; i++)
        if (elems[i]) {
            buf = elems[i];
            elems[i] = NULL;
            break;
        }
    return buf;
}

int __rpc_send_ll(struct rpc_desc* desc,
                  hccnodemask_t *nodes,
                  unsigned long seq_id,
                  int __flags,
                  const void* data, size_t size,
                  int rpc_flags)
{
    struct rpc_tx_elem* elem;
    struct tx_manager *manager;
    hcc_node_t node;
    int link_seq_index;

    elem = __rpc_tx_elem_alloc(size, __hccnodes_weight(nodes));
    if (!elem) {
        if (rpc_flags & RPC_FLAGS_EMERGENCY_BUF)
            elem = next_emergency_send_buf(desc);
        if (!elem)
            return -ENOMEM;
    }

    link_seq_index = 0;
    __for_each_hccnode_mask(node, nodes) {
        rpc_link_seq_id(elem->link_seq_id[link_seq_index], node);
        link_seq_index++;
    }
    if (rpc_flags & RPC_FLAGS_NEW_DESC_ID)
        rpc_new_desc_id_unlock();

    elem->h.from = HCC_NODE_ID;
    elem->h.client = desc->client;
    elem->h.desc_id = desc->desc_id;
    elem->h.seq_id = seq_id;

    elem->h.flags = __flags;
    if(desc->type == RPC_RQ_SRV)
        elem->h.flags |= __RPC_HEADER_FLAGS_SRV_REPLY;

    elem->h.rpcid = desc->rpcid;

    elem->iov[0].iov_base = &elem->h;
    elem->iov[0].iov_len = sizeof(elem->h);

    elem->iov[1].iov_base = (void *) data;
    elem->iov[1].iov_len = size;

    elem->index = 0;
    elem->link_seq_index = 0;

    memcpy(elem->data, data, size);
    elem->iov[1].iov_base = elem->data;

    __hccnodes_copy(&elem->nodes, nodes);

    preempt_disable();
    manager = &per_cpu(tipc_tx_manager, smp_processor_id());
    if (irqs_disabled()) {

        lockdep_off();
        spin_lock(&tipc_tx_queue_lock);
        list_add_tail(&elem->tx_queue, &manager->delayed_tx_queue);
        spin_unlock(&tipc_tx_queue_lock);
        lockdep_on();

        queue_work(hcccom_wq, &manager->delayed_tx_work.work);

    } else {
        int err = 0;

        link_seq_index = 0;
        __for_each_hccnode_mask(node, nodes){

            err = __rpc_tx_elem_send(elem, link_seq_index, node);
            if(err<0){
                spin_lock_bh(&tipc_tx_queue_lock);
                list_add_tail(&elem->tx_queue,
                              &manager->retx_queue);
                spin_unlock_bh(&tipc_tx_queue_lock);
                break;
            }

            link_seq_index++;
        }

        if(err>=0){
            spin_lock_bh(&tipc_tx_queue_lock);
            list_add_tail(&elem->tx_queue, &manager->not_retx_queue);
            spin_unlock_bh(&tipc_tx_queue_lock);
        }
    }
    preempt_enable();
    return 0;
}

inline
void insert_in_seqid_order(struct rpc_desc_elem* desc_elem,
                           struct rpc_desc_recv* desc_recv)
{
    struct rpc_desc_elem *iter;
    struct list_head *at;

    if (unlikely(desc_elem->flags & __RPC_HEADER_FLAGS_SIGNAL)) {
        int sigack = (desc_elem->flags & __RPC_HEADER_FLAGS_SIGACK);

        at = &desc_recv->list_signal_head;
        list_for_each_entry_reverse(iter, &desc_recv->list_signal_head,
                                    list_desc_elem)
        if (iter->seq_id < desc_elem->seq_id
            || (iter->seq_id == desc_elem->seq_id && !sigack)) {
            at = &iter->list_desc_elem;
            break;
        }
    } else {
        at = &desc_recv->list_desc_head;
        list_for_each_entry_reverse(iter, &desc_recv->list_desc_head,
                                    list_desc_elem)
        if (iter->seq_id < desc_elem->seq_id) {
            at = &iter->list_desc_elem;
            break;
        }
    }
    list_add(&desc_elem->list_desc_elem, at);
}

static
inline
int do_action(struct rpc_desc *desc, struct __rpc_header *h)
{
    switch ((int)desc->state) {
        case RPC_STATE_NEW:
            spin_unlock(&desc->desc_lock);
            return rpc_handle_new(desc);
        case RPC_STATE_WAIT1:
            if (desc->type == RPC_RQ_CLT
                && desc->wait_from != h->from) {
                spin_unlock(&desc->desc_lock);
                break;
            }
        case RPC_STATE_WAIT:
            desc->state = RPC_STATE_RUN;
            wake_up_process(desc->thread);
            spin_unlock(&desc->desc_lock);
            break;
        default:
            spin_unlock(&desc->desc_lock);
            break;
    }
    return 0;
}

void rpc_desc_elem_free(struct rpc_desc_elem *elem)
{
    kfree_skb(elem->raw);
    kmem_cache_free(rpc_desc_elem_cachep, elem);
}

void rpc_do_signal(struct rpc_desc *desc,
                   struct rpc_desc_elem *signal_elem)
{
    if (desc->thread)
        send_sig(*(int*)signal_elem->data, desc->thread, 0);

    __rpc_signalack(desc);

    rpc_desc_elem_free(signal_elem);
}

inline int handle_valid_desc(struct rpc_desc *desc,
                      struct rpc_desc_recv *desc_recv,
                      struct rpc_desc_elem* descelem,
                      struct __rpc_header *h,
                      struct sk_buff *buf){
    int err;

    if(descelem->seq_id<sizeof(desc_recv->received_packets)*8)
        set_bit(descelem->seq_id-1, &desc_recv->received_packets);

    if (desc_recv->iter_provided) {

        if (unlikely(h->flags & __RPC_HEADER_FLAGS_SIGNAL)
            && (!(h->flags & __RPC_HEADER_FLAGS_SIGACK))) {
            struct rpc_desc_elem *provided;

            provided = list_entry(desc_recv->list_provided_head.prev,
            struct rpc_desc_elem, list_desc_elem);

            if (descelem->seq_id <= provided->seq_id) {

                rpc_do_signal(desc, descelem);

                spin_unlock(&desc->desc_lock);
                return 0;

            } else {
                insert_in_seqid_order(descelem, desc_recv);
            }

        } else {

            if (desc_recv->iter_provided->seq_id == descelem->seq_id) {

            } else {
                insert_in_seqid_order(descelem, desc_recv);
            }
        }

        goto do_action;

    }

    if (unlikely(h->flags & __RPC_HEADER_FLAGS_SIGNAL)
        && (!(h->flags & __RPC_HEADER_FLAGS_SIGACK))
        && (h->seq_id <= atomic_read(&desc_recv->seq_id))
        && ((desc->service->flags & RPC_FLAGS_NOBLOCK) || desc->thread)) {

        rpc_do_signal(desc, descelem);

        spin_unlock(&desc->desc_lock);
        return 0;
    }

    insert_in_seqid_order(descelem, desc_recv);
    atomic_inc(&desc_recv->nbunexpected);

    do_action:
    err = do_action(desc, h);
    if (err) {
        spin_lock(&desc->desc_lock);
        BUG_ON(desc->state != RPC_STATE_NEW || descelem->seq_id > 1);
        atomic_dec(&desc_recv->nbunexpected);
        list_del(&descelem->list_desc_elem);
        spin_unlock(&desc->desc_lock);
    }
    return err;
}

static struct rpc_desc *server_rpc_desc_setup(const struct __rpc_header *h)
{
    struct rpc_desc *desc;

    desc = rpc_desc_alloc();
    if (!desc)
        goto out;

    desc->desc_send = rpc_desc_send_alloc();
    if (!desc->desc_send)
        goto err_desc_send;

    desc->desc_recv[0] = rpc_desc_recv_alloc();
    if (!desc->desc_recv[0])
        goto err_desc_recv;

    hccnode_set(0, desc->nodes);

    desc->desc_id = h->desc_id;
    desc->type = RPC_RQ_SRV;
    desc->client = h->client;
    desc->rpcid = h->rpcid;
    desc->service = rpc_services[h->rpcid];
    desc->thread = NULL;

    if (__rpc_emergency_send_buf_alloc(desc, 0))
        goto err_emergency_send;

    desc->state = RPC_STATE_NEW;

    rpc_desc_get(desc);

    BUG_ON(h->desc_id != desc->desc_id);
    if (__hashtable_add(desc_srv[h->client], h->desc_id, desc))
        goto err_hashtable;

    out:
    return desc;

    err_hashtable:
    rpc_desc_put(desc);
    __rpc_emergency_send_buf_free(desc);
    err_emergency_send:
    kmem_cache_free(rpc_desc_recv_cachep, desc->desc_recv[0]);
    err_desc_recv:
    kmem_cache_free(rpc_desc_send_cachep, desc->desc_send);
    err_desc_send:
    rpc_desc_put(desc);
    return NULL;
}

static int tipc_handler_ordered(struct sk_buff *buf,
                                unsigned const char* data,
                                unsigned int size)
{
    unsigned char const* iter;
    struct __rpc_header *h;
    struct rpc_desc *desc;
    struct rpc_desc_elem* descelem;
    struct rpc_desc_recv* desc_recv;
    struct hashtable_t* desc_ht;
    int err = 0;

    iter = data;
    h = (struct __rpc_header*)iter;
    iter += sizeof(struct __rpc_header);

    desc_ht = (h->flags & __RPC_HEADER_FLAGS_SRV_REPLY) ? desc_clt : desc_srv[h->client];

    hashtable_lock(desc_ht);
    desc = __hashtable_find(desc_ht, h->desc_id);

    if (desc) {
        BUG_ON(desc->desc_id != h->desc_id);
        rpc_desc_get(desc);

    } else {

        spin_lock(&rpc_desc_done_lock[h->client]);
        if (unlikely(h->desc_id <= rpc_desc_done_id[h->client])) {

            spin_unlock(&rpc_desc_done_lock[h->client]);
            hashtable_unlock(desc_ht);
            goto out;
        }

        rpc_desc_done_id[h->client] = h->desc_id;
        spin_unlock(&rpc_desc_done_lock[h->client]);

        if(h->flags & __RPC_HEADER_FLAGS_SRV_REPLY){
            hashtable_unlock(desc_ht);
            goto out;

        }else{
            desc = server_rpc_desc_setup(h);
            if (!desc) {
                hashtable_unlock(desc_ht);
                err = -ENOMEM;
                goto out;
            }
        }
    }

    BUG_ON(desc->desc_id != h->desc_id);
    switch (desc->type) {
        case RPC_RQ_CLT:
            desc_recv = desc->desc_recv[h->from];
            break;
        case RPC_RQ_SRV:
            desc_recv = desc->desc_recv[0];
            break;
        case RPC_RQ_FWD:
            printk("tipc_handler_ordered: todo\n");
            BUG();
            break;
        default:
            printk("unexpected case %d\n", desc->type);
            BUG();
    }

    if (!(desc->state & RPC_STATE_MASK_VALID) ||
        (desc_recv->flags & RPC_FLAGS_CLOSED)) {
        hashtable_unlock(desc_ht);
        goto out_put;
    }

    hashtable_unlock(desc_ht);

    descelem = kmem_cache_alloc(rpc_desc_elem_cachep, GFP_ATOMIC);
    if (!descelem) {
        err = -ENOMEM;
        goto out_put;
    }

    skb_get(buf);
    descelem->raw = buf;
    descelem->data = (void*) iter;
    descelem->seq_id = h->seq_id;
    descelem->size = size - (iter - data);
    descelem->flags = h->flags;

    spin_lock(&desc->desc_lock);

    if (!(desc->state & RPC_STATE_MASK_VALID) ||
        (desc_recv->flags & RPC_FLAGS_CLOSED)) {
        spin_unlock(&desc->desc_lock);
        rpc_desc_elem_free(descelem);
        goto out_put;
    }

    err = handle_valid_desc(desc, desc_recv, descelem, h, buf);
    if (err)
        rpc_desc_elem_free(descelem);

    out_put:
    rpc_desc_put(desc);
    out:
    return err;
}

static inline int handle_one_packet(hcc_node_t node,
                                    struct sk_buff *buf,
                                    unsigned char const *data,
                                    unsigned int size)
{
    int err;

    err = tipc_handler_ordered(buf, data, size);
    if (!err) {
        if (node == HCC_NODE_ID) // kerrighed_node_id
            rpc_link_send_ack_id[node] = rpc_link_recv_seq_id[node];
        rpc_link_recv_seq_id[node]++;
    }
    return err;
}

static void schedule_run_rx_queue(struct rx_manager *manager)
{
    queue_delayed_work(hcccom_wq, &manager->run_rx_queue_work, HZ / 2);
}

static void run_rx_queue(struct rx_manager *manager)
{
    struct sk_buff_head *queue;
    hcc_node_t node;
    struct sk_buff *buf;
    struct __rpc_header *h;

    node = manager->from;
    queue = &manager->rx_queue;
    while ((buf = skb_peek(queue))) {
        h = (struct __rpc_header *)buf->data;

        BUG_ON(h->link_seq_id < rpc_link_recv_seq_id[node]);
        if (h->link_seq_id > rpc_link_recv_seq_id[node])
            break;

        if (handle_one_packet(node, buf, buf->data, buf->len)) {
            schedule_run_rx_queue(manager);
            break;
        }

        __skb_unlink(buf, queue);
        kfree_skb(buf);
    }
}

static void run_rx_queue_worker(struct work_struct *work)
{
    struct rx_manager *manager =
    container_of(work, struct rx_manager, run_rx_queue_work.work);
    spin_lock_bh(&manager->rx_queue.lock);
    run_rx_queue(manager);
    spin_unlock_bh(&manager->rx_queue.lock);
}

int comlayer_init(void) {

    int res = 0;
    unsigned int i;
    struct task_struct *tmp;
    struct nsproxy *np;
    struct net *net = NULL;
    struct socket *sk = NULL;
    struct tx_manager *manager = NULL;

    printk(KERN_INFO "HCC: comlayer_init");

//    hccnodes_clear(nodes_requiring_ack);

    tmp = get_current();

    task_lock(tmp);
    np = tmp->nsproxy;
    if (np) {
        net = get_net(np->net_ns);
    }
    task_unlock(tmp);

    for_each_possible_cpu(i) {
        printk(KERN_INFO "HCC: tx %d", i);
        manager = &per_cpu(tipc_tx_manager, i);
        INIT_LIST_HEAD(&manager->delayed_tx_queue);
        INIT_DELAYED_WORK(&manager->delayed_tx_work,
                          tipc_delayed_tx_worker);
        INIT_LIST_HEAD(&manager->not_retx_queue);
        INIT_DELAYED_WORK(&manager->cleanup_not_retx_work,
                          tipc_cleanup_not_retx_worker);
        INIT_LIST_HEAD(&manager->retx_queue);
        manager->retx_iter = NULL;
        INIT_DELAYED_WORK(&manager->retx_work, tipc_retx_worker);

        INIT_DELAYED_WORK(&manager->reachable_work, tipc_reachable_node_worker);
        INIT_DELAYED_WORK(&manager->unreachable_work, tipc_unreachable_node_worker);
    }

    hcccom_wq = create_workqueue("hcccom");

    ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE;

    for(i=0; i<HCC_MAX_NODES; i++) {
        printk(KERN_INFO "HCC: rx %d", i);
        tipc_rx_manager[i].from = i;
        skb_queue_head_init(&tipc_rx_manager[i].rx_queue);
        INIT_DELAYED_WORK(&tipc_rx_manager[i].run_rx_queue_work,
                          run_rx_queue_worker);
        last_cleanup_ack[i] = 0;
        consecutive_recv[i] = 0;
        max_consecutive_recv[i] = MAX_CONSECUTIVE_RECV;
    }

//    tipc_net_id = hcc_session_id;

    lockdep_off();

    tipc_net_start(net, tipc_addr(1, 1, HCC_NODE_ID+1)); // tipc_addr(1, 1, kerrighed_node_id+1)

    res = sock_create_kern(net, AF_TIPC, SOCK_SEQPACKET, 0, &sk);
    if (res)
        return res;

    res = tipc_sk_create(net, sk, 0, 1);
    if (res)
        return res;

    tipc_seq.type = TIPC_HCC_SERVER_TYPE;
    tipc_seq.lower = tipc_seq.upper = HCC_NODE_ID; // kerrighed_node_id
    res = __tipc_sk_publish(sk, TIPC_CLUSTER_SCOPE, &tipc_seq);
    if (res)
        return res;

    for_each_possible_cpu(i){
        struct socket *send_ref = &per_cpu(tipc_send_ref, i);

        res = sock_create_kern(net, AF_TIPC, SOCK_SEQPACKET, 0, &send_ref);
        if (res)
            return res;
        res = tipc_sk_create(net, send_ref, 0, 1);
        if (res)
            return res;

//        if(tipc_sk){
//            *send_ref = tipc_sk;
//        } else {
//
//        }
//        struct tipc_port* p;
//        p = tipc_createport_raw((void*)i,
//                                port_dispatcher, port_wakeup,
//                                TIPC_LOW_IMPORTANCE,
//                                (void*)0x1111);
//        if(p){
//            *send_ref = p->ref;
//            spin_unlock_bh(p->lock);
//        } else {
//            spin_unlock_bh(p->lock);
//            goto exit_error;
//        }
    };

    lockdep_on();

    return 0;
}