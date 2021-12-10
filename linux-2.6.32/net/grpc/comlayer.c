/**
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 *
 */

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <linux/irqflags.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/sysrq.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <net/tipc/tipc.h>
#include <net/tipc/tipc_port.h>
#include <net/tipc/tipc_bearer.h>
#include <hcc/ghotplug.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <linux/hcc_hashtable.h>

#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>

#include "grpc_internal.h"

#define TIPC_HCC_SERVER_TYPE (1+TIPC_RESERVED_TYPES)

#define ACK_CLEANUP_WINDOW_SIZE 100
#define MAX_CONSECUTIVE_RECV 1000

#define REJECT_BACKOFF (HZ / 2)

#define ACK_CLEANUP_WINDOW_SIZE__LOWMEM_MODE 20
#define MAX_CONSECUTIVE_RECV__LOWMEM_MODE 20

struct tx_engine {
	struct list_head delayed_tx_queue;
	struct delayed_work delayed_tx_work; /* messages cannot be transmetted immediately */
	struct list_head not_retx_queue; /* messages accepted by TIPC */
	struct delayed_work cleanup_not_retx_work;
	struct list_head retx_queue; /* messages refused by TIPC */
	struct grpc_tx_elem *retx_iter;
	struct delayed_work retx_work;
	struct delayed_work unreachable_work;
	struct delayed_work reachable_work;
};

static DEFINE_PER_CPU(struct tx_engine, tipc_tx_engine);
static DEFINE_SPINLOCK(tipc_tx_queue_lock);
static void tipc_send_ack_worker(struct work_struct *work);
static DECLARE_DELAYED_WORK(tipc_ack_work, tipc_send_ack_worker);

struct rx_engine {
	hcc_node_t from;
	struct sk_buff_head rx_queue;
	struct delayed_work run_rx_queue_work;
};

struct rx_engine tipc_rx_engine[HCC_MAX_NODES];

struct workqueue_struct *hcc_comlayer_wq;

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

s64 grpc_consumed_bytes(void)
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

s64 grpc_consumed_bytes(void)
{
	unsigned long flags;
	s64 ret;

	spin_lock_irqsave(&consumed_bytes_lock, flags);
	ret = consumed_bytes;
	spin_unlock_irqrestore(&consumed_bytes_lock, flags);

	return ret;
}

#endif /* !CONFIG_64BIT */

/*
 * Local definition
 */

u32 tipc_user_ref = 0;
u32 tipc_port_ref;
DEFINE_PER_CPU(u32, tipc_send_ref);
struct tipc_name_seq tipc_seq;

hcc_nodemask_t nodes_requiring_ack;
unsigned long last_cleanup_ack[HCC_MAX_NODES];
static int ack_cleanup_window_size;
static int consecutive_recv[HCC_MAX_NODES];
static int max_consecutive_recv[HCC_MAX_NODES];

void __grpc_put_raw_data(void *data){
	kfree_skb((struct sk_buff*)data);
}

void __grpc_get_raw_data(void *data){
	skb_get((struct sk_buff*)data);
}

static
inline int __send_iovec(hcc_node_t node, int nr_iov, struct iovec *iov)
{
	struct tipc_name name = {
		.type = TIPC_HCC_SERVER_TYPE,
		.instance = node
	};
	struct __grpc_header *h = iov[0].iov_base;
	int err;
	

	h->link_ack_id = grpc_link_recv_seq_id[node] - 1;
	lockdep_off();
	err = tipc_send2name(per_cpu(tipc_send_ref, smp_processor_id()),
			     &name, 0,
			     nr_iov, iov);
	lockdep_on();
	if (!err)
		consecutive_recv[node] = 0;

	return err;
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

static struct grpc_tx_elem *__grpc_tx_elem_alloc(size_t size, int nr_dest)
{
	struct grpc_tx_elem *elem;

	elem = kmem_cache_alloc(grpc_tx_elem_cachep, GFP_ATOMIC);
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
	kmem_cache_free(grpc_tx_elem_cachep, elem);
oom:
	return NULL;
}

static void __grpc_tx_elem_free(struct grpc_tx_elem *elem)
{
	kfree(elem->link_seq_id);
	kfree(elem->data);
	consumed_bytes_sub(elem->iov[1].iov_len);
	kmem_cache_free(grpc_tx_elem_cachep, elem);
}

static int __grpc_tx_elem_send(struct grpc_tx_elem *elem, int link_seq_index,
			      hcc_node_t node)
{
	int err = 0;

	elem->h.link_seq_id = elem->link_seq_id[link_seq_index];
	if (elem->h.link_seq_id <= grpc_link_send_ack_id[node])
		goto out;

	/* try to send */
	err = send_iovec(node, ARRAY_SIZE(elem->iov), elem->iov);

out:
	return err;
}

static
void tipc_send_ack_worker(struct work_struct *work)
{
	struct iovec iov[1];
	struct __grpc_header h;
	hcc_node_t node;
	int err;

	if (next_hcc_node(0, nodes_requiring_ack) > HCC_MAX_NODES)
		return;

	h.from = hcc_node_id;
	h.grpcid = GRPC_ACK;
	h.flags = 0;

	iov[0].iov_base = &h;
	iov[0].iov_len = sizeof(h);

	for_each_hcc_node_mask(node, nodes_requiring_ack) {
		err = send_iovec(node, ARRAY_SIZE(iov), iov);
		if (!err)
			hcc_node_clear(node, nodes_requiring_ack);
	}
}

static void tipc_delayed_tx_worker(struct work_struct *work)
{
	struct tx_engine *engine = container_of(work, struct tx_engine, delayed_tx_work.work);
	LIST_HEAD(queue);
	LIST_HEAD(not_retx_queue);
	struct grpc_tx_elem *iter;
	struct grpc_tx_elem *safe;

	lockdep_off();

	// get the waiting list
	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->delayed_tx_queue, &queue);
	spin_unlock_bh(&tipc_tx_queue_lock);

	if(list_empty(&queue))
		goto exit_empty;

	// browse the waiting list
	list_for_each_entry_safe(iter, safe, &queue, tx_queue){
		hcc_nodemask_t nodes;
		hcc_node_t link_seq_index, node;

		link_seq_index = iter->link_seq_index;
		if (link_seq_index) {
			/* Start with the first node to which we could not
			 * transmit */
			hcc_nodes_setall(nodes);
			hcc_nodes_shift_left(nodes, nodes, iter->index);
			hcc_nodes_and(nodes, nodes, iter->nodes);
		} else {
			/* Transmit to all nodes */
			hcc_nodes_copy(nodes, iter->nodes);
		}
		for_each_hcc_node_mask(node, nodes){
			int err;

			err = __grpc_tx_elem_send(iter, link_seq_index, node);
			if (err < 0) {
				iter->index = node;
				iter->link_seq_index = link_seq_index;

				goto exit;
			}

			link_seq_index++;
		}
		/* Reset the transmission cursor for future retransmissions */
		iter->index = 0;
		iter->link_seq_index = 0;

		/* The message has been transmitted to all receivers. We should not have to
		 * re-transmit it. So move it to not_retx_queue. */
		list_move_tail(&iter->tx_queue, &not_retx_queue);
	}

 exit:
	if (!list_empty(&queue)) {
		// merge the two lists
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&queue, &engine->delayed_tx_queue);
		list_splice(&not_retx_queue, engine->not_retx_queue.prev);
		spin_unlock_bh(&tipc_tx_queue_lock);
	} else {
		if (likely(!list_empty(&not_retx_queue))) {
			spin_lock_bh(&tipc_tx_queue_lock);
			list_splice(&not_retx_queue, engine->not_retx_queue.prev);
			spin_unlock_bh(&tipc_tx_queue_lock);
		}
	}

exit_empty:
	lockdep_on();
}

static void tipc_retx_worker(struct work_struct *work)
{
	struct tx_engine *engine = container_of(work, struct tx_engine, retx_work.work);
	LIST_HEAD(queue);
	LIST_HEAD(not_retx_queue);
	struct grpc_tx_elem *iter;
	struct grpc_tx_elem *safe;

	lockdep_off();

	// get the waiting list
	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->retx_queue, &queue);
	iter = engine->retx_iter;
	engine->retx_iter = NULL;
	spin_unlock_bh(&tipc_tx_queue_lock);

	if(list_empty(&queue))
		goto exit_empty;

	/* list_for_each_entry_safe_continue starts to iterate AFTER
	   the current item. So current item can be anything as long as
	   we are not trying to use it */
	if(!iter) {
		iter = list_entry(&queue,
				  struct grpc_tx_elem,
				  tx_queue);
	} else {
		/* iter points to an entry which failed to fully
		 * retransmit. Start from it. */
		iter = list_entry(iter->tx_queue.prev, struct grpc_tx_elem, tx_queue);
	}

	// browse the waiting list
	list_for_each_entry_safe_continue(iter, safe, &queue, tx_queue){
		hcc_nodemask_t nodes;
		hcc_node_t link_seq_index, node;

		link_seq_index = iter->link_seq_index;
		if (link_seq_index) {
			/* Start with the first node to which we could not
			 * transmit */
			hcc_nodes_setall(nodes);
			hcc_nodes_shift_left(nodes, nodes, iter->index);
			hcc_nodes_and(nodes, nodes, iter->nodes);
		} else {
			/* Transmit to all nodes */
			hcc_nodes_copy(nodes, iter->nodes);
		}
		for_each_hcc_node_mask(node, nodes){
			int err;

			err = __grpc_tx_elem_send(iter, link_seq_index, node);
			if (err < 0) {
				iter->index = node;
				iter->link_seq_index = link_seq_index;

				goto exit;
			}

			link_seq_index++;
		}

		/* Reset the transmission cursor for future retransmissions */
		iter->index = 0;
		iter->link_seq_index = 0;

		list_move_tail(&iter->tx_queue, &not_retx_queue);
	}

	iter = NULL;

 exit:
 	if (!list_empty(&not_retx_queue)){
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&not_retx_queue, &engine->not_retx_queue);
		spin_unlock_bh(&tipc_tx_queue_lock);
	}

	if (!list_empty(&queue)) {
		// merge the two lists
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&queue, &engine->retx_queue);
		/* A concurrent run of the worker might already have set a
		 * restart point later in the queue. Do not overwrite it unless
		 * we set an earlier restart point. */
		if (iter)
			engine->retx_iter = iter;
		spin_unlock_bh(&tipc_tx_queue_lock);
	}

exit_empty:
	lockdep_on();
}

static void tipc_cleanup_not_retx_worker(struct work_struct *work)
{
	struct tx_engine *engine = container_of(work, struct tx_engine, cleanup_not_retx_work.work);
	struct grpc_tx_elem *iter;
	struct grpc_tx_elem *safe;
	LIST_HEAD(queue);
	int node;

	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->not_retx_queue, &queue);
	spin_unlock_bh(&tipc_tx_queue_lock);

	list_for_each_entry_safe(iter, safe, &queue, tx_queue){
		int need_to_free, link_seq_index;

		need_to_free = 0;
		link_seq_index = 0;

		for_each_hcc_node_mask(node, iter->nodes){

			iter->h.link_seq_id = iter->link_seq_id[link_seq_index];

			if (iter->h.link_seq_id >
			    grpc_link_send_ack_id[node])
				goto next_iter;

			link_seq_index++;
		}
		need_to_free = 1;

	next_iter:
		if(need_to_free){
			list_del(&iter->tx_queue);
			__grpc_tx_elem_free(iter);
		}
	}

	if (!list_empty(&queue)) {
		// merge the two lists
		spin_lock_bh(&tipc_tx_queue_lock);
		list_splice(&queue, &engine->not_retx_queue);
		spin_unlock_bh(&tipc_tx_queue_lock);
	}

}

static
void tipc_unreachable_node_worker(struct work_struct *work){
}

static
void tipc_reachable_node_worker(struct work_struct *work){
	struct tx_engine *engine = container_of(work, struct tx_engine, reachable_work.work);

	spin_lock_bh(&tipc_tx_queue_lock);
	list_splice_init(&engine->not_retx_queue, &engine->retx_queue);
	spin_unlock_bh(&tipc_tx_queue_lock);

	queue_delayed_work_on(smp_processor_id(), hcc_comlayer_wq,
			      &engine->retx_work, 0);
}

#define MAX_EMERGENCY_SEND 2

int __grpc_emergency_send_buf_alloc(struct grpc_desc *desc, size_t size)
{
	struct grpc_tx_elem **elem;
	int nr_dest;
	int err = 0;
	int i;

	elem = kmalloc(sizeof(*elem) * MAX_EMERGENCY_SEND, GFP_ATOMIC);
	if (!elem)
		goto oom;
	nr_dest = hcc_nodes_weight(desc->nodes);
	for (i = 0; i < MAX_EMERGENCY_SEND; i++) {
		elem[i] = __grpc_tx_elem_alloc(size, nr_dest);
		if (!elem[i])
			goto oom_free_elems;
	}
	desc->desc_send->emergency_send_buf = elem;

out:
	return err;

oom_free_elems:
	for (i--; i >= 0; i--)
		__grpc_tx_elem_free(elem[i]);
	kfree(elem);
oom:
	err = -ENOMEM;
	goto out;
}

void __grpc_emergency_send_buf_free(struct grpc_desc *desc)
{
	struct grpc_tx_elem **elem = desc->desc_send->emergency_send_buf;
	int i;

	/* does not buy a lot, but still can help debug */
	desc->desc_send->emergency_send_buf = NULL;
	for (i = 0; i < MAX_EMERGENCY_SEND; i++)
		if (elem[i])
			/* emergency send buf was not used */
			__grpc_tx_elem_free(elem[i]);
	kfree(elem);
}

static struct grpc_tx_elem *next_emergency_send_buf(struct grpc_desc *desc)
{
	struct grpc_tx_elem **elems = desc->desc_send->emergency_send_buf;
	struct grpc_tx_elem *buf = NULL;
	int i;

	for (i = 0; i < MAX_EMERGENCY_SEND; i++)
		if (elems[i]) {
			buf = elems[i];
			elems[i] = NULL;
			break;
		}
	return buf;
}

int __grpc_send_ll(struct grpc_desc* desc,
			 hcc_nodemask_t *nodes,
			 unsigned long seq_id,
			 int __flags,
			 const void* data, size_t size,
			 int grpc_flags)
{
	struct grpc_tx_elem* elem;
	struct tx_engine *engine;
	hcc_node_t node;
	int link_seq_index;

	elem = __grpc_tx_elem_alloc(size, __hcc_nodes_weight(nodes));
	if (!elem) {
		if (grpc_flags & GRPC_FLAGS_EMERGENCY_BUF)
			elem = next_emergency_send_buf(desc);
		if (!elem)
			return -ENOMEM;
	}

	link_seq_index = 0;
	__for_each_hcc_node_mask(node, nodes) {
		grpc_link_seq_id(elem->link_seq_id[link_seq_index], node);
		link_seq_index++;
	}
	if (grpc_flags & GRPC_FLAGS_NEW_DESC_ID)
		grpc_new_desc_id_unlock();

	elem->h.from = hcc_node_id;
	elem->h.client = desc->client;
	elem->h.desc_id = desc->desc_id;
	elem->h.seq_id = seq_id;
	
	elem->h.flags = __flags;
	if(desc->type == GRPC_RQ_SRV)
		elem->h.flags |= __GRPC_HEADER_FLAGS_SRV_REPLY;

	elem->h.grpcid = desc->grpcid;

	elem->iov[0].iov_base = &elem->h;
	elem->iov[0].iov_len = sizeof(elem->h);
	
	elem->iov[1].iov_base = (void *) data;
	elem->iov[1].iov_len = size;

	elem->index = 0;
	elem->link_seq_index = 0;

	memcpy(elem->data, data, size);
	elem->iov[1].iov_base = elem->data;
		
	__hcc_nodes_copy(&elem->nodes, nodes);	

	preempt_disable();
	engine = &per_cpu(tipc_tx_engine, smp_processor_id());
	if (irqs_disabled()) {
		/* Add the packet in the tx_queue */
		lockdep_off();
		spin_lock(&tipc_tx_queue_lock);
		list_add_tail(&elem->tx_queue, &engine->delayed_tx_queue);
		spin_unlock(&tipc_tx_queue_lock);
		lockdep_on();

		/* Schedule the work ASAP */
		queue_work(hcc_comlayer_wq, &engine->delayed_tx_work.work);

	} else {
		int err = 0;

		link_seq_index = 0;
		__for_each_hcc_node_mask(node, nodes){

			err = __grpc_tx_elem_send(elem, link_seq_index, node);

			if(err<0){
				spin_lock_bh(&tipc_tx_queue_lock);
				list_add_tail(&elem->tx_queue,
						&engine->retx_queue);
				spin_unlock_bh(&tipc_tx_queue_lock);
				break;
			}

			link_seq_index++;
		}

		if(err>=0){
			/* Add the packet in the not_retx_queue */
			spin_lock_bh(&tipc_tx_queue_lock);
			list_add_tail(&elem->tx_queue, &engine->not_retx_queue);
			spin_unlock_bh(&tipc_tx_queue_lock);
		}
	}
	preempt_enable();
	return 0;
}

inline
void insert_in_seqid_order(struct grpc_desc_elem* desc_elem,
			   struct grpc_desc_recv* desc_recv)
{
	struct grpc_desc_elem *iter;
	struct list_head *at;

	if (unlikely(desc_elem->flags & __GRPC_HEADER_FLAGS_SIGNAL)) {
		/* For a given seq_id, queue all received sigacks
		 * before all signals, and try to preserve signals order
		 */
		int sigack = (desc_elem->flags & __GRPC_HEADER_FLAGS_SIGACK);

		at = &desc_recv->list_signal_head;
		list_for_each_entry_reverse(iter, &desc_recv->list_signal_head,
					    list_desc_elem)
			if (iter->seq_id < desc_elem->seq_id
			    || (iter->seq_id == desc_elem->seq_id && !sigack)) {
				at = &iter->list_desc_elem;
				break;
			}
	} else {
		/* Data element
		 * There can be only one single element per seq_id
		 */
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

/*
 * do_action
 * Process the received descriptor
 *
 * desc->desc_lock must be hold
 */
static
inline
int do_action(struct grpc_desc *desc, struct __grpc_header *h)
{
	switch (desc->state) {
	case GRPC_STATE_NEW:
		spin_unlock(&desc->desc_lock);
		return grpc_handle_new(desc);
	case GRPC_STATE_WAIT1:
		if (desc->type == GRPC_RQ_CLT
		    && desc->wait_from != h->from) {
			spin_unlock(&desc->desc_lock);
			break;
		}
	case GRPC_STATE_WAIT:
		desc->state = GRPC_STATE_RUN;
		wake_up_process(desc->thread);
		spin_unlock(&desc->desc_lock);
		break;
	default:
		spin_unlock(&desc->desc_lock);			
		break;
	}
	return 0;
}

void grpc_desc_elem_free(struct grpc_desc_elem *elem)
{
	kfree_skb(elem->raw);
	kmem_cache_free(grpc_desc_elem_cachep, elem);
}

void grpc_do_signal(struct grpc_desc *desc,
		   struct grpc_desc_elem *signal_elem)
{
	if (desc->thread)
		send_sig(*(int*)signal_elem->data, desc->thread, 0);

	__grpc_signalack(desc);

	grpc_desc_elem_free(signal_elem);
}

/*
 * handle_valid_desc
 * We found the right descriptor, is-there a waiting buffer ?
 */
inline
int handle_valid_desc(struct grpc_desc *desc,
		      struct grpc_desc_recv *desc_recv,
		      struct grpc_desc_elem* descelem,
		      struct __grpc_header *h,
		      struct sk_buff *buf){
	int err;

	// Update the received_packets map
	if(descelem->seq_id<sizeof(desc_recv->received_packets)*8)
		set_bit(descelem->seq_id-1, &desc_recv->received_packets);

	// is there a waiting buffer ?
	if (desc_recv->iter_provided) {

		// there are some waiting buffer. is-there one for us ?
		if (unlikely(h->flags & __GRPC_HEADER_FLAGS_SIGNAL)
		    && (!(h->flags & __GRPC_HEADER_FLAGS_SIGACK))) {
			struct grpc_desc_elem *provided;

			provided = list_entry(desc_recv->list_provided_head.prev,
					      struct grpc_desc_elem, list_desc_elem);
			
			if (descelem->seq_id <= provided->seq_id) {

				grpc_do_signal(desc, descelem);

				spin_unlock(&desc->desc_lock);
				return 0;
				
			} else {
				insert_in_seqid_order(descelem, desc_recv);
			}

		} else {
			
			if (desc_recv->iter_provided->seq_id == descelem->seq_id) {
				//printk("%d tipc_handler_ordered: found a waiting buffer (%lu)\n",
				//       current->pid, descelem->seq_id);
			} else {
				insert_in_seqid_order(descelem, desc_recv);
			}
		}
		
		goto do_action;
		
	}
	
	// unexpected message
	if (unlikely(h->flags & __GRPC_HEADER_FLAGS_SIGNAL)
	    && (!(h->flags & __GRPC_HEADER_FLAGS_SIGACK))
	    && (h->seq_id <= atomic_read(&desc_recv->seq_id))
	    && ((desc->service->flags & GRPC_FLAGS_NOBLOCK) || desc->thread)) {

		grpc_do_signal(desc, descelem);

		spin_unlock(&desc->desc_lock);
		return 0;
	}
	
	insert_in_seqid_order(descelem, desc_recv);
	atomic_inc(&desc_recv->nbunexpected);
	
 do_action:
	err = do_action(desc, h);
	if (err) {
		/*
		 * Keeping this packet at this layer would need to reschedule
		 * its handling, which lower layers already do without needing
		 * more metadata. So dropping that packet at this layer is
		 * simpler and safe.
		 */
		spin_lock(&desc->desc_lock);
		/*
		 * We expect that only the first packet of a new transaction may
		 * fail to be handled by do_action(). Otherwise the packet might
		 * have been unpacked by the handler, or the handler may have
		 * played with nbunexpected.
		 */
		BUG_ON(desc->state != GRPC_STATE_NEW || descelem->seq_id > 1);
		atomic_dec(&desc_recv->nbunexpected);
		list_del(&descelem->list_desc_elem);
		spin_unlock(&desc->desc_lock);
	}
	return err;
}

static struct grpc_desc *server_grpc_desc_setup(const struct __grpc_header *h)
{
	struct grpc_desc *desc;

	desc = grpc_desc_alloc();
	if (!desc)
		goto out;

	desc->desc_send = grpc_desc_send_alloc();
	if (!desc->desc_send)
		goto err_desc_send;

	desc->desc_recv[0] = grpc_desc_recv_alloc();
	if (!desc->desc_recv[0])
		goto err_desc_recv;

	// Since a GRPC_RQ_CLT can only be received from one node:
	// by choice, we decide to use 0 as the corresponding id
	hcc_node_set(0, desc->nodes);

	desc->desc_id = h->desc_id;
	desc->type = GRPC_RQ_SRV;
	desc->client = h->client;
	desc->grpcid = h->grpcid;
	desc->service = grpc_services[h->grpcid];
	desc->thread = NULL;

	if (__grpc_emergency_send_buf_alloc(desc, 0))
		goto err_emergency_send;

	desc->state = GRPC_STATE_NEW;

	grpc_desc_get(desc);

	BUG_ON(h->desc_id != desc->desc_id);
	if (__hashtable_add(desc_srv[h->client], h->desc_id, desc))
		goto err_hashtable;

out:
	return desc;

err_hashtable:
	grpc_desc_put(desc);
	__grpc_emergency_send_buf_free(desc);
err_emergency_send:
	kmem_cache_free(grpc_desc_recv_cachep, desc->desc_recv[0]);
err_desc_recv:
	kmem_cache_free(grpc_desc_send_cachep, desc->desc_send);
err_desc_send:
	grpc_desc_put(desc);
	return NULL;
}

/*
 * tipc_handler_ordered
 * Packets are in the right order, so we have to find the corresponding
 * descriptor (if any).
 */
static int tipc_handler_ordered(struct sk_buff *buf,
				unsigned const char* data,
				unsigned int size)
{
	unsigned char const* iter;
	struct __grpc_header *h;
	struct grpc_desc *desc;
	struct grpc_desc_elem* descelem;
	struct grpc_desc_recv* desc_recv;
	struct hashtable_t* desc_ht;
	int err = 0;

	iter = data;
	h = (struct __grpc_header*)iter;
	iter += sizeof(struct __grpc_header);

	/* select the right array regarding the type of request:
	   __GRPC_HEADER_FLAGS_SRV_REPLY: we are the client side -> desc_clt
	   else: we are the server side -> desc_srv[]
	*/
	desc_ht = (h->flags & __GRPC_HEADER_FLAGS_SRV_REPLY) ? desc_clt : desc_srv[h->client];

	hashtable_lock(desc_ht);
	desc = __hashtable_find(desc_ht, h->desc_id);

	if (desc) {
		BUG_ON(desc->desc_id != h->desc_id);
		grpc_desc_get(desc);

	} else {
		
		spin_lock(&grpc_desc_done_lock[h->client]);
		if (unlikely(h->desc_id <= grpc_desc_done_id[h->client])) {
			
			spin_unlock(&grpc_desc_done_lock[h->client]);
			hashtable_unlock(desc_ht);
			goto out;

		}

		grpc_desc_done_id[h->client] = h->desc_id;
		spin_unlock(&grpc_desc_done_lock[h->client]);

		if(h->flags & __GRPC_HEADER_FLAGS_SRV_REPLY){

			// requesting desc is already closed (most probably an async request
			// just discard this packet
			hashtable_unlock(desc_ht);
			goto out;

		}else{

			desc = server_grpc_desc_setup(h);
			if (!desc) {
				/*
				 * Drop the packet, but not silently.
				 * tipc_handler() may decide to drop more pending
				 * packets to decrease memory pressure, or keep
				 * the packet and retry handling it later.
				 */
				hashtable_unlock(desc_ht);
				err = -ENOMEM;
				goto out;
			}

		}

	}

	BUG_ON(desc->desc_id != h->desc_id);

	/* Optimization: do not allocate memory if we already know that it is
	 * useless to.
	 * If desc is valid after double check, desc_recv retrieved below will
	 * be valid too, since hashtable's lock acts as a memory barrier between
	 * the processor having allocated desc (and inserted it in the table)
	 * and us.
	 * If desc has a valid state here, as long as we do not release
	 * hashtable's lock desc_recv retrieved below is valid too (see
	 * grpc_end()).
	 */
	switch (desc->type) {
	case GRPC_RQ_CLT:
		// we are in the client side (just received a msg from server)
		desc_recv = desc->desc_recv[h->from];
		break;

	case GRPC_RQ_SRV:
		// we are in the server side (just received a msg from client)
		desc_recv = desc->desc_recv[0];
		break;

	case GRPC_RQ_FWD:
		printk("tipc_handler_ordered: todo\n");
		BUG();
		break;

	default:
		printk("unexpected case %d\n", desc->type);
		BUG();
	}
	/* Is the transaction still accepting packets? */
	if (!(desc->state & GRPC_STATE_MASK_VALID) ||
	    (desc_recv->flags & GRPC_FLAGS_CLOSED)) {
		hashtable_unlock(desc_ht);
		goto out_put;
	}

	hashtable_unlock(desc_ht);

	descelem = kmem_cache_alloc(grpc_desc_elem_cachep, GFP_ATOMIC);
	if (!descelem) {
		/*
		 * Same OOM handling as for new grpc_desc above, except that we
		 * keep the grpc_desc, even if we just created it, because it is
		 * now visible in the hashtable and it would just add
		 * complexity to try to free it.
		 */
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

	/* Double-check withe desc->desc_lock held */
	if (!(desc->state & GRPC_STATE_MASK_VALID) ||
	    (desc_recv->flags & GRPC_FLAGS_CLOSED)) {
		// This side is closed. Discard the packet
		spin_unlock(&desc->desc_lock);
		grpc_desc_elem_free(descelem);
		goto out_put;
	}

	/* Releases desc->desc_lock */
	err = handle_valid_desc(desc, desc_recv, descelem, h, buf);
	if (err)
		/* Same OOM handling as above */
		grpc_desc_elem_free(descelem);

out_put:
	grpc_desc_put(desc);
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
		if (node == hcc_node_id)
			grpc_link_send_ack_id[node] = grpc_link_recv_seq_id[node];
		grpc_link_recv_seq_id[node]++;
	}
	return err;
}

static void schedule_run_rx_queue(struct rx_engine *engine);

static void run_rx_queue(struct rx_engine *engine)
{
	struct sk_buff_head *queue;
	hcc_node_t node;
	struct sk_buff *buf;
	struct __grpc_header *h;

	node = engine->from;
	queue = &engine->rx_queue;
	while ((buf = skb_peek(queue))) {
		h = (struct __grpc_header *)buf->data;

		BUG_ON(h->link_seq_id < grpc_link_recv_seq_id[node]);
		if (h->link_seq_id > grpc_link_recv_seq_id[node])
			break;

		if (handle_one_packet(node, buf, buf->data, buf->len)) {
			schedule_run_rx_queue(engine);
			break;
		}

		__skb_unlink(buf, queue);
		kfree_skb(buf);
	}
}

static void run_rx_queue_worker(struct work_struct *work)
{
	struct rx_engine *engine =
		container_of(work, struct rx_engine, run_rx_queue_work.work);
	spin_lock_bh(&engine->rx_queue.lock);
	run_rx_queue(engine);
	spin_unlock_bh(&engine->rx_queue.lock);
}

static void schedule_run_rx_queue(struct rx_engine *engine)
{
	queue_delayed_work(hcc_comlayer_wq, &engine->run_rx_queue_work, HZ / 2);
}

/*
 * tipc_handler
 * receives packets from TIPC and orders them
 */
static void tipc_handler(void *usr_handle,
			 u32 port_ref,
			 struct sk_buff **buf,
			 unsigned char const *data,
			 unsigned int size,
			 unsigned int importance,
			 struct tipc_portid const *orig,
			 struct tipc_name_seq const *dest)
{
	struct sk_buff_head *queue;
	struct sk_buff *__buf;
	struct __grpc_header *h;

	__buf = *buf;
	h = (struct __grpc_header*)data;
	BUG_ON(size != __buf->len);

	queue = &tipc_rx_engine[h->from].rx_queue;
	spin_lock(&queue->lock);

	// Update the ack value sent by the other node
	if (h->link_ack_id > grpc_link_send_ack_id[h->from]){
		grpc_link_send_ack_id[h->from] = h->link_ack_id;
		if(grpc_link_send_ack_id[h->from] - last_cleanup_ack[h->from]
			> ack_cleanup_window_size){
			int cpuid;
			last_cleanup_ack[h->from] = h->link_ack_id;
			for_each_online_cpu(cpuid){
				struct tx_engine *engine = &per_cpu(tipc_tx_engine,
									cpuid);
				queue_delayed_work_on(cpuid, hcc_comlayer_wq,
							&engine->cleanup_not_retx_work,0);

			}
		}

	}

	if (h->grpcid == GRPC_ACK)
		goto exit;

	// Check if we are not receiving an already received packet
	if (h->link_seq_id < grpc_link_recv_seq_id[h->from]) {
		hcc_node_set(h->from, nodes_requiring_ack);
		queue_delayed_work(hcc_comlayer_wq, &tipc_ack_work, 0);
		goto exit;
	}

	// Check if we are receiving lot of packets but sending none
	if (consecutive_recv[h->from] >= max_consecutive_recv[h->from]){
		hcc_node_set(h->from, nodes_requiring_ack);
		queue_delayed_work(hcc_comlayer_wq, &tipc_ack_work, 0);
	}
	consecutive_recv[h->from]++;

	// Is-it the next ordered message ?
	if (h->link_seq_id > grpc_link_recv_seq_id[h->from]) {
		struct sk_buff *at;
		unsigned long seq_id = h->link_seq_id;

		/*
		 * Insert in the ordered list.
		 * Optimized for in-order reception.
		 */
		skb_queue_reverse_walk(queue, at) {
			struct __grpc_header *ath;

			ath = (struct __grpc_header *)at->data;
			if (ath->link_seq_id < seq_id)
				break;
			else if (ath->link_seq_id == seq_id)
				/* Duplicate */
				goto exit;
		}
		skb_get(__buf);
		__skb_queue_after(queue, at, __buf);
		goto exit;
	}

	if (handle_one_packet(h->from, __buf, data, size)) {
		skb_get(__buf);
		__skb_queue_head(queue, __buf);
		schedule_run_rx_queue(&tipc_rx_engine[h->from]);
	} else {
		run_rx_queue(&tipc_rx_engine[h->from]);
	}

 exit:
	spin_unlock(&queue->lock);
}

static
u32 port_dispatcher(struct tipc_port *p_ptr, struct sk_buff *buf)
{
	struct tipc_msg *msg = (struct tipc_msg *)buf->data;
	long cpuid = (long)p_ptr->usr_handle;
	struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);

	/*
	 * We might have sent something while TIPC is still setting up the
	 * connection to the peer. Retransmit after a small delay, unless the peer
	 * disconnects, in which case port_wakeup() will retransmit when
	 * possible.
	 */
	if (msg_errcode(msg) == TIPC_ERR_NO_NAME
	    && hcc_node_present(msg_nameinst(msg))) {
		queue_delayed_work(hcc_comlayer_wq, &tipc_ack_work, REJECT_BACKOFF);
		queue_delayed_work_on(cpuid, hcc_comlayer_wq,
				      &engine->reachable_work, REJECT_BACKOFF);
	}

	kfree_skb(buf);
	return TIPC_OK;
}

static
void port_wakeup(struct tipc_port *p_ptr){
	long cpuid = (long)p_ptr->usr_handle;
	struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);

	/*
	 * Schedule the work ASAP
	 * To help the other side freeing memory, we try to favor acks and delay
	 * retx by 1 jiffy.
	 */

	queue_delayed_work(hcc_comlayer_wq, &tipc_ack_work, 0);

	queue_delayed_work_on(cpuid, hcc_comlayer_wq, &engine->retx_work, 1);
	queue_delayed_work_on(cpuid, hcc_comlayer_wq, &engine->delayed_tx_work, 1);
}

int comlayer_enable_dev(const char *name)
{
	char buf[256];
	int res;

	printk("Try to enable bearer on %s:", name);

	snprintf(buf, sizeof(buf), "eth:%s", name);

    tipc_net_id = hcc_session_id;
	res = tipc_enable_bearer(buf, tipc_addr(tipc_net_id, 1, 0), TIPC_MEDIA_LINK_PRI);
	if (res)
		printk("failed\n");
	else
		printk("ok\n");

	return res;
}

void comlayer_enable(void)
{
	struct net_device *netdev;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, netdev)
		comlayer_enable_dev(netdev->name);
	read_unlock(&dev_base_lock);
}

int comlayer_disable_dev(const char *name)
{
	int res;

	printk("Try to disable bearer on %s:", name);

	res = tipc_disable_bearer(name);
	if (res)
		printk("failed\n");
	else
		printk("ok\n");

	return res;
}

void comlayer_disable(void)
{
	struct net_device *netdev;

	read_lock(&dev_base_lock);
	for_each_netdev(&init_net, netdev)
		comlayer_disable_dev(netdev->name);
	read_unlock(&dev_base_lock);
}

void hcc_node_reachable(hcc_node_t nodeid){
	int cpuid;

	queue_delayed_work(hcc_comlayer_wq, &tipc_ack_work, 0);
	for_each_online_cpu(cpuid){
		struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);

		queue_delayed_work_on(cpuid, hcc_comlayer_wq,
				      &engine->reachable_work, 0);
	}
}

void hcc_node_unreachable(hcc_node_t nodeid){
}

void grpc_enable_lowmem_mode(hcc_node_t nodeid){
	max_consecutive_recv[nodeid] = MAX_CONSECUTIVE_RECV__LOWMEM_MODE;

	hcc_node_set(nodeid, nodes_requiring_ack);
	queue_delayed_work(hcc_comlayer_wq, &tipc_ack_work, 0);
}

void grpc_disable_lowmem_mode(hcc_node_t nodeid){
	max_consecutive_recv[nodeid] = MAX_CONSECUTIVE_RECV;
}

void grpc_enable_local_lowmem_mode(void){
	int cpuid;

	ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE__LOWMEM_MODE;

	for_each_online_cpu(cpuid){
		struct tx_engine *engine = &per_cpu(tipc_tx_engine, cpuid);
		queue_delayed_work_on(cpuid, hcc_comlayer_wq,
			&engine->cleanup_not_retx_work, 0);
	}
}

void grpc_disable_local_lowmem_mode(void){
	ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE;
}

int comlayer_init(void)
{
	int res = 0;
	long i;

	hcc_nodes_clear(nodes_requiring_ack);	

	for_each_possible_cpu(i) {
		struct tx_engine *engine = &per_cpu(tipc_tx_engine, i);
		INIT_LIST_HEAD(&engine->delayed_tx_queue);
		INIT_DELAYED_WORK(&engine->delayed_tx_work,
					tipc_delayed_tx_worker);
		INIT_LIST_HEAD(&engine->not_retx_queue);
		INIT_DELAYED_WORK(&engine->cleanup_not_retx_work,
					tipc_cleanup_not_retx_worker);
		INIT_LIST_HEAD(&engine->retx_queue);
		engine->retx_iter = NULL;
		INIT_DELAYED_WORK(&engine->retx_work, tipc_retx_worker);

		INIT_DELAYED_WORK(&engine->reachable_work, tipc_reachable_node_worker);
		INIT_DELAYED_WORK(&engine->unreachable_work, tipc_unreachable_node_worker);
	}

	hcc_comlayer_wq = create_workqueue("hcc_comlayer");

	ack_cleanup_window_size = ACK_CLEANUP_WINDOW_SIZE;

	for (i = 0; i < HCC_MAX_NODES; i++) {
		tipc_rx_engine[i].from = i;
		skb_queue_head_init(&tipc_rx_engine[i].rx_queue);
		INIT_DELAYED_WORK(&tipc_rx_engine[i].run_rx_queue_work,
				  run_rx_queue_worker);
		last_cleanup_ack[i] = 0;
		consecutive_recv[i] = 0;
		max_consecutive_recv[i] = MAX_CONSECUTIVE_RECV;
	}

	tipc_net_id = hcc_session_id;

	lockdep_off();

	tipc_core_start_net(tipc_addr(tipc_net_id, 1, hcc_node_id+1));

	res = tipc_attach(&tipc_user_ref, NULL, NULL);
	if (res)
		goto exit_error;

	res = tipc_createport(tipc_user_ref, NULL, TIPC_LOW_IMPORTANCE,
			      NULL, NULL, NULL,
			      NULL, tipc_handler, NULL,
			      NULL, &tipc_port_ref);
	if (res)
		return res;

        tipc_seq.type = TIPC_HCC_SERVER_TYPE;
        tipc_seq.lower = tipc_seq.upper = hcc_node_id;
        res = tipc_publish(tipc_port_ref, TIPC_CLUSTER_SCOPE, &tipc_seq);

	for_each_possible_cpu(i){
		u32* send_ref = &per_cpu(tipc_send_ref, i);
		struct tipc_port* p;

		/* since TIPC do strange assumption regarding this field
		   we need to initialise it. But this field is dedicated
		   to the plugins of TIPC. ie: only our code use this field. So
		   we can set it to any value we want.
		*/
		p = tipc_createport_raw((void*)i,
					port_dispatcher, port_wakeup,
					TIPC_LOW_IMPORTANCE,
					(void*)0x1111);
		if(p){
			*send_ref = p->ref;
			spin_unlock_bh(p->lock);
		} else {
			spin_unlock_bh(p->lock);
			goto exit_error;
		}
	};

	lockdep_on();

	return 0;
	
 exit_error:
	printk("Error while trying to init TIPC (%d)\n", res);
        return res;
}
