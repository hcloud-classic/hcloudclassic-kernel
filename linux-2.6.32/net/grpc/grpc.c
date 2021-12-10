/**
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/irqflags.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/string.h>
#include <hcc/hcc_nodemask.h>
#include <linux/hcc_hashtable.h>

#include <net/grpc/grpcid.h>
#include <net/grpc/grpc.h>

#include "grpc_internal.h"

struct grpc_service** grpc_services;
unsigned long grpc_desc_id;
hashtable_t* desc_srv[HCC_MAX_NODES];
hashtable_t* desc_clt;
spinlock_t grpc_desc_done_lock[HCC_MAX_NODES];
unsigned long grpc_desc_done_id[HCC_MAX_NODES];

unsigned long grpc_link_send_seq_id[HCC_MAX_NODES];
unsigned long grpc_link_send_ack_id[HCC_MAX_NODES];
unsigned long grpc_link_recv_seq_id[HCC_MAX_NODES];

DEFINE_PER_CPU(struct list_head, grpc_desc_trash);

struct kmem_cache* grpc_desc_cachep;
struct kmem_cache* grpc_desc_send_cachep;
struct kmem_cache* grpc_desc_recv_cachep;
struct kmem_cache* grpc_desc_elem_cachep;
struct kmem_cache* grpc_tx_elem_cachep;
struct kmem_cache* __grpc_synchro_cachep;

static struct lock_class_key grpc_desc_srv_lock_key;
static struct lock_class_key grpc_desc_clt_lock_key;

unsigned long grpc_mask[GRPCID_MAX/(sizeof(unsigned long)*8)+1];

/*
 * GRPC management
 */
inline
struct grpc_service* grpc_service_init(enum grpcid grpcid,
				     enum grpc_target grpc_target,
				     enum grpc_handler grpc_handler,
				     struct grpc_synchro *grpc_synchro,
				     grpc_handler_t h,
				     unsigned long flags){
	struct grpc_service* service;

	service = kmalloc(sizeof(*service), GFP_KERNEL);
	if(!service){
		printk("OOM in grpc_service_init\n");
		return NULL;
	};
	
	service->id = grpcid;
	service->target = grpc_target;
	service->handler = grpc_handler;
	service->h = h;
	service->synchro = grpc_synchro;
	service->flags = flags;

	return service;
};

int __grpc_register(enum grpcid grpcid,
		   enum grpc_target grpc_target,
		   enum grpc_handler grpc_handler,
		   struct grpc_synchro *grpc_synchro,
		   void* _h, unsigned long flags){
	grpc_handler_t h = (grpc_handler_t)_h;
	grpc_services[grpcid] = grpc_service_init(grpcid, grpc_target, grpc_handler,
					       grpc_synchro, h, flags);

	grpc_disable(grpcid);
	return 0;
};

struct grpc_desc* grpc_desc_alloc(void){
	struct grpc_desc* desc;
	int in_interrupt;
	int cpu = smp_processor_id();
	
	in_interrupt = 0;
	if(list_empty(&per_cpu(grpc_desc_trash, cpu))){
		desc = kmem_cache_alloc(grpc_desc_cachep, GFP_ATOMIC);
		if(!desc)
			return NULL;
		
		in_interrupt = 1;
	}else{
		desc = container_of(per_cpu(grpc_desc_trash, cpu).next,
				    struct grpc_desc,
				    list);
		list_del(&desc->list);
	};

	memset(desc, 0, sizeof(*desc));
	spin_lock_init(&desc->desc_lock);
	desc->in_interrupt = in_interrupt;
	atomic_set(&desc->usage, 1);
	desc->__synchro = NULL;

	return desc;
};

void grpc_desc_get(struct grpc_desc* desc){
	BUG_ON(atomic_read(&desc->usage)==0);
	atomic_inc(&desc->usage);
};

void grpc_desc_put(struct grpc_desc* desc){
	BUG_ON(atomic_read(&desc->usage)==0);
	if(!atomic_dec_and_test(&desc->usage))
		return;
	
	kmem_cache_free(grpc_desc_cachep, desc);
};

struct grpc_desc_send* grpc_desc_send_alloc(void){
	struct grpc_desc_send* desc_send;

	desc_send = kmem_cache_alloc(grpc_desc_send_cachep, GFP_ATOMIC);
	if(!desc_send)
		return NULL;

	atomic_set(&desc_send->seq_id, 0);
	spin_lock_init(&desc_send->lock);
	INIT_LIST_HEAD(&desc_send->list_desc_head);
	desc_send->flags = 0;

	return desc_send;
};

struct grpc_desc_recv* grpc_desc_recv_alloc(void){
	struct grpc_desc_recv* desc_recv;

	desc_recv = kmem_cache_alloc(grpc_desc_recv_cachep, GFP_ATOMIC);
	if(!desc_recv)
		return NULL;

	atomic_set(&desc_recv->seq_id, 0);
	atomic_set(&desc_recv->nbunexpected, 0);
	INIT_LIST_HEAD(&desc_recv->list_desc_head);
	INIT_LIST_HEAD(&desc_recv->list_provided_head);
	INIT_LIST_HEAD(&desc_recv->list_signal_head);
	desc_recv->iter = NULL;
	desc_recv->iter_provided = NULL;
	desc_recv->received_packets = 0;
	desc_recv->flags = 0;
	
	return desc_recv;
};


void test(void){
}

/*
 *
 * Enable a registered GRPC
 * We must take the waiting_desc_lock.
 * After each grpc handle, the grpc go through the waiting_desc
 * list, in order to find another desc to process. We must avoid
 * to enable an GRPC when such iteration is happened
 *
 */
void grpc_enable(enum grpcid grpcid){
	spin_lock_bh(&waiting_desc_lock);
	if(grpc_services[grpcid]->id == grpcid)
		clear_bit(grpcid, grpc_mask);

	spin_unlock_bh(&waiting_desc_lock);
};

void grpc_enable_all(void){
	int i;

	for(i=0;i<GRPCID_MAX;i++)
		grpc_enable(i);
	
	if(!list_empty(&waiting_desc))
		grpc_wake_up_thread(NULL);
};

void grpc_disable(enum grpcid grpcid){
	if(grpc_services[grpcid]->id == grpcid)
		set_bit(grpcid, grpc_mask);
};


/** Initialisation of the grpc module.
 *  @author Innogrid HCC
 */

void grpc_undef_handler (struct grpc_desc *desc){
	printk("service %d not registered\n", desc->grpcid);
};

void grpc_enable_alldev(void)
{
	comlayer_enable();
}

int grpc_enable_dev(const char *name)
{
	return comlayer_enable_dev(name);
}

void grpc_disable_alldev(void)
{
	comlayer_disable();
}

int grpc_disable_dev(const char *name)
{
	return comlayer_disable_dev(name);
}

int init_grpc(void)
{
	int i, res;
	struct grpc_service *grpc_undef_service;

	grpc_desc_cachep = kmem_cache_create("grpc_desc",
					    sizeof(struct grpc_desc),
					    0, 0, NULL);
	if(!grpc_desc_cachep)
		return -ENOMEM;
	
	grpc_desc_send_cachep = kmem_cache_create("grpc_desc_send",
						 sizeof(struct grpc_desc_send),
						 0, 0, NULL);
	if(!grpc_desc_send_cachep)
		return -ENOMEM;

	grpc_desc_recv_cachep = kmem_cache_create("grpc_desc_recv",
						 sizeof(struct grpc_desc_recv),
						 0, 0, NULL);
	if(!grpc_desc_recv_cachep)
		return -ENOMEM;

	grpc_tx_elem_cachep = kmem_cache_create("grpc_tx_elem",
					       sizeof(struct grpc_tx_elem),
					       0, 0, NULL);
	if(!grpc_tx_elem_cachep)
		return -ENOMEM;

	grpc_desc_elem_cachep = kmem_cache_create("grpc_desc_elem",
						 sizeof(struct grpc_desc_elem),
						 0, 0, NULL);
	if(!grpc_desc_elem_cachep)
		return -ENOMEM;

	__grpc_synchro_cachep = kmem_cache_create("__grpc_synchro",
						 sizeof(struct __grpc_synchro),
						 0, 0, NULL);
	if(!__grpc_synchro_cachep)
		return -ENOMEM;
	
	memset(grpc_mask, 0, sizeof(grpc_mask));
	
	grpc_services = kmalloc(sizeof(*grpc_services)*(GRPCID_MAX+1),
			       GFP_KERNEL);
	if(!grpc_services)
		return -ENOMEM;

	grpc_undef_service = grpc_service_init(GRPC_UNDEF,
					     GRPC_TARGET_NODE,
					     GRPC_HANDLER_KTHREAD_VOID,
					     NULL,
					     grpc_undef_handler, 0);

	for(i=0;i<GRPCID_MAX;i++)
		grpc_services[i] = grpc_undef_service;
	
	for_each_possible_cpu(i){
		INIT_LIST_HEAD(&per_cpu(grpc_desc_trash, i));
	};
		
	grpc_desc_id = 1;

	for(i=0;i<HCC_MAX_NODES;i++){
		desc_srv[i] = hashtable_new(32);
		if(!desc_srv[i])
			return -ENOMEM;

		lockdep_set_class(&desc_srv[i]->lock, &grpc_desc_srv_lock_key);

		grpc_desc_done_id[i] = 0;
		spin_lock_init(&grpc_desc_done_lock[i]);

	};
	desc_clt = hashtable_new(32);
	if(!desc_clt)
		return -ENOMEM;

	lockdep_set_class(&desc_clt->lock, &grpc_desc_clt_lock_key);

	for (i = 0; i < HCC_MAX_NODES; i++) {
		grpc_link_send_seq_id[i] = 1;
		grpc_link_send_ack_id[i] = 0;
		grpc_link_recv_seq_id[i] = 1;
	}
		
	res = thread_pool_init();
	if(res)
		return res;
	
	res = comlayer_init();
	if(res)
		return res;

	res = grpclayer_init();
	if(res)
		return res;

	res = grpc_monitor_init();
	if(res)
		return res;
	
	printk("GRPC initialisation done\n");
	
	return 0;
}

/** Cleanup of the Nazgul module.
 *  @author Innogrid HCC
 */
void cleanup_grpc(void)
{
}
