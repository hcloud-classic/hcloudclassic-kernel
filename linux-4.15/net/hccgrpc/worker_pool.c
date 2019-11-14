/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <hcc/workqueue.h>
#include <linux/fs_struct.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <hcc/sys/types.h>
#include <net/hccgrpc/rpcid.h>
#include "rpc_internal.h"
#include <linux/rcupdate.h>


typedef unsigned long threads_vector_t;
#define THREADS_VECTOR_WIDTH (sizeof(threads_vector_t) * 8)

struct workers_pool {
    threads_vector_t threads_vector;
    struct task_struct* threads[THREADS_VECTOR_WIDTH];
    struct rpc_desc* desc[THREADS_VECTOR_WIDTH];
    int nbthreads;
};

#define HCCRPC_INIT_FDTABLE \
{                                                                           \
    .max_fds        = NR_OPEN_DEFAULT,                                      \
    .fd             = &hccrpc_files.fd_array[0],                            \
    .close_on_exec  = (unsigned long *)&hccrpc_files.close_on_exec_init,    \
    .open_fds       = (unsigned long *)&hccrpc_files.open_fds_init,         \
    .rcu            = { .next = NULL, .func = NULL,},                       \
}

#define HCCRPC_INIT_FILES \
{                                                                   \
    .count          = ATOMIC_INIT(1),                               \
    .fdt            = &hccrpc_files.fdtab,                          \
    .fdtab          = HCCRPC_INIT_FDTABLE,                          \
	.file_lock	= __SPIN_LOCK_UNLOCKED(hccrpc_files.file_lock),     \
    .next_fd        = 0,                                            \
    .close_on_exec_init = { 0, },                                   \
    .open_fds_init  = { 0, },                                       \
    .fd_array       = { NULL, }                                     \
}

static struct files_struct hccrpc_files = HCCRPC_INIT_FILES;
struct task_struct *first_hccrpc = NULL;

static struct completion init_complete;

DEFINE_PER_CPU(struct workers_pool, workers_pool);

struct waiting_desc {
    struct list_head list_waiting_desc;
    struct rpc_desc *desc;
};

struct list_head waiting_desc;
spinlock_t waiting_desc_lock;

struct thread_data {

	atomic_t request[NR_CPUS];
	struct delayed_work dwork;

} new_thread_data;

void (*rpc_handlers[RPC_HANDLER_MAX])(struct rpc_desc* desc);

void rpc_handler_kthread(struct rpc_desc* desc){
    ((rpc_handler_t)desc->service->h)(desc);
};

void rpc_handler_kthread_void(struct rpc_desc* desc){
    int err;
    struct rpc_data rpc_data;

    BUG_ON(!desc);

    err = rpc_unpack(desc, RPC_FLAGS_NOCOPY,
                     &rpc_data, 0);

    if(!err){
        BUG_ON(!desc);
        BUG_ON(!desc->service);
        BUG_ON(!desc->service->h);

        ((rpc_handler_void_t)desc->service->h)(desc, rpc_data.data,
                                               rpc_data.size);

        rpc_free_buffer(&rpc_data);

    }else{
        printk("unexpected event\n");
        BUG();
    };

};

void rpc_handler_kthread_int(struct rpc_desc* desc){
    int res;
    int id;
    int err;
    struct rpc_data rpc_data;

    err = rpc_unpack(desc, RPC_FLAGS_NOCOPY,
                     &rpc_data, 0);

    if(!err){

        id = rpc_pack(desc, RPC_FLAGS_LATER,
                      &res, sizeof(res));

        res = ((rpc_handler_int_t)desc->service->h)(desc,
                                                    rpc_data.data,
                                                    rpc_data.size);

        rpc_free_buffer(&rpc_data);
        rpc_wait_pack(desc, id);

    }else{
        printk("unexpected event\n");
        BUG();
    };
};

inline void do_hccrpc_handler(struct rpc_desc* desc, int thread_pool_id)
{
    struct __rpc_synchro* __synchro;
    hcc_node_t client;
    struct waiting_desc *wd;

    BUG_ON(desc->type != RPC_RQ_SRV);

    __synchro = desc->__synchro;
    if(__synchro)
        __rpc_synchro_get(__synchro);

    continue_in_synchro:
    client = desc->client;
    BUG_ON(!desc->desc_recv[0]);

    if(test_bit(desc->rpcid, rpc_mask)){
        printk("need to move current desc in the waiting_desc queue\n");
        BUG();
    };

    rpc_signal_deliver_pending(desc, desc->desc_recv[0]);
    rpc_handlers[desc->service->handler](desc);
    BUG_ON(signal_pending(current));

    rpc_end(desc, 0);

    if(__synchro){

        spin_lock_bh(&__synchro->lock);

        if(!list_empty(&__synchro->list_waiting_head)){

            wd = list_entry(__synchro->list_waiting_head.next,
            struct waiting_desc,
            list_waiting_desc);

            list_del(&wd->list_waiting_desc);

            spin_unlock_bh(&__synchro->lock);

            rpc_desc_put(wd->desc);

            desc = wd->desc;
            desc->thread = current;
            desc->state = RPC_STATE_RUN;

            kfree(wd);

            goto continue_in_synchro;
        }else{
            atomic_inc(&__synchro->v);
            spin_unlock_bh(&__synchro->lock);
        }

        __rpc_synchro_put(__synchro);
    }
}

static int thread_pool_init_fs(void)
{
    struct fs_struct *new_fs;

    new_fs = copy_fs_struct(current->fs);
    if (!new_fs)
        return -ENOMEM;
    exit_fs(current);
    task_lock(current);
    current->fs = new_fs;
    task_unlock(current);
    return 0;
}

int thread_pool_run(void* _data){
    struct workers_pool* worker_pool;
    struct rpc_desc *desc;
    int j;

    if (thread_pool_init_fs()) {
        if(atomic_inc_return(&new_thread_data.request[smp_processor_id()]) == 1)
            queue_delayed_work(hcc_nb_wq, &new_thread_data.dwork, 0);
        return -EAGAIN;
    }

    atomic_inc(&hccrpc_files.count);
    reset_files_struct(&hccrpc_files);

    worker_pool = &per_cpu(workers_pool, smp_processor_id());

    j = find_next_zero_bit(&worker_pool->threads_vector,
                           THREADS_VECTOR_WIDTH,
                           worker_pool->nbthreads);

    if(j < THREADS_VECTOR_WIDTH){
        BUG_ON(j < worker_pool->nbthreads);

        set_bit(j, &worker_pool->threads_vector);
        mb();
        worker_pool->threads[j] = current;
        worker_pool->nbthreads++;
        desc = worker_pool->desc[j];
        worker_pool->desc[j] = NULL;

        if(!first_hccrpc){
            first_hccrpc = current;
            complete(&init_complete);
        }

    }else{
        desc = NULL;
    }

    while (!kthread_should_stop()) {
        struct waiting_desc *wd, *wd_safe;

        continue_in_waiting_desc:

        if(desc)
            do_hccrpc_handler(desc, j);

        spin_lock_bh(&waiting_desc_lock);
        list_for_each_entry_safe(wd, wd_safe,
                                 &waiting_desc,
                                 list_waiting_desc){

            if(test_bit(wd->desc->rpcid, rpc_mask))
                continue;

            list_del(&wd->list_waiting_desc);
            spin_unlock_bh(&waiting_desc_lock);

            rpc_desc_put(wd->desc);

            desc = wd->desc;
            desc->thread = current;
            desc->state = RPC_STATE_RUN;
            kfree(wd);

            BUG_ON(!desc->desc_recv[0]);
            goto continue_in_waiting_desc;
        };

        if(j<THREADS_VECTOR_WIDTH){
            set_current_state(TASK_INTERRUPTIBLE);
            clear_bit(j, &worker_pool->threads_vector);
            spin_unlock_bh(&waiting_desc_lock);

            schedule();

            // prepare the next work
            desc = worker_pool->desc[j];
            worker_pool->desc[j] = NULL;
        }else{
            spin_unlock_bh(&waiting_desc_lock);
            return 0;
        }

        BUG_ON(signal_pending(current));
    };
    return 0;
};

static void new_thread_worker(struct work_struct *data)
{
    unsigned int i;

    printk("HCC: worker_pool - new_thread_worker");

    for_each_online_cpu(i){
        while(atomic_add_unless(&new_thread_data.request[i], -1, 0)){
            struct task_struct *tsk;

            tsk = kthread_create(thread_pool_run, NULL, "hccrpc");
            if (IS_ERR(tsk)) {
                atomic_inc(&new_thread_data.request[i]);
                queue_delayed_work(hcc_nb_wq,
                                   &new_thread_data.dwork,
                                   HZ);
                break;
            }
            kthread_bind(tsk, i);
            wake_up_process(tsk);
        };
    };
};

inline
void list_waiting_ordered_add(struct list_head *head,
                              struct waiting_desc *wd){
    rpc_desc_get(wd->desc);

    if(list_empty(head)){
        list_add(&wd->list_waiting_desc, head);
    }else{
        struct waiting_desc *iter;
        list_for_each_entry_reverse(iter, head,
                                    list_waiting_desc){
            if(iter->desc->desc_id < wd->desc->desc_id){
                list_add(&wd->list_waiting_desc,
                         &iter->list_waiting_desc);
                return;
            };
        };
        list_add(&wd->list_waiting_desc, head);
    };
};

inline
int queue_waiting_desc(struct rpc_desc* desc){
    struct waiting_desc* wd;
    int r = 0;

    wd = kmalloc(sizeof(struct waiting_desc), GFP_ATOMIC);
    if(!wd){
        r = -ENOMEM;
        goto out;
    };

    rpc_desc_get(desc);
    wd->desc = desc;
    desc->state = RPC_STATE_HANDLE;

    spin_lock(&waiting_desc_lock);
    list_add_tail(&wd->list_waiting_desc, &waiting_desc);
    spin_unlock(&waiting_desc_lock);

    out:
    return r;
}

inline
struct rpc_desc* handle_in_interrupt(struct rpc_desc* desc){
    struct __rpc_synchro *__synchro;
    struct waiting_desc *wd;

    __synchro = desc->__synchro;

    if(__synchro)
        __rpc_synchro_get(__synchro);

    continue_in_synchro:

    rpc_handlers[desc->service->handler](desc);

    rpc_end(desc, 0);

    if(__synchro){
        spin_lock_bh(&__synchro->lock);

        if(!list_empty(&__synchro->list_waiting_head)){

            wd = list_entry(__synchro->list_waiting_head.next,
            struct waiting_desc,
            list_waiting_desc);

            list_del(&wd->list_waiting_desc);

            spin_unlock_bh(&__synchro->lock);

            rpc_desc_put(wd->desc);

            desc = wd->desc;
            desc->thread = NULL;
            desc->state = RPC_STATE_RUN;

            kfree(wd);

            if(desc->service->flags & RPC_FLAGS_NOBLOCK)
                goto continue_in_synchro;
        }else{
            atomic_inc(&__synchro->v);
            spin_unlock_bh(&__synchro->lock);
        }

        __rpc_synchro_put(__synchro);

    }

    return desc;
}

int rpc_handle_new(struct rpc_desc* desc){
    struct workers_pool* worker_pool = &per_cpu(workers_pool, smp_processor_id());
    struct __rpc_synchro *__synchro;
    int i, r=0;

    if (!desc->__synchro) {
        r = rpc_synchro_lookup(desc);
        if (r)
            return r;
    }

    __synchro = desc->__synchro;
    if(__synchro){
        spin_lock(&__synchro->lock);

        if(atomic_read(&__synchro->v)){

            atomic_dec(&__synchro->v);
            spin_unlock(&__synchro->lock);

        }else{
            struct waiting_desc *wd;

            wd = kmalloc(sizeof(struct waiting_desc),
                         GFP_ATOMIC);
            if(!wd) {
                spin_unlock(&__synchro->lock);
                return -ENOMEM;
            }

            wd->desc = desc;
            desc->state = RPC_STATE_HANDLE;

            list_waiting_ordered_add(&__synchro->list_waiting_head,
                                     wd);

            spin_unlock(&__synchro->lock);
            return 0;
        }
    }

    // Is it a disabled rpc ?
    if(unlikely(test_bit(desc->rpcid, rpc_mask))){
        if (queue_waiting_desc(desc))
            r = -ENOMEM;
        return r;
    };

    // Is it an interruption-ready handler ?
    if(likely(desc->service->flags & RPC_FLAGS_NOBLOCK)
       && !(desc = handle_in_interrupt(desc)))
        return r;

    // Is-there any available handler ?
    i = find_first_zero_bit(&worker_pool->threads_vector,
                            worker_pool->nbthreads);

    if(i < worker_pool->nbthreads){
        // Found an available handler

        set_bit(i, &worker_pool->threads_vector);

        worker_pool->desc[i] = desc;
        desc->thread = worker_pool->threads[i];
        desc->state = RPC_STATE_RUN;

        wake_up_process(desc->thread);
    }else{

        // No available handler
        if (queue_waiting_desc(desc))
            return -ENOMEM;

        if(atomic_inc_return(&new_thread_data.request[smp_processor_id()]) == 1)
            queue_delayed_work(hcc_nb_wq, &new_thread_data.dwork, 0);

    };

    return r;
};

void rpc_wake_up_thread(struct rpc_desc *desc){
    struct workers_pool* worker_pool = &per_cpu(workers_pool, smp_processor_id());
    int i;

    i = find_first_zero_bit(&worker_pool->threads_vector,
                            worker_pool->nbthreads);

    if(i < worker_pool->nbthreads){
        set_bit(i, &worker_pool->threads_vector);

        worker_pool->desc[i] = desc;

        if(desc){
            desc->thread = worker_pool->threads[i];
            desc->state = RPC_STATE_RUN;
        };

        wake_up_process(worker_pool->threads[i]);
    }else{

        if(atomic_inc_return(&new_thread_data.request[smp_processor_id()]) == 1)
            queue_delayed_work(hcc_nb_wq, &new_thread_data.dwork, 0);

    }
};

int worker_pool_init(void)
{
    unsigned int i, j;
//    struct workers_pool* worker_pool;
    struct workers_pool* worker_pool[1024];

    printk("HCC: worker_pool_init");

    for_each_possible_cpu(i) {
        printk(KERN_INFO "HCC: %d", i);

        worker_pool[i] = &per_cpu(workers_pool, smp_processor_id());
        worker_pool[i]->threads_vector = 0;
        worker_pool[i]->nbthreads = 0;

        for(j = 0; j<THREADS_VECTOR_WIDTH; j++){
            worker_pool[i]->threads[j] = NULL;
            worker_pool[i]->desc[j] = NULL;
        };

        atomic_set(&new_thread_data.request[i], 0);
    }

    printk("HCC: worker_pool - thread done");

    INIT_DELAYED_WORK(&new_thread_data.dwork, new_thread_worker);
    INIT_LIST_HEAD(&waiting_desc);
    spin_lock_init(&waiting_desc_lock);

    rpc_handlers[RPC_HANDLER_KTHREAD] = rpc_handler_kthread;
    rpc_handlers[RPC_HANDLER_KTHREAD_VOID] = rpc_handler_kthread_void;
    rpc_handlers[RPC_HANDLER_KTHREAD_INT] = rpc_handler_kthread_int;

    init_completion(&init_complete);
    atomic_inc(&new_thread_data.request[smp_processor_id()]);
    queue_delayed_work(hcc_nb_wq, &new_thread_data.dwork, 0);
    wait_for_completion(&init_complete);

    return 0;
}