/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#include <linux/kernel.h>
#include <linux/smp.h>

typedef unsigned long threads_vector_t;
#define THREADS_VECTOR_WIDTH (sizeof(threads_vector_t) * 8)

struct workers_pool {
    threads_vector_t threads_vector;
    struct task_struct* threads[THREADS_VECTOR_WIDTH];
    struct rpc_desc* desc[THREADS_VECTOR_WIDTH];
    int nbthreads;
};

int worker_pool_init(void)
{
    unsigned int i, j;
    struct workers_pool* worker_pool;

    printk("HCC: worker_pool_init");

    for_each_possible_cpu(i) {
        printk(KERN_INFO "HCC: %d", i);
        worker_pool = per_cpu(worker_pool, smp_processor_id());

        worker_pool->threads_vector = 0;
        worker_pool->nbthreads = 0;

        for(j = 0; j<THREADS_VECTOR_WIDTH; j++){
            worker_pool->threads[j] = NULL;
            worker_pool->desc[j] = NULL;
        };
    }

    return 0;
}