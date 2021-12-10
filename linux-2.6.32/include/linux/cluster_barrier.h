/** Cluster wide barrier
 *  @file cluster_barrier.h
 *
 *  @author Innogrid HCC
 */
#include <linux/wait.h>
#include <linux/spinlock_types.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/types.h>
#include <linux/sched.h>
enum static_cluster_barrier_id {
	CLUSTER_BARRIER_NONE = 0,
	GDM_GHOTPLUG_BARRIER,
	GSCHED_GHOTPLUG_BARRIER,
	CLUSTER_BARRIER_MAX,
};

struct cluster_barrier_core {
	hcc_nodemask_t nodes_in_barrier;
	hcc_nodemask_t nodes_to_wait;
	wait_queue_head_t waiting_tsk;
	int in_barrier;
};

struct cluster_barrier_id {
	unique_id_t key;
	int toggle;
};

struct cluster_barrier {
	spinlock_t lock;
	struct cluster_barrier_id id;
	struct cluster_barrier_core core[2];
};


struct cluster_barrier *alloc_cluster_barrier(unique_id_t key);
void free_cluster_barrier(struct cluster_barrier *barrier);
int cluster_barrier(struct cluster_barrier *barrier, hcc_nodemask_t *nodes,
		    hcc_node_t master);
void init_cluster_barrier(void);

