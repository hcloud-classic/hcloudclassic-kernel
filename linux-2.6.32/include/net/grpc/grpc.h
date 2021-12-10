#ifndef __HCC_GRPC__
#define __HCC_GRPC__

#include <net/grpc/grpcid.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/sys/types.h>

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/errno.h>

enum grpc_target {
	GRPC_TARGET_NODE,
	GRPC_TARGET_PIDTYPE,
};

enum grpc_handler {
	GRPC_HANDLER_KTHREAD,
	GRPC_HANDLER_KTHREAD_VOID,
	GRPC_HANDLER_KTHREAD_INT,
	GRPC_HANDLER_MAX
};

enum grpc_error {
	GRPC_EOK = 0,
	GRPC_EINTR,
	GRPC_ESIGACK,
	GRPC_EPIPE,
	GRPC_ECLOSE,
	GRPC_EVAL,
};

enum {
	__GRPC_FLAGS_NOBLOCK, /* request async operation */
	__GRPC_FLAGS_EARLIER, /* do the action as soon as possible */
	__GRPC_FLAGS_LATER,   /* do the action during the grpc_end_xxx */
	__GRPC_FLAGS_SECURE,  /* force a copy of the sent buffer */
	__GRPC_FLAGS_NOCOPY,  /* request the network buffer */
	__GRPC_FLAGS_INTR,    /* sleep in INTERRUPTIBLE state */
	__GRPC_FLAGS_REPOST,  /* post a send/recv without update seqid */
	__GRPC_FLAGS_SIGACK,  /* unpack() should return SIGACKs */
	__GRPC_FLAGS_MAX      /* Must be last */
};

#define GRPC_FLAGS_NOBLOCK (1<<__GRPC_FLAGS_NOBLOCK)
#define GRPC_FLAGS_EARLIER (1<<__GRPC_FLAGS_EARLIER)
#define GRPC_FLAGS_LATER   (1<<__GRPC_FLAGS_LATER)
#define GRPC_FLAGS_SECURE  (1<<__GRPC_FLAGS_SECURE)
#define GRPC_FLAGS_NOCOPY  (1<<__GRPC_FLAGS_NOCOPY)
#define GRPC_FLAGS_INTR    (1<<__GRPC_FLAGS_INTR)
#define GRPC_FLAGS_REPOST  (1<<__GRPC_FLAGS_REPOST)
#define GRPC_FLAGS_SIGACK  (1<<__GRPC_FLAGS_SIGACK)

enum grpc_rq_type {
	GRPC_RQ_UNDEF,
	GRPC_RQ_CLT,
	GRPC_RQ_SRV,
	GRPC_RQ_FWD,
};

enum {
	__GRPC_STATE_NEW,
	__GRPC_STATE_HANDLE,
	__GRPC_STATE_RUN,
	__GRPC_STATE_CANCEL,
	__GRPC_STATE_END,
	__GRPC_STATE_WAIT,
	__GRPC_STATE_WAIT1,
};

enum grpc_rq_state {
	GRPC_STATE_NEW    = (1<<__GRPC_STATE_NEW),
	GRPC_STATE_HANDLE = (1<<__GRPC_STATE_HANDLE),
	GRPC_STATE_RUN    = (1<<__GRPC_STATE_RUN),
	GRPC_STATE_CANCEL = (1<<__GRPC_STATE_CANCEL),
	GRPC_STATE_END    = (1<<__GRPC_STATE_END),
	GRPC_STATE_WAIT   = (1<<__GRPC_STATE_WAIT),
	GRPC_STATE_WAIT1  = (1<<__GRPC_STATE_WAIT1),
};

#define GRPC_STATE_MASK_VALID (GRPC_STATE_RUN\
 | GRPC_STATE_HANDLE \
 | GRPC_STATE_NEW \
 | GRPC_STATE_WAIT \
 | GRPC_STATE_WAIT1)

struct grpc_service;

struct grpc_desc {
	struct grpc_desc_send* desc_send;
	struct grpc_desc_recv* desc_recv[HCC_MAX_NODES];
	struct grpc_service* service;
	hcc_nodemask_t nodes;
	enum grpc_rq_type type;
	struct list_head list;
	int in_interrupt;
	unsigned long desc_id;
	spinlock_t desc_lock;
	enum grpcid grpcid;
	hcc_node_t client;
	enum grpc_rq_state state;
	struct task_struct *thread;
	hcc_node_t wait_from;
	atomic_t usage;
	struct __grpc_synchro *__synchro;
};

struct grpc_data {
	void *raw;
	void *data;
	size_t size;
};

typedef void (*grpc_handler_t) (struct grpc_desc* grpc_desc);

typedef void (*grpc_handler_void_t)(struct grpc_desc* grpc_desc,
				   void* data, size_t size);

typedef int (*grpc_handler_int_t) (struct grpc_desc* grpc_desc,
				  void* data, size_t size);

/*
 * GRPC synchro
 */

struct grpc_synchro* grpc_synchro_new(int max,
				    char *label,
				    int order);

/*
 * GRPC management
 */
int __grpc_register(enum grpcid grpcid,
		   enum grpc_target grpc_target,
		   enum grpc_handler grpc_handler,
		   struct grpc_synchro *grpc_synchro,
		   void* _h,
		   unsigned long flags);

struct grpc_desc* grpc_begin_m(enum grpcid grpcid,
			     hcc_nodemask_t* nodes);

int grpc_cancel(struct grpc_desc* desc);

int grpc_pack(struct grpc_desc* desc, int flags, const void* data, size_t size);
int grpc_wait_pack(struct grpc_desc* desc, int seq_id);
int grpc_cancel_pack(struct grpc_desc* desc);

int grpc_forward(struct grpc_desc* desc, hcc_node_t node);

enum grpc_error grpc_unpack(struct grpc_desc* desc, int flags, void* data, size_t size);
enum grpc_error grpc_unpack_from(struct grpc_desc* desc, hcc_node_t node,
			       int flags, void* data, size_t size);
void grpc_cancel_unpack(struct grpc_desc* desc);

hcc_node_t grpc_wait_return(struct grpc_desc* desc, int* value);
int grpc_wait_return_from(struct grpc_desc* desc, hcc_node_t node);
int grpc_wait_all(struct grpc_desc *desc);

int grpc_signal(struct grpc_desc* desc, int sigid);

int grpc_end(struct grpc_desc *grpc_desc, int flags);

void grpc_free_buffer(struct grpc_data *buf);

s64 grpc_consumed_bytes(void);

void grpc_enable_lowmem_mode(hcc_node_t nodeid);
void grpc_disable_lowmem_mode(hcc_node_t nodeid);
void grpc_enable_local_lowmem_mode(void);
void grpc_disable_local_lowmem_mode(void);

/*
 * Convenient define
 */

#define grpc_pack_type(desc, v) grpc_pack(desc, 0, &v, sizeof(v))
#define grpc_unpack_type(desc, v) grpc_unpack(desc, 0, &v, sizeof(v))
#define grpc_unpack_type_from(desc, n, v) grpc_unpack_from(desc, n, 0, &v, sizeof(v))

/*
 * Convenient functions
 */

static inline
int grpc_register_void(enum grpcid grpcid,
		      grpc_handler_void_t h,
		      unsigned long flags){
	return __grpc_register(grpcid, GRPC_TARGET_NODE, GRPC_HANDLER_KTHREAD_VOID,
			      NULL, (grpc_handler_t)h, flags);
};

static inline
int grpc_register_int(enum grpcid grpcid,
		     grpc_handler_int_t h,
		     unsigned long flags){
	return __grpc_register(grpcid, GRPC_TARGET_NODE, GRPC_HANDLER_KTHREAD_INT,
			      NULL, (grpc_handler_t)h, flags);
};

static inline
int grpc_register(enum grpcid grpcid,
		 grpc_handler_t h,
		 unsigned long flags){
	return __grpc_register(grpcid, GRPC_TARGET_NODE, GRPC_HANDLER_KTHREAD,
			      NULL, h, flags);
};

static inline
struct grpc_desc* grpc_begin(enum grpcid grpcid,
			   hcc_node_t node){
	hcc_nodemask_t nodes;

	hcc_nodes_clear(nodes);
	hcc_node_set(node, nodes);

	return grpc_begin_m(grpcid, &nodes);
};

static inline
int grpc_async_m(enum grpcid grpcid,
		hcc_nodemask_t* nodes,
		const void* data, size_t size){
	struct grpc_desc* desc;
	int err = -ENOMEM;

	desc = grpc_begin_m(grpcid, nodes);
	if (!desc)
		goto out;

	err = grpc_pack(desc, 0, data, size);

	/* grpc_end() always succeeds without delayed grpc_pack() */
	grpc_end(desc, 0);

out:
	return err;
};

static inline
int grpc_async(enum grpcid grpcid,
	      hcc_node_t node,
	      const void* data, size_t size){
	hcc_nodemask_t nodes;

	hcc_nodes_clear(nodes);
	hcc_node_set(node, nodes);
	
	return grpc_async_m(grpcid, &nodes, data, size);
};

static inline
int grpc_sync_m(enum grpcid grpcid,
	       hcc_nodemask_t* nodes,
	       const void* data, size_t size){
	struct grpc_desc *desc;
	int rold, r, first, error;
	int i;

	r = -ENOMEM;
	desc = grpc_begin_m(grpcid, nodes);
	if (!desc)
		goto out;

	r = grpc_pack(desc, 0, data, size);
	if (r)
		goto end;

	i = 0;
	first = 1;
	error = 0;
	r = 0;

	__for_each_hcc_node_mask(i, nodes){
		grpc_unpack_type_from(desc, i, rold);
		if(first){
			r = rold;
			first = 0;
		}else
			error = error || (r != rold);
		i++;
	};

end:
	/* grpc_end() always succeeds without delayed grpc_pack() */
	grpc_end(desc, 0);

out:
	return r;
};

static inline
int grpc_sync(enum grpcid grpcid,
	     hcc_node_t node,
	     const void* data, size_t size){
	hcc_nodemask_t nodes;

	hcc_nodes_clear(nodes);
	hcc_node_set(node, nodes);
	
	return grpc_sync_m(grpcid, &nodes, data, size);
};

void grpc_enable(enum grpcid grpcid);
void grpc_enable_all(void);
void grpc_disable(enum grpcid grpcid);

void grpc_enable_alldev(void);
int grpc_enable_dev(const char *name);
void grpc_disable_alldev(void);
int grpc_disable_dev(const char *name);

hcc_node_t grpc_desc_get_client(struct grpc_desc *desc);

extern struct task_struct *first_grpc;

#endif
