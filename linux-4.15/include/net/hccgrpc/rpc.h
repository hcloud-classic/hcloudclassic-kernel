#ifndef __RPC__H
#define __RPC__H

#include <net/hccgrpc/rpcid.h>
#include <linux/spinlock.h>
#include <hcc/sys/types.h>
#include <hcc/hccnodemask.h>

enum rpc_target {
    RPC_TARGET_NODE,
    RPC_TARGET_PIDTYPE,
};

enum rpc_handler {
    RPC_HANDLER_KTHREAD,
    RPC_HANDLER_KTHREAD_VOID,
    RPC_HANDLER_KTHREAD_INT,
    RPC_HANDLER_MAX
};

enum rpc_error {
    RPC_EOK = 0,
    RPC_EINTR,
    RPC_ESIGACK,
    RPC_EPIPE,
    RPC_ECLOSE,
    RPC_EVAL,
};

enum {
    __RPC_FLAGS_NOBLOCK, /* request async operation */
    __RPC_FLAGS_EARLIER, /* do the action as soon as possible */
    __RPC_FLAGS_LATER,   /* do the action during the rpc_end_xxx */
    __RPC_FLAGS_SECURE,  /* force a copy of the sent buffer */
    __RPC_FLAGS_NOCOPY,  /* request the network buffer */
    __RPC_FLAGS_INTR,    /* sleep in INTERRUPTIBLE state */
    __RPC_FLAGS_REPOST,  /* post a send/recv without update seqid */
    __RPC_FLAGS_SIGACK,  /* unpack() should return SIGACKs */
    __RPC_FLAGS_MAX      /* Must be last */
};

#define RPC_FLAGS_NOBLOCK (1<<__RPC_FLAGS_NOBLOCK)
#define RPC_FLAGS_EARLIER (1<<__RPC_FLAGS_EARLIER)
#define RPC_FLAGS_LATER   (1<<__RPC_FLAGS_LATER)
#define RPC_FLAGS_SECURE  (1<<__RPC_FLAGS_SECURE)
#define RPC_FLAGS_NOCOPY  (1<<__RPC_FLAGS_NOCOPY)
#define RPC_FLAGS_INTR    (1<<__RPC_FLAGS_INTR)
#define RPC_FLAGS_REPOST  (1<<__RPC_FLAGS_REPOST)
#define RPC_FLAGS_SIGACK  (1<<__RPC_FLAGS_SIGACK)

enum rpc_rq_type {
    RPC_RQ_UNDEF,
    RPC_RQ_CLT,
    RPC_RQ_SRV,
    RPC_RQ_FWD,
};

enum rpc_rq_state {
    __RPC_STATE_NEW,
    __RPC_STATE_HANDLE,
    __RPC_STATE_RUN,
    __RPC_STATE_CANCEL,
    __RPC_STATE_END,
    __RPC_STATE_WAIT,
    __RPC_STATE_WAIT1,
};

#define RPC_STATE_NEW    (1<<__RPC_STATE_NEW)
#define RPC_STATE_HANDLE (1<<__RPC_STATE_HANDLE)
#define RPC_STATE_RUN    (1<<__RPC_STATE_RUN)
#define RPC_STATE_CANCEL (1<<__RPC_STATE_CANCEL)
#define RPC_STATE_END    (1<<__RPC_STATE_END)
#define RPC_STATE_WAIT   (1<<__RPC_STATE_WAIT)
#define RPC_STATE_WAIT1  (1<<__RPC_STATE_WAIT1)

#define RPC_STATE_MASK_VALID (RPC_STATE_RUN\
 | RPC_STATE_HANDLE \
 | RPC_STATE_NEW \
 | RPC_STATE_WAIT \
 | RPC_STATE_WAIT1)

struct rpc_service;

struct rpc_desc {
    struct rpc_desc_send* desc_send;
    struct rpc_desc_recv* desc_recv[HCC_MAX_NODES];
    struct rpc_service* service;
    hccnodemask_t nodes;
    enum rpc_rq_type type;
    struct list_head list;
    int in_interrupt;
    unsigned long desc_id;
    spinlock_t desc_lock;
    enum rpcid rpcid;
    hcc_node_t client;
    enum rpc_rq_state state;
    struct task_struct *thread;
    hcc_node_t wait_from;
    atomic_t usage;
    struct __rpc_synchro *__synchro;
};

struct rpc_data {
    void *raw;
    void *data;
    size_t size;
};

typedef void (*rpc_handler_t) (struct rpc_desc* rpc_desc);

typedef void (*rpc_handler_void_t)(struct rpc_desc* rpc_desc,
                                   void* data, size_t size);

typedef int (*rpc_handler_int_t) (struct rpc_desc* rpc_desc,
                                  void* data, size_t size);

int rpc_pack(struct rpc_desc* desc, int flags, const void* data, size_t size);
int rpc_wait_pack(struct rpc_desc* desc, int seq_id);
int rpc_cancel_pack(struct rpc_desc* desc);

int init_rpc(void);
int comlayer_init(void);

int rpc_end(struct rpc_desc *rpc_desc, int flags);

enum rpc_error rpc_unpack(struct rpc_desc* desc, int flags, void* data, size_t size);

void rpc_free_buffer(struct rpc_data *buf);

void rpc_enable(enum rpcid rpcid);
void rpc_enable_all(void);
void rpc_disable(enum rpcid rpcid);

#define rpc_pack_type(desc, v) rpc_pack(desc, 0, &v, sizeof(v))
#define rpc_unpack_type(desc, v) rpc_unpack(desc, 0, &v, sizeof(v))
#define rpc_unpack_type_from(desc, n, v) rpc_unpack_from(desc, n, 0, &v, sizeof(v))


#endif