/*
 * linux/ipc/util.h
 * Copyright (C) 1999 Christoph Rohland
 *
 * ipc helper functions (c) 1999 Manfred Spraul <manfred@colorfullife.com>
 * namespaces support.      2006 OpenVZ, SWsoft Inc.
 *                               Pavel Emelianov <xemul@openvz.org>
 */

#ifndef _IPC_UTIL_H
#define _IPC_UTIL_H

#include <linux/unistd.h>
#include <linux/err.h>
#ifdef CONFIG_HCC_GIPC
#include <linux/security.h>
#include <hcc/types.h>
#include <gdm/gdm_types.h>
#endif

#define SEQ_MULTIPLIER	(IPCMNI)

/* One semaphore structure for each semaphore in the system. */
struct sem {
	int	semval;		/* current value */
	int	sempid;		/* pid of last operation */
	spinlock_t	lock;	/* spinlock for fine-grained semtimedop */
#ifdef CONFIG_HCC_GIPC
	struct list_head remote_sem_pending;
#endif
	struct list_head sem_pending; /* pending single-sop operations */
};

/* One queue for each sleeping process in the system. */
struct sem_queue {
	struct list_head	list;	 /* queue of pending operations */
	struct task_struct	*sleeper; /* this process */
	struct sem_undo		*undo;	 /* undo structure */
	int			pid;	 /* process id of requesting process */
	int			status;	 /* completion status of operation */
	struct sembuf		*sops;	 /* array of pending operations */
	int			nsops;	 /* number of operations */
	int			alter;	 /* does *sops alter the array? */
#ifdef CONFIG_HCC_GIPC
	int                     semid;
	hcc_node_t        node;
#endif
};

/* Each task has a list of undo requests. They are executed automatically
 * when the process exits.
 */
struct sem_undo {
#ifdef CONFIG_HCC_GIPC
	unique_id_t             proc_list_id;
	/* list_proc is useless in HCC code */
#endif
	struct list_head	list_proc;	/* per-process list: *
						 * all undos from one process
						 * rcu protected */
	struct rcu_head		rcu;		/* rcu struct for sem_undo */
	struct sem_undo_list	*ulp;		/* back ptr to sem_undo_list */
	struct list_head	list_id;	/* per semaphore array list:
						 * all undos for one array */
	int			semid;		/* semaphore set identifier */
	short			*semadj;	/* array of adjustments */
						/* one per semaphore */
};

#define sem_ids(ns)	((ns)->ids[IPC_SEM_IDS])

void sem_init (void);
void msg_init (void);
void shm_init (void);

struct ipc_namespace;

#ifdef CONFIG_POSIX_MQUEUE
extern void mq_clear_sbinfo(struct ipc_namespace *ns);
extern void mq_put_mnt(struct ipc_namespace *ns);
#else
static inline void mq_clear_sbinfo(struct ipc_namespace *ns) { }
static inline void mq_put_mnt(struct ipc_namespace *ns) { }
#endif

#ifdef CONFIG_SYSVIPC
void sem_init_ns(struct ipc_namespace *ns);
void msg_init_ns(struct ipc_namespace *ns);
void shm_init_ns(struct ipc_namespace *ns);

void sem_exit_ns(struct ipc_namespace *ns);
void msg_exit_ns(struct ipc_namespace *ns);
void shm_exit_ns(struct ipc_namespace *ns);
#else
static inline void sem_init_ns(struct ipc_namespace *ns) { }
static inline void msg_init_ns(struct ipc_namespace *ns) { }
static inline void shm_init_ns(struct ipc_namespace *ns) { }

static inline void sem_exit_ns(struct ipc_namespace *ns) { }
static inline void msg_exit_ns(struct ipc_namespace *ns) { }
static inline void shm_exit_ns(struct ipc_namespace *ns) { }
#endif

struct ipc_rcu {
	struct rcu_head rcu;
	atomic_t refcount;
} ____cacheline_aligned_in_smp;

#define ipc_rcu_to_struct(p)  ((void *)(p+1))

#ifdef CONFIG_HCC_GIPC
#define sem_ids(ns)     ((ns)->ids[IPC_SEM_IDS])
#define msg_ids(ns)     ((ns)->ids[IPC_MSG_IDS])
#define shm_ids(ns)     ((ns)->ids[IPC_SHM_IDS])
#endif

/*
 * Structure that holds the parameters needed by the ipc operations
 * (see after)
 */
struct ipc_params {
	key_t key;
	int flg;
	union {
		size_t size;	/* for shared memories */
		int nsems;	/* for semaphores */
	} u;			/* holds the getnew() specific param */
#ifdef CONFIG_HCC_GIPC
	int requested_id;
#endif
};

/*
 * Structure that holds some ipc operations. This structure is used to unify
 * the calls to sys_msgget(), sys_semget(), sys_shmget()
 *      . routine to call to create a new ipc object. Can be one of newque,
 *        newary, newseg
 *      . routine to call to check permissions for a new ipc object.
 *        Can be one of security_msg_associate, security_sem_associate,
 *        security_shm_associate
 *      . routine to call for an extra check if needed
 */
struct ipc_ops {
	int (*getnew) (struct ipc_namespace *, struct ipc_params *);
	int (*associate) (struct kern_ipc_perm *, int);
	int (*more_checks) (struct kern_ipc_perm *, struct ipc_params *);
};

struct seq_file;
struct ipc_ids;

void ipc_init_ids(struct ipc_ids *);
#ifdef CONFIG_PROC_FS
void __init ipc_init_proc_interface(const char *path, const char *header,
		int ids, int (*show)(struct seq_file *, void *));
#else
#define ipc_init_proc_interface(path, header, ids, show) do {} while (0)
#endif

#define IPC_SEM_IDS	0
#define IPC_MSG_IDS	1
#define IPC_SHM_IDS	2

#define ipcid_to_idx(id) ((id) % SEQ_MULTIPLIER)

/* must be called with ids->rw_mutex acquired for writing */
#ifdef CONFIG_HCC_GIPC
int ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int, int);
#else
int ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int);
#endif

/* must be called with ids->rw_mutex acquired for reading */
int ipc_get_maxid(struct ipc_ids *);

/* must be called with both locks acquired. */
void ipc_rmid(struct ipc_ids *, struct kern_ipc_perm *);

/* must be called with ipcp locked */
int ipcperms(struct kern_ipc_perm *ipcp, short flg);

/* for rare, potentially huge allocations.
 * both function can sleep
 */
void* ipc_alloc(int size);
void ipc_free(void* ptr, int size);

/*
 * For allocation that need to be freed by RCU.
 * Objects are reference counted, they start with reference count 1.
 * getref increases the refcount, the putref call that reduces the recount
 * to 0 schedules the rcu destruction. Caller must guarantee locking.
 */
void* ipc_rcu_alloc(int size);
int ipc_rcu_getref(void *ptr);
void ipc_rcu_putref(void *ptr, void (*func)(struct rcu_head *head));
void ipc_rcu_free(struct rcu_head *head);

struct kern_ipc_perm *ipc_lock(struct ipc_ids *, int);
#ifdef CONFIG_HCC_GIPC
struct kern_ipc_perm *local_ipc_lock(struct ipc_ids *ids, int id);
#endif
struct kern_ipc_perm *ipc_obtain_object(struct ipc_ids *ids, int id);

void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out);
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out);
void ipc_update_perm(struct ipc64_perm *in, struct kern_ipc_perm *out);
struct kern_ipc_perm *ipcctl_pre_down_nolock(struct ipc_ids *ids, int id,
				 	     int cmd, struct ipc64_perm *perm,
					     int extra_perm);
struct kern_ipc_perm *ipcctl_pre_down(struct ipc_ids *ids, int id, int cmd,
				      struct ipc64_perm *perm, int extra_perm);

#ifndef __ARCH_WANT_IPC_PARSE_VERSION
  /* On IA-64, we always use the "64-bit version" of the IPC structures.  */ 
# define ipc_parse_version(cmd)	IPC_64
#else
int ipc_parse_version (int *cmd);
#endif

extern void free_msg(struct msg_msg *msg);
extern struct msg_msg *load_msg(const void __user *src, int len);
extern int store_msg(void __user *dest, struct msg_msg *msg, int len);

extern void recompute_msgmni(struct ipc_namespace *);

static inline int ipc_buildid(int id, int seq)
{
	return SEQ_MULTIPLIER * seq + id;
}

static inline int ipc_checkid(struct kern_ipc_perm *ipcp, int uid)
{
	return uid / SEQ_MULTIPLIER != ipcp->seq;
}

static inline void ipc_lock_by_ptr(struct kern_ipc_perm *perm)
{
#ifdef CONFIG_HCC_GIPC
	BUG_ON(perm->hcc_ops);
#endif
	rcu_read_lock();
	spin_lock(&perm->lock);
}

#ifdef CONFIG_HCC_GIPC
void ipc_unlock(struct kern_ipc_perm *perm);

void local_ipc_unlock(struct kern_ipc_perm *perm);
#else
static inline void ipc_unlock(struct kern_ipc_perm *perm)
{
	spin_unlock(&perm->lock);
	rcu_read_unlock();
}
#endif

static inline void ipc_lock_object(struct kern_ipc_perm *perm)
{
	spin_lock(&perm->lock);
}

struct kern_ipc_perm *ipc_lock_check(struct ipc_ids *ids, int id);
struct kern_ipc_perm *ipc_obtain_object_check(struct ipc_ids *ids, int id);
int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
			struct ipc_ops *ops, struct ipc_params *params);
void free_ipcs(struct ipc_namespace *ns, struct ipc_ids *ids,
		void (*free)(struct ipc_namespace *, struct kern_ipc_perm *));

#ifdef CONFIG_HCC_GIPC
void unlink_queue(struct sem_array *sma, struct sem_queue *q);

void msg_rcu_free(struct rcu_head *head);
void sem_rcu_free(struct rcu_head *head);

struct hcc_gipc_ops {
	struct gdm_set *map_gdm_set;
	struct gdm_set *key_gdm_set;
	struct gdm_set *data_gdm_set;

	struct kern_ipc_perm *(*ipc_lock)(struct ipc_ids *, int);
	void (*ipc_unlock)(struct kern_ipc_perm *);
	struct kern_ipc_perm *(*ipc_findkey)(struct ipc_ids *, key_t);
};

int local_ipc_reserveid(struct ipc_ids* ids, struct kern_ipc_perm* new,
                        int size);

int is_hcc_gipc(struct ipc_ids *ids);

int hcc_msg_init_ns(struct ipc_namespace *ns);
int hcc_sem_init_ns(struct ipc_namespace *ns);
int hcc_shm_init_ns(struct ipc_namespace *ns);

void hcc_msg_exit_ns(struct ipc_namespace *ns);
void hcc_sem_exit_ns(struct ipc_namespace *ns);
void hcc_shm_exit_ns(struct ipc_namespace *ns);
#endif

#endif
