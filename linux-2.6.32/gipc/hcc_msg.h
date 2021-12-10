#ifndef __HCC_MSG__
#define __HCC_MSG__


struct msg_msgseg {
	struct msg_msgseg* next;
	/* the next part of the message follows immediately */
};

#define DATALEN_MSG	(PAGE_SIZE-sizeof(struct msg_msg))
#define DATALEN_SEG	(PAGE_SIZE-sizeof(struct msg_msgseg))

/** HCC Hooks **/

int hcc_gipc_msg_newque(struct ipc_namespace *ns,
		       struct msg_queue *msq);

void hcc_gipc_msg_freeque(struct ipc_namespace *ns,
			 struct kern_ipc_perm *ipcp);

long hcc_gipc_msgsnd(int msqid, long mtype, void __user *mtext,
		    size_t msgsz, int msgflg, struct ipc_namespace *ns,
		    pid_t tgid);

long hcc_gipc_msgrcv(int msqid, long *pmtype, void __user *mtext,
		    size_t msgsz, long msgtyp, int msgflg,
		    struct ipc_namespace *ns, pid_t tgid);


int newque(struct ipc_namespace *ns, struct ipc_params *params);

static inline struct msg_queue *msg_lock(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = ipc_lock(&msg_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct msg_queue *)ipcp;

	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline void msg_unlock(struct msg_queue *msq)
{
	ipc_unlock(&(msq)->q_perm);
}

static inline struct msg_queue *local_msg_lock(struct ipc_namespace *ns, int id)
{
	struct kern_ipc_perm *ipcp = local_ipc_lock(&msg_ids(ns), id);

	if (IS_ERR(ipcp))
		return (struct msg_queue *)ipcp;

	return container_of(ipcp, struct msg_queue, q_perm);
}

static inline void local_msg_unlock(struct msg_queue *msq)
{
	local_ipc_unlock(&(msq)->q_perm);
}

long __do_msgsnd(int msqid, long mtype, void __user *mtext,
		 size_t msgsz, int msgflg, struct ipc_namespace *ns,
		 pid_t tgid);

long __do_msgrcv(int msqid, long *pmtype, void __user *mtext,
		 size_t msgsz, long msgtyp, int msgflg,
		 struct ipc_namespace *ns, pid_t tgid);

void local_master_freeque(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp);

#endif // __HCC_MSG__
