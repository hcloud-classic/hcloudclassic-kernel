#ifndef NO_MSG
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/msg.h>
#include <linux/syscalls.h>
#include "util.h"
#include "msg_handler.h"



struct msghccops {
	struct hccipc_ops hccops;
	struct master_set *master_set;
};


struct master_set *hccipc_ops_master_set(struct hccipc_ops *ipcops)
{
	struct msghccops *msgops;

	msgops = container_of(ipcops, struct msghccops, hccops);

	return msgops->master_set;
}


#endif