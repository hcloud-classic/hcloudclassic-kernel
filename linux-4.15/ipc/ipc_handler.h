#ifndef IPC_HANDLER_H
#define IPC_HANDLER_H

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>

int jcc_ipc_get_maxid(struct ipc_ids *ids);
int jcc_ipc_get_new_id(struct ipc_ids *ids);
void jcc_ipc_rmid(struct ipc_ids *ids, int index);
int jcc_ipc_get_this_id(struct ipc_ids *ids, int id);

struct ipc_namespace *find_get_jcc_ipcns(void);

void ipc_handler_finalize (void);
void ipc_handler_init (void);

#endif 
