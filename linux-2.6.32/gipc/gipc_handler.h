/** Interface of IPC management.
 *  @file gipc_handler.h
 *
 *  @author Innogrid HCC
 */


#ifndef IPC_HANDLER_H
#define IPC_HANDLER_H

#include <linux/ipc.h>
#include <linux/ipc_namespace.h>

int hcc_gipc_get_maxid(struct ipc_ids *ids);
int hcc_gipc_get_new_id(struct ipc_ids *ids);
void hcc_gipc_rmid(struct ipc_ids *ids, int index);
int hcc_gipc_get_this_id(struct ipc_ids *ids, int id);

struct ipc_namespace *find_get_hcc_gipcns(void);

void ipc_handler_finalize (void);
void ipc_handler_init (void);

#endif // IPC_HANDLER_H
