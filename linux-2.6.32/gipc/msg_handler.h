/** Interface of IPC msg management.
 *  @file msg_handler.h
 *
 *  @author Innogrid HCC
 */


#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include <linux/msg.h>

struct gdm_set;

struct gdm_set *hcc_gipc_ops_master_set(struct hcc_gipc_ops *ipcops);

void msg_handler_init(void);
void msg_handler_finalize(void);

#endif // MSG_HANDLER_H
