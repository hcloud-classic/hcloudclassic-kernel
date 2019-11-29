#ifndef MSG_HANDLER_H
#define MSG_HANDLER_H

#include <linux/msg.h>

struct master_set;

struct master_set *jccipc_ops_master_set(struct jccipc_ops *ipcops);

void msg_handler_init(void);
void msg_handler_finalize(void);

#endif 
