#ifndef __RUACCESS_H__
#define __RUACCESS_H__

struct grpc_desc;

int prepare_ruaccess(struct grpc_desc *desc);
int cleanup_ruaccess(struct grpc_desc *desc);

int handle_ruaccess(struct grpc_desc *desc);

#endif /* __RUACCESS_H__ */
