/*
 *  HCC/modules/gpm/app_utils.h
 *
 *  Copyright (C) 2008 INRIA
 *
 *  @author Innogrid HCC
 */
#ifndef __APP_UTILS_H__
#define __APP_UTILS_H__

#include <net/grpc/grpc.h>

static inline int app_wait_returns_from_nodes(struct grpc_desc *desc,
					      hcc_nodemask_t nodes)
{
	hcc_node_t node;
	int ret, r=0;
	enum grpc_error error;

	for_each_hcc_node_mask(node, nodes) {
		error = grpc_unpack_type_from(desc, node, ret);
		if (error) /* unpack has failed */
			r = error;
		else if (ret)
			r = ret;
        }

	return r;
}

static inline int send_result(struct grpc_desc *desc, int result)
{
	int r;
	enum grpc_error error;

	error = grpc_pack_type(desc, result);
	if (error)
		goto err_grpc;
	error = grpc_unpack_type(desc, r);
	if (error)
		goto err_grpc;

exit:
	return r;
err_grpc:
	r = error;
	goto exit;
}

static inline int ask_nodes_to_continue(struct grpc_desc *desc,
					hcc_nodemask_t nodes,
					int result)
{
	int r;
	enum grpc_error error;

	error = grpc_pack_type(desc, result);
	if (error)
		goto err_grpc;

	r = app_wait_returns_from_nodes(desc, nodes);
exit:
	return r;
err_grpc:
	r = error;
	goto exit;
}

struct task_struct *alloc_shared_fake_task_struct(struct app_struct *app);

void free_shared_fake_task_struct(struct task_struct *fake);

#endif /* __APP_UTILS_H__ */
