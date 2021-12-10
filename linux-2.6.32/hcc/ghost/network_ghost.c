/** Network Ghost interface.
 *  @file network_ghost.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <net/grpc/grpc.h>
#include <hcc/ghost.h>
#include <hcc/network_ghost.h>

/** Read data from a network ghost.
 *  @author Innogrid HCC
 *
 *  @param  ghost   Ghost to read data from.
 *  @param  buff    Buffer to store data.
 *  @param  length  Size of data to read.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int network_ghost_read(struct ghost *ghost, void *buff, size_t length)
{
	struct grpc_desc *desc = ghost->data;
	int retval;

	retval = grpc_unpack(desc, 0, buff, length);
	if (retval == GRPC_EPIPE)
		retval = -EPIPE;
	BUG_ON(retval > 0);

	return retval;
}

/** Write data to a network ghost.
 *  @author Innogrid HCC
 *
 *  @param  ghost   Ghost to write data to.
 *  @param  buff    Buffer to write in the ghost.
 *  @param  length  Size of data to write.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int network_ghost_write(struct ghost *ghost, const void *buff, size_t length)
{
	struct grpc_desc *desc = ghost->data;
	int retval;

	retval = grpc_pack(desc, 0, buff, length);

	return retval;
}

/** Close a network ghost.
 *  @author Innogrid HCC
 *
 *  @param  ghost   Ghost to close.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
int network_ghost_close(struct ghost *ghost)
{
	ghost->data = NULL;
	free_ghost(ghost);
	return 0;
}

/** Netwotk ghost operations
 */
struct ghost_operations ghost_network_ops = {
	.read  = network_ghost_read,
	.write = network_ghost_write,
	.close = network_ghost_close
};

/** Create a network ghost.
 *  @author Innogrid HCC
 *
 *  @param  access Ghost access (READ/WRITE)
 *  @param  desc   GRPC descriptor to send/receive on.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
ghost_t * create_network_ghost(int access, struct grpc_desc *desc)
{
	struct ghost *ghost;

	/* A network ghost can be used in bi-directional mode */
	BUG_ON(!access);

	ghost = create_ghost(GHOST_NETWORK, access);
	if (IS_ERR(ghost))
		return ghost;

	ghost->data = desc;
	ghost->ops = &ghost_network_ops;

	return ghost;
}
