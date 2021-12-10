/** Network ghost interface
 *  @file network_ghost.h
 *
 *  Definition of network ghost structures and functions.
 *  @author Innogrid HCC
 */

#ifndef __NETWORK_GHOST_H__
#define __NETWORK_GHOST_H__

#include <hcc/ghost_types.h>

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct grpc_desc;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** Create a network file ghost.
 *  @author Innogrid HCC
 *
 *  @param  access Ghost access (READ/WRITE)
 *  @param  desc   GRPC descriptor to send/receive data on.
 *
 *  @return        0 if everything ok
 *                 Negative value otherwise.
 */
ghost_t * create_network_ghost(int access, struct grpc_desc *desc);

#endif /* __NETWORK_GHOST_H__ */
