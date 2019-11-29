/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#ifndef __RPC_ID__
#define __RPC_ID__

enum rpcid {

    NODE_ADD,
    NODE_REMOVE,
    NODE_REMOVE_ADVERTISE,
    NODE_REMOVE_ACK,
    NODE_REMOVE_CONFIRM,
    NODE_FAIL,
    NODE_POWEROFF,
    NODE_REBOOT,

    NODE_FWD_ADD,
    NODE_FWD_REMOVE,

    CLUSTER_START,
    CLUSTER_STOP
};

#endif
