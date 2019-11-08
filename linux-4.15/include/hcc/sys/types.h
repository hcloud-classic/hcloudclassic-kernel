/*
 *  Copyright (C) 2019 Innogrid
 */

/*  writen by cgs 2019 */

#ifndef __HCC_TYPES__

#define HCC_MAX_NODES 16
#define HCC_HARD_MAX_NODES 256
#define HCC_NODE_ID 1

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

typedef short hcc_node_t;

typedef unsigned long event_counter_t;

typedef unsigned long physaddr_t;

enum hcc_status {
	HCC_FIRST_START,
	HCC_FINAL_STOP,
	HCC_NODE_STARTING,
	HCC_NODE_STOPING,
	HCC_RUNNING_CLUSTER,
};
#define __HCC_TYPES__

#endif
