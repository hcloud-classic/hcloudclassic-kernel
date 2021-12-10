/** Main hcc types.
 *  @file gtypes.h
 *
 *  Definition of the main types and structures.
 *  @author Innogrid HCC
 */

#ifndef __HCC_TYPES__
#define __HCC_TYPES__

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#ifdef CONFIG_HCC_AUTONODEID
#define NR_BITS_IN_MAX_NODE_ID     8
#else
#define NR_BITS_IN_MAX_NODE_ID     7
#endif

#define HCC_MAX_NODES      (1<<NR_BITS_IN_MAX_NODE_ID)        /* Real limit 32766 */
#define HCC_HARD_MAX_NODES 256

#define HCC_MAX_CLUSTERS   256
#define HCC_NODE_ID_NONE    -1        /* Invalid node id */

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#ifndef __ASSEMBLER__

/** Type for node id           */
typedef short hcc_node_t;

/** Event counter type */
typedef unsigned long event_counter_t;

/** Physical address type */
typedef unsigned long physaddr_t;

/** Network id */
typedef unsigned int hcc_network_t;

enum hcc_status {
	HCC_FIRST_START,
	HCC_FINAL_STOP,
	HCC_NODE_STARTING,
	HCC_NODE_STOPING,
	HCC_RUNNING_CLUSTER,
};
typedef enum hcc_status hcc_status_t;

#endif /* __ASSEMBLER__ */

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                             EXTERN VARIABLES                             *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#endif /* __HCC_TYPES__ */
