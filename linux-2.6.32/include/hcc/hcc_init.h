#ifndef __HCC_INIT_H__
#define __HCC_INIT_H__

#include <hcc/types.h>
#include <linux/rwsem.h>

enum hcc_init_flags_t {
	HCC_INIT_FLAGS_NODEID,
	HCC_INIT_FLAGS_SESSIONID,
	HCC_INIT_FLAGS_AUTONODEID,
};

/* Tools */
extern hcc_node_t hcc_node_id;
extern hcc_node_t hcc_nb_nodes;
extern hcc_node_t hcc_nb_nodes_min;
extern hcc_session_t hcc_session_id;
extern hcc_subsession_t hcc_subsession_id;
extern int hcc_init_flags;
extern struct rw_semaphore hcc_init_sem;

#define SET_HCC_INIT_FLAGS(p) hcc_init_flags |= (1<<p)
#define CLR_HCC_INIT_FLAGS(p) hcc_init_flags &= ~(1<<p)
#define ISSET_HCC_INIT_FLAGS(p) (hcc_init_flags & (1<<p))

#endif
