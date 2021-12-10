#ifndef __HCC_FLAGS_H__
#define __HCC_FLAGS_H__

enum {
	__HCC_FLAGS_LOADED,
	__HCC_FLAGS_STARTING,
	__HCC_FLAGS_RUNNING,
	__HCC_FLAGS_ADDING,
	__HCC_FLAGS_REMOVING,
	__HCC_FLAGS_RECOVERING,
	__HCC_FLAGS_STOPPING,
	__HCC_FLAGS_STOPPED,
	__HCC_FLAGS_FAILED,
};

#define HCC_FLAGS_LOADED (1<<__HCC_FLAGS_LOADED)
#define HCC_FLAGS_STARTING (1<<__HCC_FLAGS_STARTING)
#define HCC_FLAGS_RUNNING (1<<__HCC_FLAGS_RUNNING)
#define HCC_FLAGS_ADDING (1<<__HCC_FLAGS_ADDING)
#define HCC_FLAGS_REMOVING (1<<__HCC_FLAGS_REMOVING)
#define HCC_FLAGS_RECOVERING (1<<__HCC_FLAGS_RECOVERING)
#define HCC_FLAGS_STOPPING (1<<__HCC_FLAGS_STOPPING)
#define HCC_FLAGS_STOPPED (1<<__HCC_FLAGS_STOPPED)
#define HCC_FLAGS_FAILED (1<<__HCC_FLAGS_FAILED)

extern int hcc_cluster_flags;
extern int hcc_node_flags;

#define IS_HCC_CLUSTER(m) (hcc_cluster_flags & m)
#define IS_HCC_NODE(m) (hcc_node_flags & m)

#define SET_HCC_CLUSTER_FLAGS(m) hcc_cluster_flags |= m
#define SET_HCC_NODE_FLAGS(m) hcc_node_flags |= m

#define CLEAR_HCC_CLUSTER_FLAGS(m) hcc_cluster_flags &= ~m
#define CLEAR_HCC_NODE_FLAGS(m) hcc_node_flags &= ~m

#endif
