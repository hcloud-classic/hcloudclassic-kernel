#ifndef __LIBPROC_H__
#define __LIBPROC_H__

#include <gdm/io_linker.h>

hcc_node_t global_pid_default_owner(struct gdm_set *set, objid_t objid,
					  const hcc_nodemask_t *nodes,
					  int nr_nodes);

#endif /* __LIBPROC_H__ */
