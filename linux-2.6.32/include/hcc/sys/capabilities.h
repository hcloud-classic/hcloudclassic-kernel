/**
 * Define HCC Capabilities
 * @author Innogrid HCC
 */

#ifndef _HCC_GCAPABILITIES_H
#define _HCC_GCAPABILITIES_H

enum {
       CAP_CHANGE_HCC_GCAP = 0,
       GCAP_CAN_MIGRATE,
       GCAP_DISTANT_FORK,
       GCAP_FORK_DELAY,
       GCAP_CHECKPOINTABLE,
       GCAP_USE_REMOTE_MEMORY,
       GCAP_USE_INTRA_CLUSTER_KERSTREAMS,
       GCAP_USE_INTER_CLUSTER_KERSTREAMS,
       GCAP_USE_WORLD_VISIBLE_KERSTREAMS,
       GCAP_SEE_LOCAL_PROC_STAT,
       GCAP_DEBUG,
       GCAP_SYSCALL_EXIT_HOOK,
       CAP_SIZE /* keep as last capability */
};

typedef struct hcc_gcap_struct
{
	int hcc_gcap_effective;
       char hcc_gcap_effective_depth[16];
	int hcc_gcap_permitted;
	int hcc_gcap_inheritable_permitted;
	int hcc_gcap_inheritable_effective;
} hcc_gcap_t;

typedef struct hcc_gcap_pid_desc
{
	pid_t pid;
	hcc_gcap_t *caps;
} hcc_gcap_pid_t;

#endif /* _HCC_GCAPABILITIES_H */
