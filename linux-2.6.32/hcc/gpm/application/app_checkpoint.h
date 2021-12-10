/**
 *  Application checkpoint
 *  @author Innogrid HCC
 */

#ifndef __APPLICATION_CHECKPOINT_H__
#define __APPLICATION_CHECKPOINT_H__

#include <hcc/sys/checkpoint.h>

int app_freeze(struct checkpoint_info *info);

int app_unfreeze(struct checkpoint_info *info);

int app_chkpt(struct checkpoint_info *info);

int app_cr_exclude(struct cr_mm_region *mm_regions);

void application_checkpoint_grpc_init(void);

#endif /* __APPLICATION_CHECKPOINT_H__ */
