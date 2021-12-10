/**
 *  Application frontier
 *  @author Innogrid HCC
 */

#ifndef __APPLICATION_FRONTIER_H__
#define __APPLICATION_FRONTIER_H__

long get_appid_from_pid(pid_t pid);

void application_frontier_grpc_init(void);

#endif /* __APPLICATION_FRONTIER_H__ */
