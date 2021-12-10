/** Application restart
 *  @author Innogrid HCC
 */

#ifndef __APPLICATION_RESTART_H__
#define __APPLICATION_RESTART_H__

int app_restart(struct restart_request *req,
		const task_identity_t *requester);

void application_restart_grpc_init(void);

#endif /* __APPLICATION_RESTART_H__ */
