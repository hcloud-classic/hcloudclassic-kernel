#include <hcc/ghost.h>

int __sys_msgq_checkpoint(int msqid, int fd);

void handle_msg_checkpoint(struct grpc_desc *desc, void *_msg, size_t size);

int import_full_sysv_msgq(ghost_t *ghost);

int export_full_sysv_sem(ghost_t *ghost, int semid);

int import_full_sysv_sem(ghost_t *ghost);

int export_full_sysv_shm(ghost_t *ghost, int shmid);

int import_full_sysv_shm(ghost_t *ghost);
