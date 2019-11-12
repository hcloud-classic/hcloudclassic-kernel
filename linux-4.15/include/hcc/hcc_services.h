#ifndef __HCC_SERVICES__
#define __HCC_SERVICES__

#include <linux/ioctl.h>

/*
 * IPC related hcc syscalls
 */
#define KSYS_IPC_MSGQ_CHKPT            _IOW(HCC_PROC_MAGIC,       \
					    IPC_PROC_BASE + 0,		\
					    int[2])
#define KSYS_IPC_MSGQ_RESTART          _IOW(HCC_PROC_MAGIC, \
					    IPC_PROC_BASE + 1,	  \
					    int)
#define KSYS_IPC_SEM_CHKPT             _IOW(HCC_PROC_MAGIC,       \
					    IPC_PROC_BASE + 2,		\
					    int[2])
#define KSYS_IPC_SEM_RESTART           _IOW(HCC_PROC_MAGIC, \
					    IPC_PROC_BASE + 3,	  \
					    int)
#define KSYS_IPC_SHM_CHKPT             _IOW(HCC_PROC_MAGIC,       \
					    IPC_PROC_BASE + 4,		\
					    int[2])
#define KSYS_IPC_SHM_RESTART           _IOW(HCC_PROC_MAGIC, \
					    IPC_PROC_BASE + 5,	  \
					    int)

#endif