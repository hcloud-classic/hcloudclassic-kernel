#ifndef __KHCC_FCNTL__
#define __KHCC_FCNTL__

#define O_FAF_CLT_BIT_NR        22        /* Client File Access Forwarding flag */
#define O_FAF_SRV_BIT_NR        23        /* Server File Access Forwarding flag */
#define O_HCC_SHARED_BIT_NR     24        /* Cluster wide shared file pointer */
#define O_FAF_TTY_BIT_NR        25        /* The file is faffed and is a tty */

#define O_FAF_CLT               (1<<O_FAF_CLT_BIT_NR)
#define O_FAF_SRV               (1<<O_FAF_SRV_BIT_NR)
#define O_HCC_SHARED            (1<<O_HCC_SHARED_BIT_NR)
#define O_FAF_TTY               (1<<O_FAF_TTY_BIT_NR)

/* Mask for HCC O flags */
#define O_HCC_FLAGS             (O_FAF_CLT|O_FAF_SRV|O_HCC_SHARED|O_FAF_TTY)

#endif // __KHCC_FCNTL__
