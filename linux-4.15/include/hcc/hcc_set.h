
#ifndef __HCC_SET__
#define __HCC_SET__
#include <linux/socket.h>



enum
  {
    HCC_SET_UNUSED,                  //  0
    TASK_HCC_ID,                     //  1
    SIGNAL_STRUCT_HCC_ID,            //  2
    SIGHAND_STRUCT_HCC_ID,           //  3
    STATIC_NODE_INFO_HCC_ID,         //  4
    STATIC_CPU_INFO_HCC_ID,          //  5
    DYNAMIC_NODE_INFO_HCC_ID,        //  6
    DYNAMIC_CPU_INFO_HCC_ID,         //  7
    APP_HCC_ID,                      //  8
    SHMID_HCC_ID,                    //  9
    SHMKEY_HCC_ID,                   // 10
    SHMMAP_HCC_ID,                   // 11
    SEMARRAY_HCC_ID,                 // 12
    SEMKEY_HCC_ID,                   // 13
    SEMMAP_HCC_ID,                   // 14
    SEMUNDO_HCC_ID,                  // 15
    MSG_HCC_ID,                      // 16
    MSGKEY_HCC_ID,                   // 17
    MSGMAP_HCC_ID,                   // 18
    MSGMASTER_HCC_ID,                // 19
    PID_HCC_ID,                      // 20
    CHILDREN_HCC_ID,                 // 21
    DVFS_FILE_STRUCT_HCC_ID,         // 22
    GLOBAL_LOCK_HCC_SET_ID,	      // 23
    GLOBAL_CONFIG_HCC_SET_ID,        // 24
    HCC_TEST4_DIST,                  // 25
    HCC_TEST4_LOC,                   // 26
    HCC_TEST4096,                    // 27
    MM_STRUCT_HCC_ID,                // 28
    PIDMAP_MAP_HCC_ID,               // 29
    MIN_HCC_ID,           /* MUST always be the last one */
  };

typedef struct {
	int ns_id;                 
	hcc_set_id_t set_id;      
} hcc_id_msg_t;



#endif