#ifndef __MSGID_IO_LINKER__
#define __MSGID_IO_LINKER__


extern struct kmem_cache *msq_object_cachep;

typedef struct msq_object {
	struct msg_queue mobile_msq;
	struct msg_queue *local_msq;
} msq_object_t;


extern struct iolinker_struct msq_linker;
extern struct iolinker_struct msqkey_linker;
extern struct iolinker_struct msqmaster_linker;

#endif
