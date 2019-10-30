#ifndef __SEMARRAY_IO_LINKER__
#define __SEMARRAY_IO_LINKER__


extern struct kmem_cache *semarray_object_cachep;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


typedef struct semarray_object {
	struct sem_array imported_sem;
	struct sem_array *local_sem;
	struct sem* mobile_sem_base;
} semarray_object_t;


extern struct iolinker_struct semarray_linker;
extern struct iolinker_struct semkey_linker;

#define remote_sleeper_pid(q) ((pid_t)((long)(q->sleeper)))

#endif
