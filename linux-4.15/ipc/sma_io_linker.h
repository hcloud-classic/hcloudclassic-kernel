#ifndef __SEMARRAY_IO_LINKER__
#define __SEMARRAY_IO_LINKER__

#include <linux/types.h>

typedef struct semarray_object {
	struct sem_array imported_sem;
	struct sem_array *local_sem;
	struct sem* mobile_sem_base;
} semarray_object_t;

#endif
