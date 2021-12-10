/** HCC MM Server.
 *  @file mm_server.h
 *
 *  @author Innogrid HCC
 */

#ifndef __MM_SERVER__
#define __MM_SERVER__



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



typedef struct mm_mmap_msg {
	unique_id_t mm_id;
	union {
		unsigned long start;
		unsigned long brk;
		unsigned long addr;
	};
	union {
		size_t len;
		unsigned long lock_limit;
	};
	union {
		unsigned long new_len;
		unsigned long long vm_flags;
		unsigned long prot;
	};
	union {
		unsigned long flags;
		unsigned long data_limit;
		int personality;
	};
	union {
		unsigned long old_len;
		unsigned long pgoff;
	};
	unsigned long new_addr;
	unsigned long _new_addr;
} mm_mmap_msg_t;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



void mm_server_init (void);
void mm_server_finalize (void);


#endif // __MM_SERVER__
