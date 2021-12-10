/** GDM name space interface.
 *  @file name_space.h
 *
 *  Definition of GDM name space interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_NS__
#define __GDM_NS__

#include <linux/unique_id.h>
#include <linux/hcc_hashtable.h>
#include <gdm/gdm_types.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



struct gdm_ns;

typedef struct gdm_ns_ops {
	struct gdm_set *(*gdm_set_lookup)(struct gdm_ns *ns,
					    gdm_set_id_t set_id);
} gdm_ns_ops_t;

typedef struct gdm_ns {
	atomic_t count;
	struct semaphore table_sem;
	hashtable_t *gdm_set_table;
	unique_id_root_t gdm_set_unique_id_root;
	struct gdm_ns_ops *ops;
	void *private;
	int id;
} gdm_ns_t;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN VARIABLES                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



#define GDM_DEF_NS_ID 0

extern struct gdm_ns *gdm_def_ns;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



void gdm_ns_init(void);
void gdm_ns_finalize(void);


struct gdm_ns * create_gdm_ns(int ns_id, void *private,
				struct gdm_ns_ops *ops);
int remove_gdm_ns(int ns_id);

struct gdm_ns *gdm_ns_get(int ns_id);
void gdm_ns_put(struct gdm_ns *ns);


#endif // __GDM_NS__
