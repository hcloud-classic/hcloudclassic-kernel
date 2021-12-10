/** GDM gdm interface.
 *  @file gdm_set.h
 *
 *  Definition of GDM set interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_SET__
#define __GDM_SET__

#include <linux/socket.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>
#include <hcc/hcc_syms.h>

#include <gdm/gdm_types.h>
#include <gdm/name_space.h>
#include <gdm/gdm_tree.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                             MACRO CONSTANTS                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/* GDM set state */
enum
  {
    GDM_SET_UNINITIALIZED,
    GDM_SET_NEED_LOOKUP,
    GDM_SET_INVALID,
    GDM_SET_LOCKED,
    GDM_SET_READY,
  };



#define GDM_ALLOC_STRUCT 1
#define GDM_CHECK_UNIQUE 2
#define GDM_LOCK_FREE 4


/** Return the manager id of the given gdm set */
#define GDM_SET_MGR(set) ((hcc_node_t)(set->id >> UNIQUE_ID_NODE_SHIFT))

#define MAX_PRIVATE_DATA_SIZE (PAGE_SIZE-sizeof(msg_gdm_set_t))

/** Default size of a gdm set hash table */
#define GDM_SET_HASH_TABLE_SIZE 1024

/** Default size for readahead windows */
#define DEFAULT_READAHEAD_WINDOW_SIZE 8

/* Kddm set with round robin distributed default owner */
#define GDM_RR_DEF_OWNER ((hcc_node_t)(HCC_MAX_NODES + 1))

/* Kddm set with default owner based on unique ID */
#define GDM_UNIQUE_ID_DEF_OWNER ((hcc_node_t)(HCC_MAX_NODES + 2))

/* Kddm set with a custom default owner policy */
#define GDM_CUSTOM_DEF_OWNER ((hcc_node_t)(HCC_MAX_NODES + 3))

/* MUST ALWAYS BE THE LAST ONE and equal to the highest possible value */
#define GDM_MAX_DEF_OWNER ((hcc_node_t)(HCC_MAX_NODES + 4))

/* Kddm set id reserved for internal system usage (sys_gdm_ns name space). */
enum
  {
    GDM_SET_UNUSED,                  //  0
    TASK_GDM_ID,                     //  1
    SIGNAL_STRUCT_GDM_ID,            //  2
    SIGHAND_STRUCT_GDM_ID,           //  3
    STATIC_NODE_INFO_GDM_ID,         //  4
    STATIC_CPU_INFO_GDM_ID,          //  5
    DYNAMIC_NODE_INFO_GDM_ID,        //  6
    DYNAMIC_CPU_INFO_GDM_ID,         //  7
    APP_GDM_ID,                      //  8
    SHMID_GDM_ID,                    //  9
    SHMKEY_GDM_ID,                   // 10
    SHMMAP_GDM_ID,                   // 11
    SEMARRAY_GDM_ID,                 // 12
    SEMKEY_GDM_ID,                   // 13
    SEMMAP_GDM_ID,                   // 14
    SEMUNDO_GDM_ID,                  // 15
    MSG_GDM_ID,                      // 16
    MSGKEY_GDM_ID,                   // 17
    MSGMAP_GDM_ID,                   // 18
    MSGMASTER_GDM_ID,                // 19
    PID_GDM_ID,                      // 20
    CHILDREN_GDM_ID,                 // 21
    DVFS_FILE_STRUCT_GDM_ID,         // 22
    GLOBAL_LOCK_GDM_SET_ID,	      // 23
    GLOBAL_CONFIG_GDM_SET_ID,        // 24
    GDM_TEST4_DIST,                  // 25
    GDM_TEST4_LOC,                   // 26
    GDM_TEST4096,                    // 27
    MM_STRUCT_GDM_ID,                // 28
    PIDMAP_MAP_GDM_ID,               // 29
    MIN_GDM_ID,           /* MUST always be the last one */
  };



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** gdm set manager message type.
 *  Used to store informations to sent to the GDM set manager server.
 */
typedef struct {
	int gdm_ns;               /**< GDM name space identifier */
	gdm_set_id_t gdm_set_id; /**< GDM set identifier */
	unsigned long flags;       /**< Kddm Set flags */
	hcc_node_t link;     /**< Node linked to the gdm set */
	int obj_size;              /**< Size of objects stored in gdm set */
	iolinker_id_t linker_id;   /**< Identifier of the io linker  */
	unsigned long data_size;   /**< Size of set private data to receive */
	hcc_syms_val_t set_ops;     /**< GDM set operations struct ID */
	char private_data[1];
} msg_gdm_set_t;



typedef struct {
	int ns_id;                   /**< GDM name space identifier */
	gdm_set_id_t set_id;        /**< GDM set identifier */
} gdm_id_msg_t;



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



void gdm_set_init(void);
void gdm_set_finalize(void);

struct gdm_set *__create_new_gdm_set(struct gdm_ns *ns,
				       gdm_set_id_t gdm_set_id,
				       struct gdm_set_ops *set_ops,
				       void *tree_init_data,
				       iolinker_id_t linker_id,
				       hcc_node_t def_owner,
				       int obj_size,
				       void *private_data,
				       unsigned long data_size,
				       unsigned long flags);

static inline struct gdm_set *_create_new_gdm_set(struct gdm_ns *ns,
				       gdm_set_id_t gdm_set_id,
				       iolinker_id_t linker_id,
				       hcc_node_t def_owner,
				       int obj_size,
				       void *private_data,
				       unsigned long data_size,
				       unsigned long flags)
{
	return (struct gdm_set *) __create_new_gdm_set(ns, gdm_set_id,
						 &gdm_tree_set_ops,
						 _nlevels_gdm_tree_init_data,
						 linker_id, def_owner,
						 obj_size, private_data,
						 data_size, flags);
}

static inline struct gdm_set *create_new_gdm_set(struct gdm_ns *ns,
				       gdm_set_id_t gdm_set_id,
				       iolinker_id_t linker_id,
				       hcc_node_t def_owner,
				       int obj_size,
				       unsigned long flags)
{
	return (struct gdm_set *) __create_new_gdm_set(ns, gdm_set_id,
						 &gdm_tree_set_ops,
						 _nlevels_gdm_tree_init_data,
						 linker_id, def_owner,
						 obj_size, NULL, 0, flags);
}

int _destroy_gdm_set(struct gdm_set * gdm_set);
int destroy_gdm_set(struct gdm_ns *ns, gdm_set_id_t set_id);

struct gdm_set *__find_get_gdm_set(struct gdm_ns *ns,
				     gdm_set_id_t gdm_set_id,
				     int flags);

static inline struct gdm_set *_find_get_gdm_set(struct gdm_ns *ns,
						  gdm_set_id_t gdm_set_id)
{
	return __find_get_gdm_set(ns, gdm_set_id, 0);
}

struct gdm_set *find_get_gdm_set(int ns_id,
				   gdm_set_id_t set_id);

struct gdm_set *generic_local_get_gdm_set(int ns_id,
					     gdm_set_id_t set_id,
					     int init_state,
					     int flags);

struct gdm_set *_generic_local_get_gdm_set(struct gdm_ns *ns,
					     gdm_set_id_t set_id,
					     int init_state,
					     int flags);

/** Different flavors of the get_gdm_set function */

static inline struct gdm_set *_local_get_gdm_set(struct gdm_ns *ns,
						   gdm_set_id_t set_id)
{
	return _generic_local_get_gdm_set(ns, set_id, 0, 0);
}

static inline struct gdm_set *_local_get_alloc_gdm_set(struct gdm_ns *ns,
							 gdm_set_id_t set_id,
							 int init_state)
{
	return _generic_local_get_gdm_set(ns, set_id, init_state,
					   GDM_ALLOC_STRUCT);
}

static inline struct gdm_set *local_get_gdm_set(int ns_id,
						  gdm_set_id_t set_id)
{
	return generic_local_get_gdm_set(ns_id, set_id, 0, 0);
}

static inline struct gdm_set *local_get_alloc_gdm_set(int ns_id,
							gdm_set_id_t set_id,
							int init_state)
{
	return generic_local_get_gdm_set(ns_id, set_id, init_state,
					  GDM_ALLOC_STRUCT);
}

static inline struct gdm_set *_local_get_alloc_unique_gdm_set(
	                                          struct gdm_ns *ns,
						  gdm_set_id_t set_id,
						  int init_state)
{
	return _generic_local_get_gdm_set(ns, set_id, init_state,
					   GDM_ALLOC_STRUCT |
					   GDM_CHECK_UNIQUE);

}

void put_gdm_set(struct gdm_set *set);

static inline int gdm_set_frozen(struct gdm_set *set)
{
	return (set->flags & GDM_FROZEN);
}

void freeze_gdm(void);
void unfreeze_gdm(void);

#endif // __GDM_NS__
