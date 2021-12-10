/** Definition and management of gdm objects.
 *  @file object.h
 *
 *  @author Innogrid HCC
 */

#ifndef __GDM_OBJECT__
#define __GDM_OBJECT__

#include <linux/highmem.h>

#include <gdm/gdm_types.h>
#include <gdm/gdm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                   MACROS                                 *
 *                                                                          *
 *--------------------------------------------------------------------------*/

/** Object states used for the coherence protocol */

typedef enum {
	INV_COPY = 0,
	READ_COPY =         1 << STATE_INDEX_SHIFT | GDM_READ_OBJ,

	INV_OWNER =         2 << STATE_INDEX_SHIFT | GDM_OWNER_OBJ,
	READ_OWNER =        3 << STATE_INDEX_SHIFT | GDM_OWNER_OBJ | GDM_READ_OBJ,
	WRITE_OWNER =       4 << STATE_INDEX_SHIFT | GDM_OWNER_OBJ | GDM_READ_OBJ | GDM_WRITE_OBJ,
	WRITE_GHOST =       5 << STATE_INDEX_SHIFT | GDM_OWNER_OBJ | GDM_READ_OBJ | GDM_WRITE_OBJ,

	WAIT_ACK_INV =      6 << STATE_INDEX_SHIFT | GDM_OWNER_OBJ | GDM_READ_OBJ,
	WAIT_ACK_WRITE =    7 << STATE_INDEX_SHIFT | GDM_OWNER_OBJ | GDM_READ_OBJ,
	WAIT_CHG_OWN_ACK =  8 << STATE_INDEX_SHIFT | GDM_READ_OBJ,

	WAIT_OBJ_READ =    10 << STATE_INDEX_SHIFT,
	WAIT_OBJ_WRITE =   11 << STATE_INDEX_SHIFT,

	WAIT_OBJ_RM_DONE = 13 << STATE_INDEX_SHIFT,
	WAIT_OBJ_RM_ACK =  14 << STATE_INDEX_SHIFT,
	WAIT_OBJ_RM_ACK2 = 15 << STATE_INDEX_SHIFT,

	INV_FILLING =      16 << STATE_INDEX_SHIFT,

	NB_OBJ_STATE =     17 /* MUST always be the last one */
} gdm_obj_state_t;

/************************** Copyset management **************************/

/** Get the copyset */
#define COPYSET(obj_entry) (&(obj_entry)->master_obj.copyset)
#define RMSET(obj_entry) (&(obj_entry)->master_obj.rmset)

/** Clear the copyset */
#define CLEAR_SET(set) __hcc_nodes_clear(set)

/** Duplicate the copyset */
#define DUP2_SET(set, v) __hcc_nodes_copy(v, set)

/** Tests the presence of a node in the copyset */
#define NODE_IN_SET(set,nodeid) __hcc_node_isset(nodeid, set)

/** Tests if local node is the object owner */

#define I_AM_OWNER(obj_entry) ((obj_entry)->flags & GDM_OWNER_OBJ)

/** Tests if the copyset is empty */
#define SET_IS_EMPTY(set) __hcc_nodes_empty(set)

/** Tests if the local node own the exclusive copy of the object */
#define OBJ_EXCLUSIVE(obj_entry) (hcc_node_is_unique(hcc_node_id, (obj_entry)->master_obj.copyset) || \
				  hcc_node_is_unique(get_prob_owner(obj_entry), (obj_entry)->master_obj.copyset))

#define OBJ_EXCLUSIVE2(set) (__hcc_node_is_unique(hcc_node_id, set))

/** Add a node in the copyset */
#define ADD_TO_SET(set,nodeid) __hcc_node_set(nodeid, set)

/** Remove a node from the copyset */
#define REMOVE_FROM_SET(set,nodeid) __hcc_node_clear(nodeid, set)

#define I_AM_DEFAULT_OWNER(set, objid) \
        (hcc_node_id == gdm_io_default_owner(set, objid))

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                            EXTERN VARIABLES                              *
 *                                                                          *
 *--------------------------------------------------------------------------*/



extern atomic_t nr_master_objects;  /*< Number of local master objects */
extern atomic_t nr_copy_objects;    /*< Number of local copy objects */
extern atomic_t nr_OBJ_STATE[]; /*< Number of objects in each possible state */
extern const char *state_name[]; /*< Printable state name */



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

#define ASSERT_OBJ_PATH_LOCKED(set, objid) assert_spin_locked(&(set)->obj_lock[(objid) % NR_OBJ_ENTRY_LOCKS])

/** Lock the object (take care about the interrupt context) **/
static inline void gdm_obj_path_lock (struct gdm_set *set,
				       objid_t objid)
{
	spinlock_t *lock = &set->obj_lock[objid % NR_OBJ_ENTRY_LOCKS];

	if (irqs_disabled ())
		spin_lock (lock);
	else
		spin_lock_bh (lock);
}

static inline void gdm_obj_path_unlock (struct gdm_set *set,
					 objid_t objid)
{
	spinlock_t *lock = &set->obj_lock[objid % NR_OBJ_ENTRY_LOCKS];

	if (irqs_disabled ())
		spin_unlock (lock);
	else
		spin_unlock_bh (lock);
}



/** Alloc a new GDM obj entry structure.
 *  @author Innogrid HCC
 *
 *  @param set     Kddm set to create an object for.
 *  @param objid   Id of the object to create.
 */
struct gdm_obj *alloc_gdm_obj_entry(struct gdm_set *set,
				      objid_t objid);

/** Duplicate a GDM obj entry structure.
 *  @author Innogrid HCC
 *
 *  @param src_obj   The object entry to duplicate
 */
struct gdm_obj *dup_gdm_obj_entry(struct gdm_obj *src_obj);

/** Free GDM obj entry structure.
 *  @author Innogrid HCC
 *
 *  @param set        The set the object belongs to.
 *  @param obj_entry  The structure to free
 *  @param objid      Id of the object to free.
 */
void free_gdm_obj_entry(struct gdm_set *set,
			 struct gdm_obj *obj_entry,
			 objid_t objid);

static inline void put_obj_entry_count(struct gdm_set *set,
					 struct gdm_obj *obj_entry,
					 objid_t objid)
{
	if (atomic_dec_and_test(&obj_entry->count))
		free_gdm_obj_entry(set, obj_entry, objid);
}

static inline int obj_entry_count(struct gdm_obj *obj_entry)
{
        return atomic_read(&obj_entry->count);
}

/** Lookup for an object entry in a gdm set.
 *  @author Innogrid HCC
 *
 *  @param gdm_set    Kddm set to lookup the object in.
 *  @param objid       Id of the object to lookup for.
 *
 *  @return        Object entry of the object or NULL if the object entry does
 *                 not exist.
 */
struct gdm_obj *__get_gdm_obj_entry (struct gdm_set *gdm_set,
				       objid_t objid);

static inline struct gdm_obj *_get_gdm_obj_entry (struct gdm_ns *ns,
						    gdm_set_id_t set_id,
						    objid_t objid,
						    struct gdm_set **gdm_set)
{
	struct gdm_obj *obj = NULL;

	*gdm_set = _find_get_gdm_set (ns, set_id);
	if (*gdm_set) {
		obj = __get_gdm_obj_entry (*gdm_set, objid);
		put_gdm_set(*gdm_set);
	}
	return obj;
}

static inline struct gdm_obj *get_gdm_obj_entry (int ns_id,
						   gdm_set_id_t set_id,
						   objid_t objid,
						   struct gdm_set **gdm_set)
{
	struct gdm_obj *obj = NULL;

	*gdm_set = find_get_gdm_set (ns_id, set_id);
	if (*gdm_set) {
		obj = __get_gdm_obj_entry (*gdm_set, objid);
		put_gdm_set(*gdm_set);
	}
	return obj;
}

static inline void put_gdm_obj_entry (struct gdm_set *set,
				       struct gdm_obj *obj_entry,
				       objid_t objid)
{
	if (obj_entry)
		CLEAR_OBJECT_LOCKED(obj_entry);

	gdm_obj_path_unlock (set, objid);
}

struct gdm_obj *default_get_gdm_obj_entry (struct gdm_set *set,
					     objid_t objid);



/** Lookup for an object entry in a gdm set and create it if necessary
 *  @author Innogrid HCC
 *
 *  @param gdm_set    Kddm set to lookup the object in.
 *  @param objid       Id of the object to lookup for.
 *
 *  @return        Object entry of the object. If the object does not exist,
 *                 it is allocated
 */
struct gdm_obj *__get_alloc_gdm_obj_entry (struct gdm_set *gdm_set,
					     objid_t objid);

static inline struct gdm_obj *get_alloc_gdm_obj_entry (int ns_id,
							 gdm_set_id_t set_id,
							 objid_t objid,
							 struct gdm_set **gdm_set)
{
	struct gdm_obj *obj = NULL;

	*gdm_set = find_get_gdm_set (ns_id, set_id);
	if (*gdm_set) {
		obj = __get_alloc_gdm_obj_entry (*gdm_set, objid);
		put_gdm_set(*gdm_set);
	}
	return obj;
}

static inline struct gdm_obj *_get_alloc_gdm_obj_entry (struct gdm_ns *ns,
							  gdm_set_id_t set_id,
							  objid_t objid,
							  struct gdm_set **gdm_set)
{
	struct gdm_obj *obj = NULL;

	*gdm_set = _find_get_gdm_set (ns, set_id);
	if (*gdm_set) {
		obj = __get_alloc_gdm_obj_entry (*gdm_set, objid);
		put_gdm_set(*gdm_set);
	}
	return obj;
}



int destroy_gdm_obj_entry (struct gdm_set *gdm_set,
			    struct gdm_obj *obj_entry,
			    objid_t objid,
			    int cluster_wide_remove);

void __for_each_gdm_object(struct gdm_set *gdm_set,
			    int(*f)(unsigned long, void *, void*),
			    void *data);

void for_each_gdm_object(int ns_id, gdm_set_id_t set_id,
			  int(*f)(unsigned long, void*, void*),
			  void *data);

/** Insert a new object frame in a gdm set.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm set to insert object in.
 *  @param objid        Id of the object to insert.
 *  @param state        State of the object to insert.
 */
void gdm_insert_object (struct gdm_set *set, objid_t objid,
                         struct gdm_obj * obj_entry,
			 gdm_obj_state_t state);

static inline struct gdm_obj *gdm_break_cow_object (struct gdm_set * set,
					      struct gdm_obj *obj_entry,
					      objid_t objid,
					      int break_type)
{
	if (set->ops->break_cow)
		return set->ops->break_cow (set, obj_entry, objid, break_type);
	return obj_entry;
}


/** Change a gdm object state.
 *  @author Innogrid HCC
 *
 *  @param gdm_set   Kddm set hosting the object.
 *  @param obj_entry  Structure of the object.
 *  @param objid      Id of the object to modify state.
 *  @param new_state  New state of the object.
 */
void gdm_change_obj_state(struct gdm_set * gdm_set,
			   struct gdm_obj *obj_entry,
			   objid_t objid,
			   gdm_obj_state_t newState);


/** Invalidate a object frame from a gdm set.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to invalidate.
 *  @param set        Kddm set hosting the object.
 *  @param objid      Id of the object to invalidate.
 */
void gdm_invalidate_local_object_and_unlock (struct gdm_obj *obj_entry,
					      struct gdm_set *set,
					      objid_t objid,
					      gdm_obj_state_t state);



/** Indicate if an object is frozen, ie if it should not be modified.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to test.
 */
int object_frozen (struct gdm_obj * obj_entry, struct gdm_set *set);

int object_frozen_or_pinned (struct gdm_obj * obj_entry,
			     struct gdm_set * set);



/** Freeze the given object.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to freeze.
 */
void set_object_frozen (struct gdm_obj * obj_entry, struct gdm_set *set);



/** Object clear Frozen.
 *  @author Innogrid HCC
 *
 *  @param obj_entry  Entry of the object to warm.
 */
void object_clear_frozen (struct gdm_obj * obj_entry, struct gdm_set *set);



static inline int change_prob_owner(struct gdm_obj * obj_entry,
				     hcc_node_t new_owner)
{
	if (obj_entry)
		obj_entry->flags = (obj_entry->flags & ~PROB_OWNER_MASK) |
			(new_owner << PROB_OWNER_SHIFT);
	return 0;
}



static inline hcc_node_t get_prob_owner (struct gdm_obj *obj_entry)
{
	if (likely(obj_entry))
		return (obj_entry->flags & PROB_OWNER_MASK) >>PROB_OWNER_SHIFT;
	else
		return HCC_NODE_ID_NONE;
}



/** Unlock, and make a process sleep until the corresponding
 *  object is received.
 *  @author Innogrid HCC
 *
 *  @param  set        The gdm set the object belong to.
 *  @param  obj_entry  The object to wait for.
 *  @param  objid      Id of the object.
 */
void __sleep_on_gdm_obj (struct gdm_set *set,
			  struct gdm_obj *obj_entry,
			  objid_t objid,
			  int flags);

static inline void sleep_on_gdm_obj (struct gdm_set *set,
				      struct gdm_obj *obj_entry,
				      objid_t objid,
				      int flags)
{
	__sleep_on_gdm_obj (set, obj_entry, objid, flags);
}

int check_sleep_on_local_exclusive (struct gdm_set *set,
				    struct gdm_obj *obj_entry,
				    objid_t objid,
				    int flags);


/** Wake up the process waiting for the object.
 *  @author Innogrid HCC
 *
 *  @param  obj_entry  The object to wake up waiting process.
 */
static inline void wake_up_on_wait_object (struct gdm_obj *obj_entry,
                                           struct gdm_set *set)
{
	if (atomic_read (&obj_entry->sleeper_count))
		SET_OBJECT_PINNED (obj_entry);
	wake_up (&obj_entry->waiting_tsk);
}

int init_gdm_objects (void);

#endif // __GDM_OBJECT__
