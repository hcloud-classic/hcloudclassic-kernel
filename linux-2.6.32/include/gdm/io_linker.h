/** GDM IO linker interface.
 *  @file io_linker.h
 *
 *  Create link between GDM and io linkers.
 *  @author Innogrid HCC
 */

#ifndef __IO_LINKER__
#define __IO_LINKER__

#include <hcc/hcc_nodemask.h>
#include <hcc/hcc_init.h>
#include <hcc/sys/types.h>

#include <gdm/gdm_types.h>
#include <gdm/object.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                 MACROS                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** IO linker types  */

enum
  {
    MEMORY_LINKER,
    FILE_LINKER,
    DIR_LINKER,
    SHM_MEMORY_LINKER,
    INODE_LINKER,
    FILE_STRUCT_LINKER,
    TASK_LINKER,
    SIGNAL_STRUCT_LINKER,
    SIGHAND_STRUCT_LINKER,
    STATIC_NODE_INFO_LINKER,
    STATIC_CPU_INFO_LINKER,
    DYNAMIC_NODE_INFO_LINKER,
    DYNAMIC_CPU_INFO_LINKER,
    STREAM_LINKER,
    SOCKET_LINKER,
    APP_LINKER,
    FUTEX_LINKER,
    IPCMAP_LINKER,
    SHMID_LINKER,
    SHMKEY_LINKER,
    SEMARRAY_LINKER,
    SEMUNDO_LINKER,
    SEMKEY_LINKER,
    MSG_LINKER,
    MSGKEY_LINKER,
    MSGMASTER_LINKER,
    DSTREAM_LINKER,
    DSOCKET_LINKER,
    PID_LINKER,
    CHILDREN_LINKER,
    DVFS_FILE_STRUCT_LINKER,
    GLOBAL_LOCK_LINKER,
    STRING_LIST_LINKER,
    GDM_TEST_LINKER,
    MM_STRUCT_LINKER,
    PIDMAP_MAP_LINKER,
    MAX_IO_LINKER, /* MUST always be the last one */
  } ;



#define GDM_IO_KEEP_OBJECT 1



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/



struct grpc_desc;

/** IO linker struct
 *  Describe IO linker interface functions, name, etc.
 */

struct iolinker_struct {
  int (*instantiate) (struct gdm_set * set, void *private_data, int master);
  void (*uninstantiate) (struct gdm_set * set, int destroy);
  int (*first_touch) (struct gdm_obj * obj_entry, struct gdm_set * set,
		      objid_t objid, int flags);
  int (*remove_object) (void *object, struct gdm_set * set,
                        objid_t objid);
  int (*invalidate_object) (struct gdm_obj * obj_entry, struct gdm_set * set,
                            objid_t objid);
  int (*flush_object) (struct gdm_obj * obj_entry, struct gdm_set * set,
		       objid_t objid);
  int (*insert_object) (struct gdm_obj * obj_entry, struct gdm_set * set,
                        objid_t objid);
  int (*put_object) (struct gdm_obj * obj_entry, struct gdm_set * set,
		     objid_t objid);
  int (*sync_object) (struct gdm_obj * obj_entry, struct gdm_set * set,
                      objid_t objid);
  void (*change_state) (struct gdm_obj * obj_entry, struct gdm_set * set,
                         objid_t objid, gdm_obj_state_t state);
  int (*alloc_object) (struct gdm_obj * obj_entry, struct gdm_set * set,
                       objid_t objid);
  int (*import_object) (struct grpc_desc *desc, struct gdm_set *set,
			struct gdm_obj *obj_entry, objid_t objid, int flags);
  int (*export_object) (struct grpc_desc *desc, struct gdm_set *set,
			struct gdm_obj *obj_entry, objid_t objid, int flags);
  hcc_node_t (*default_owner) (struct gdm_set * set, objid_t objid,
                                     const hcc_nodemask_t * nodes, int nr_nodes);
  char linker_name[16];
  iolinker_id_t linker_id;
};



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Initialize IO linkers.
 *  @author Innogrid HCC
 */
void io_linker_init (void);
void io_linker_finalize (void);



/** Register a new gdm IO linker.
 *  @author Innogrid HCC
 *
 *  @param io_linker_id
 *  @param linker
 */
int register_io_linker (int linker_id, struct iolinker_struct *io_linker);



/** Instantiate a gdm set.
 *  @author Innogrid HCC
 *
 *  @param set           GDM set to instantiate
 *  @param link          Node linked to the gdm set
 *  @param iolinker_id   Id of the iolinker to link to the gdm set
 *  @param private_data  Data used by the instantiator...
 *
 *  @return error code or 0 if everything ok.
 */
int gdm_io_instantiate (struct gdm_set * set, hcc_node_t link,
			 iolinker_id_t iolinker_id, void *private_data,
			 int data_size, int master);



/** Uninstantiate a GDM set.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm set to uninstantiate
 */
void gdm_io_uninstantiate (struct gdm_set * set, int destroy);



/** Do an object first touch.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to first touch.
 *  @param obj_entry    Object entry the object belong to.
 *  @param objectState  Initial state of the object.
 */
int gdm_io_first_touch_object (struct gdm_obj * obj_entry,
				struct gdm_set * set, objid_t objid,
				int flags);



/** Put a GDM object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to put.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_put_object (struct gdm_obj * obj_entry, struct gdm_set * set,
                        objid_t objid);



/** Insert an object in a gdm set.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to insert.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_insert_object (struct gdm_obj * obj_entry, struct gdm_set * set,
                           objid_t objid);



/** Request an IO linker to invalidate an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to invalidate.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_invalidate_object (struct gdm_obj * obj_entry, struct gdm_set * set,
                               objid_t objid);



/** Request an IO linker to remove an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to remove.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_remove_object_and_unlock (struct gdm_obj * obj_entry, struct gdm_set * set,
				      objid_t objid);

int gdm_io_remove_object (void *object, struct gdm_set * set, objid_t objid);



/** Request an IO linker to sync an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param obj_entry    Object entry the object belong to.
 */
int gdm_io_sync_object (struct gdm_obj * obj_entry, struct gdm_set * set,
                         objid_t objid);



/** Inform an IO linker that an object state has changed.
 *  @author Innogrid HCC
 *
 *  @param obj_entry    Object entry the object belong to.
 *  @param set          Kddm Set the object belong to.
 *  @param objid        Id of the object to sync.
 *  @param new_state    New state for the object.
 */
int gdm_io_change_state (struct gdm_obj * obj_entry,
			  struct gdm_set * set,
			  objid_t objid,
			  gdm_obj_state_t new_state);



/** Request an IO linker to import data into an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to import data into.
 *  @param buffer       Buffer containing data to import.
 */
int gdm_io_import_object (struct grpc_desc *desc, struct gdm_set *set,
			   struct gdm_obj *obj_entry, objid_t objid,
			   int flags);

/** Request an IO linker to export data from an object.
 *  @author Innogrid HCC
 *
 *  @param set          Kddm Set the object belong to.
 *  @param obj_entry    Object entry to export data from.
 *  @param buffer       Buffer to export data to.
 */
int gdm_io_export_object (struct grpc_desc *desc, struct gdm_set *set,
			   struct gdm_obj *obj_entry, objid_t objid,
			   int flags);
hcc_node_t gdm_io_default_owner (struct gdm_set * set, objid_t objid);

/** Request an IO linker to allocate an object.
 *  @author Innogrid HCC
 *
 *  @param obj_entry   Object entry to export data from.
 *  @param set         Kddm Set the object belong to.
 */
int gdm_io_alloc_object (struct gdm_obj * obj_entry, struct gdm_set * set,
			  objid_t objid);

#endif // __IO_LINKER__
