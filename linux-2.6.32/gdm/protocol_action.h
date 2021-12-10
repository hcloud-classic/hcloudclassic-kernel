/** Basic coherence protocol actions.
 *  @file protocol_action.h
 *
 *  @author Innogrid HCC
 */

#ifndef __PROTOCOL_ACTION__
#define __PROTOCOL_ACTION__

typedef int (*queue_event_handler_t) (hcc_node_t sender, void* msg);



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Send object invalidation requests.
 *  @author Innogrid HCC
 */
void request_copies_invalidation (struct gdm_set *set,
				  struct gdm_obj *obj_entry, objid_t objid,
                                  hcc_node_t sender);

/** Send object remove requests.
 *  @author Innogrid HCC
 */
int request_copies_remove (struct gdm_set * set, struct gdm_obj *obj_entry,
			   objid_t objid, hcc_node_t sender);

/** Send object remove request to the object manager.
 *  @author Innogrid HCC
 */
void request_objects_remove_to_mgr (struct gdm_set * set,
				    struct gdm_obj * obj_entry,
				    objid_t objid);

/** Send an object write request for the given object.
 *  @author Innogrid HCC
 */
void request_object_on_write (struct gdm_set * set,
			      struct gdm_obj *obj_entry,
			      objid_t objid, int flags);

/** Send an object read request for the given object.
 *  @author Innogrid HCC
 */
void request_object_on_read (struct gdm_set * set, struct gdm_obj *obj_entry,
			     objid_t objid, int flags);

/** Send an object write copy to the given node.
 *  @author Innogrid HCC
 */
void send_copy_on_write (struct gdm_set *set, struct gdm_obj *obj_entry,
			 objid_t objid, hcc_node_t dest_node, int flags);

struct gdm_obj *send_copy_on_write_and_inv (struct gdm_set *set,
					     struct gdm_obj *obj_entry,
					     objid_t objid,
					     hcc_node_t dest_node,
					     int flags);


/** Send an object read copy to the given node.
 *  @author Innogrid HCC
 */
int send_copy_on_read (struct gdm_set *set, struct gdm_obj *obj_entry,
		       objid_t objid, hcc_node_t dest_node, int flags);

/** Send a "no object" anwser to the given node.
 *  @author Innogrid HCC
 */
void send_no_object (struct gdm_set * set, struct gdm_obj *obj_entry,
		     objid_t objid, hcc_node_t dest_node,
		     int send_ownership);

/** Send object write access to the given node.
 *  @author Innogrid HCC
 */
void transfer_write_access_and_unlock (struct gdm_set *set,
                                       struct gdm_obj *obj_entry,
				       objid_t objid,
				       hcc_node_t dest_node,
				       masterObj_t * master_info);

void merge_ack_set(hcc_nodemask_t *obj_set, hcc_nodemask_t *recv_set);

/** Send an object invalidation ack to the given node.
 *  @author Innogrid HCC
 */
void send_invalidation_ack (struct gdm_set *set, objid_t objid,
			    hcc_node_t dest_node);

/** Send an object remove ack to the given node.
 *  @author Innogrid HCC
 */
void send_remove_ack (struct gdm_set *set, objid_t objid,
		      hcc_node_t dest_node, int flags);
void send_remove_ack2 (struct gdm_set *set, objid_t objid,
		       hcc_node_t dest_node);

/** Send a global objects remove ack from the manager node to the given node.
 *  @author Innogrid HCC
 */
void send_remove_object_done (struct gdm_set *set, objid_t objid,
			      hcc_node_t dest_node,
			      hcc_nodemask_t *rmset);


/** Do an object first touch.
 *  @author Innogrid HCC
 */
int object_first_touch (struct gdm_set *set, struct gdm_obj *obj_entry,
			objid_t objid, gdm_obj_state_t objectState,
			int flags);
int object_first_touch_no_wakeup (struct gdm_set *set,
				  struct gdm_obj *obj_entry,objid_t objid,
                                  gdm_obj_state_t objectState, int flags);


/** Send back an object first touch request to the faulting node.
 *  @author Innogrid HCC
 */
void send_back_object_first_touch (struct gdm_set *set,
				   struct gdm_obj * obj_entry,
                                   objid_t objid, hcc_node_t dest_node,
                                   int flags, int req_type);

void send_change_ownership_req (struct gdm_set * set,
				struct gdm_obj *obj_entry, objid_t objid,
				hcc_node_t dest_node,
                                masterObj_t * master_info);

void ack_change_object_owner (struct gdm_set * set,
                              struct gdm_obj * obj_entry, objid_t objid,
			      hcc_node_t dest_node,
			      masterObj_t * master_info);

void queue_event (queue_event_handler_t event, hcc_node_t sender,
		  struct gdm_set *set, struct gdm_obj * obj_entry,
		  objid_t objid, void *dataIn, size_t data_size);

void flush_gdm_event(struct gdm_set *set, objid_t objid);
void freeze_gdm_event(struct gdm_set *set);
void unfreeze_gdm_event(struct gdm_set *set);

hcc_node_t choose_injection_node_in_copyset (struct gdm_obj * object);
hcc_node_t choose_injection_node (void);


int request_sync_object_and_unlock (struct gdm_set * set,
				    struct gdm_obj *obj_entry, objid_t objid,
				    gdm_obj_state_t new_state);


void request_change_prob_owner(struct gdm_set * set, objid_t objid,
			       hcc_node_t dest_node,
			       hcc_node_t new_owner);

void start_run_queue_thread (void);
void stop_run_queue_thread (void);

#endif // __PROTOCOL_ACTION__
