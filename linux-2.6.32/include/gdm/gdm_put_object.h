/** GDM put object.
 *  @file gdm_put_object.h
 *
 *  Definition of GDM interface.
 *  @author Innogrid HCC
 */

#ifndef __GDM_PUT_OBJECT__
#define __GDM_PUT_OBJECT__

#include <gdm/gdm_set.h>



/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/



/** Release a gdm object acquired by a find, get or grab object. */

void gdm_put_object(struct gdm_ns *ns, gdm_set_id_t set_id, objid_t objid);

void _gdm_put_object(struct gdm_set *set, objid_t objid);

#endif
