#ifndef __STRING_LIST_H__
#define __STRING_LIST_H__

#include <gdm/gdm_types.h>

struct gdm_set;
struct string_list_object;

struct string_list_object *
string_list_create_writelock(struct gdm_set *gdm_set, objid_t objid);
struct string_list_object *string_list_writelock(struct gdm_set *gdm_set,
						 objid_t objid);
void string_list_unlock(struct gdm_set *gdm_set,
			struct string_list_object *object);
void string_list_unlock_and_destroy(struct gdm_set *gdm_set,
				    struct string_list_object *object);

int string_list_add_element(struct string_list_object *object,
			    const char *element);
int string_list_remove_element(struct string_list_object *object,
			       const char *element);
int string_list_is_element(struct string_list_object *object,
			   const char *element);
int string_list_empty(struct string_list_object *object);

#endif /* __STRING_LIST_H__ */
