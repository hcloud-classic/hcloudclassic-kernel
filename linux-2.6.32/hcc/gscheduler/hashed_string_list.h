#ifndef __HASHED_STRING_LIST_H__
#define __HASHED_STRING_LIST_H__

#include <gdm/gdm_types.h>

struct gdm_set;
struct string_list_object;

struct gdm_set *hashed_string_list_create(gdm_set_id_t gdm_set_id);

struct string_list_object *
hashed_string_list_lock_hash(struct gdm_set *gdm_set, const char *element);
void hashed_string_list_unlock_hash(struct gdm_set *gdm_set,
				    struct string_list_object *string_list);

#endif /* __HASHED_STRING_LIST_H__ */
