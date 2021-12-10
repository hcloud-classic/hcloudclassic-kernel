/*
 *  hcc/gscheduler/hashed_string_list.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/string.h>
#include <gdm/gdm.h>

#include "string_list.h"

struct gdm_set *hashed_string_list_create(gdm_set_id_t gdm_set_id)
{
	return create_new_gdm_set(gdm_def_ns, gdm_set_id,
				   STRING_LIST_LINKER,
				   GDM_RR_DEF_OWNER,
				   0,
				   GDM_LOCAL_EXCLUSIVE);
}

static unsigned long get_hash(const char *string)
{
	unsigned long hash = 0;
	const char *limit = string + strlen(string) - sizeof(hash);
	const unsigned long *pos;

	for (pos = (const unsigned long *) string; (char *) pos <= limit; pos++)
		hash = hash ^ *pos;

	if ((char *) (pos - 1) < limit) {
		unsigned long last_hash = 0;

		strcpy((char *) &last_hash, (const char *) pos);
		hash = hash ^ last_hash;
	}

	return hash;
}

struct string_list_object *
hashed_string_list_lock_hash(struct gdm_set *gdm_set, const char *element)
{
	return string_list_create_writelock(gdm_set, get_hash(element));
}

void hashed_string_list_unlock_hash(struct gdm_set *gdm_set,
				    struct string_list_object *string_list)
{
	if (string_list_empty(string_list))
		string_list_unlock_and_destroy(gdm_set, string_list);
	else
		string_list_unlock(gdm_set, string_list);
}
