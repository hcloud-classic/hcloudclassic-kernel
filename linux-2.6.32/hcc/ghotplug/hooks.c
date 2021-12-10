/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#define MODULE_NAME "Hotplug"

#include <linux/semaphore.h>
#include <linux/sched.h>
#include <linux/hcc_hashtable.h>

#define GHOTPLUG_MAX_HOOKS 256

static struct {
	void (**hook) (void);
	void *fct;
} hooks_table[GHOTPLUG_MAX_HOOKS];

static int hooks_index;
static DECLARE_MUTEX (hooks_lock);

void hook_register(void (**hk) (void), void *f)
{

	BUG_ON(hooks_index >= GHOTPLUG_MAX_HOOKS);
	BUG_ON(hk == NULL);

	down(&hooks_lock);

	hooks_table[hooks_index].hook = hk;
	hooks_table[hooks_index].fct = f;

	hooks_index++;
	up(&hooks_lock);
}

void hooks_start(void)
{
	int i;

	down(&hooks_lock);
	for (i = 0; i < hooks_index; i++) {
		*(hooks_table[i].hook) = hooks_table[i].fct;
	}
}

void hooks_stop(void)
{
	int i;
	
	for(i = 0; i < hooks_index; i++){
		*(hooks_table[i].hook) = NULL;
	}
	up(&hooks_lock);
}

int ghotplug_hooks_init(void)
{
	hooks_index = 0;
	return 0;
}

void ghotplug_hooks_cleanup(void)
{
}
