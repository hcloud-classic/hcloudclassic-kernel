/*
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <hcc/hcc_syms.h>
#include <linux/module.h>
#include <linux/hcc_hashtable.h>
#include <linux/init.h>

/*****************************************************************************/
/*                                                                           */
/*                          HCC KSYM MANAGEMENT                        */
/*                                                                           */
/*****************************************************************************/


#define HCC_SYMS_HTABLE_SIZE 256

static hashtable_t *hcc_syms_htable;
static void* hcc_syms_table[HCC_SYMS_TABLE_SIZE];

int hcc_syms_register(enum hcc_syms_val v, void* p)
{
	if( (v < 0) || (v >= HCC_SYMS_TABLE_SIZE) ){
		printk("hcc_syms_register: Incorrect hcc_sym value (%d)\n", v);
		BUG();
		return -1;
	};

	if(hcc_syms_table[v])
		printk("hcc_syms_register_symbol(%d, %p): value already set in table\n",
					 v, p);

	if(hashtable_find(hcc_syms_htable, (unsigned long)p) != NULL)
	{
		printk("hcc_syms_register_symbol(%d, %p): value already set in htable\n",
					 v, p);
		BUG();
	}

	hashtable_add(hcc_syms_htable, (unsigned long)p, (void*)v);
	hcc_syms_table[v] = p;

	return 0;
};
EXPORT_SYMBOL(hcc_syms_register);

int hcc_syms_unregister(enum hcc_syms_val v)
{
	void *p;

	if( (v < 0) || (v >= HCC_SYMS_TABLE_SIZE) ){
		printk("hcc_syms_unregister: Incorrect hcc_sym value (%d)\n", v);
		BUG();
		return -1;
	};

	p = hcc_syms_table[v];
	hcc_syms_table[v] = NULL;
	hashtable_remove(hcc_syms_htable, (unsigned long)p);

	return 0;
};
EXPORT_SYMBOL(hcc_syms_unregister);

enum hcc_syms_val hcc_syms_export(void* p)
{
	return (enum hcc_syms_val)hashtable_find(hcc_syms_htable, (unsigned long)p);
};

void* hcc_syms_import(enum hcc_syms_val v)
{
	if( (v < 0) || (v >= HCC_SYMS_TABLE_SIZE) ){
		printk("hcc_syms_import: Incorrect hcc_sym value (%d)\n", v);
		BUG();
		return NULL;
	};

	if ((v!=0) && (hcc_syms_table[v] == NULL))
	{
		printk ("undefined hcc_symbol (%d)\n", v);
		BUG();
	}

	return hcc_syms_table[v];
};

int __init init_hcc_syms(void)
{
	hcc_syms_htable = hashtable_new(HCC_SYMS_HTABLE_SIZE);
	if (!hcc_syms_htable)
		panic("Could not setup hcc_syms table!\n");

	return 0;
};
