#ifndef __HASHTABLE_H__
#define __HASHTABLE_H__

#include <linux/stddef.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#define HASHTABLE_SIZE 1024

struct hash_list {
	unsigned long hash;
	void * data;
	struct hash_list * next;
};

typedef struct hashtable_t {
	spinlock_t lock;
	struct hash_list * table;
	unsigned long hashtable_size;
	unsigned long flags[NR_CPUS];
} hashtable_t;

#define hashtable_lock(table) spin_lock (&table->lock)
#define hashtable_unlock(table) spin_unlock (&table->lock)

#define hashtable_lock_bh(table) spin_lock_bh (&table->lock)
#define hashtable_unlock_bh(table) spin_unlock_bh (&table->lock)

#define hashtable_lock_irq(table) spin_lock_irq (&table->lock)
#define hashtable_unlock_irq(table) spin_unlock_irq (&table->lock)

#define hashtable_lock_irqsave(table) spin_lock_irqsave (&table->lock, table->flags[smp_processor_id()])
#define hashtable_unlock_irqrestore(table) spin_unlock_irqrestore (&table->lock, table->flags[smp_processor_id()])


hashtable_t *_hashtable_new(unsigned long hashtable_size);
static inline hashtable_t * hashtable_new(unsigned long hashtable_size)
{
	hashtable_t *ht;

	ht = _hashtable_new(hashtable_size);
	if (ht)
		spin_lock_init(&ht->lock);

	return ht;
}

void hashtable_free(hashtable_t * table);

int __hashtable_add(hashtable_t * table, unsigned long hash, void * data);

static inline int hashtable_add(hashtable_t * table, unsigned long hash,
			       void * data)
{
	int r;

	hashtable_lock_irqsave (table);

	r = __hashtable_add (table, hash, data);

	hashtable_unlock_irqrestore (table);

	return r;
}

int __hashtable_add_unique(hashtable_t *table, unsigned long hash, void *data);

static inline int hashtable_add_unique(hashtable_t *table, unsigned long hash,
				       void *data)
{
	int r;

	hashtable_lock_irqsave(table);

	r = __hashtable_add_unique(table, hash, data);

	hashtable_unlock_irqrestore(table);

	return r;
}

void *__hashtable_remove(hashtable_t * table, unsigned long hash);

static inline void * hashtable_remove(hashtable_t * table, unsigned long hash)
{
	void *data;

	hashtable_lock_irqsave (table);

	data = __hashtable_remove (table, hash);

	hashtable_unlock_irqrestore (table);

	return data;
}

void * __hashtable_find(hashtable_t * table, unsigned long hash);

static inline void * hashtable_find(hashtable_t * table, unsigned long hash)
{
	void * r;

	hashtable_lock_irqsave (table);

	r = __hashtable_find (table, hash);

	hashtable_unlock_irqrestore (table);

	return r;
}

void * __hashtable_find_next(hashtable_t * table, unsigned long hash,
			     unsigned long *hash_found);
static inline void * hashtable_find_next(hashtable_t * table,
					 unsigned long hash,
					 unsigned long *hash_found)
{
	void * r;

	hashtable_lock_irqsave (table);

	r = __hashtable_find_next (table, hash, hash_found);

	hashtable_unlock_irqrestore (table);

	return r;
}

void __hashtable_foreach_key(hashtable_t * table,
			     void (* func)(unsigned long, void *),
			     void * data);

void __hashtable_foreach_data(hashtable_t * table,
			      void (* fun)(void *, void *),
			      void * data);

void __hashtable_foreach_key_data(hashtable_t * table,
				  void (* func)(unsigned long, void *, void *),
				  void * data);

void * hashtable_find_data(hashtable_t * table,
			   int (* fun)(void *, void *),
			   void * data);

#endif