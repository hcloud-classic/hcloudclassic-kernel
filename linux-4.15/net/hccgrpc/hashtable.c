#include <linux/module.h>
#include <hcc/lib/hashtable.h>

static struct hash_list HASH_LISTHEAD_NEW = { 0, NULL, NULL };

static inline int hash_list_add(hashtable_t * table,
                                unsigned long hash,
				void * data)
{
	struct hash_list * ht;
	int index;

	index = hash % table->hashtable_size;

	ht = kmalloc(sizeof(struct hash_list), GFP_ATOMIC);
	if (ht == NULL)
		return -ENOMEM;

	ht->hash = hash;
	ht->data = data;
	ht->next = table->table[index].next;

	table->table[index].next = ht;

	return 0;
}

static inline void *hash_list_remove(hashtable_t * table,
				     unsigned long hash)
{
	struct hash_list * elem;
	void *data;
	int index;

	index = hash % table->hashtable_size;

	for(elem = &table->table[index]; elem->next != NULL; elem = elem->next) {
		if (elem->next->hash == hash) {
			struct hash_list * hash_data;

			hash_data = elem->next;
			data = hash_data->data;
			elem->next = elem->next->next;

			kfree(hash_data);
			return data;
		}
	}

	return NULL;
}

static inline void hash_list_free(struct hash_list * list)
{
	struct hash_list * elem;
	struct hash_list * next;

	next = list;
	while (next != NULL) {
		elem = next;
		next = elem->next;
		kfree(elem);
	}
}

static inline void * hash_list_find(struct hash_list * head,
				    unsigned long hash)
{
	struct hash_list * elem;

	for(elem = head; elem != NULL; elem = elem->next) {
		if (elem->hash == hash)
			return elem->data;
	}

	return NULL;
}

static inline void * hash_list_find_equal_or_next(struct hash_list * head,
						  unsigned long hash,
						  unsigned long *hash_found)
{
	struct hash_list * elem;
	void *found = NULL;

	*hash_found = -1UL;
	for(elem = head; elem != NULL; elem = elem->next) {
		if (elem->hash == hash) {
			*hash_found = elem->hash;
			return elem->data;
		}

		if (elem->hash > hash &&
		    elem->hash <= *hash_found) {
			*hash_found = elem->hash;
			found = elem->data;
		}
	}

	return found;
}

hashtable_t *_hashtable_new(unsigned long hashtable_size)
{
	hashtable_t * ht;
	int i;

	ht = kmalloc(sizeof(hashtable_t), GFP_KERNEL);
	if (ht == NULL)
		return NULL;

	ht->table = kmalloc(sizeof(struct hash_list) * hashtable_size,
			    GFP_KERNEL);

	if (ht->table == NULL)
		return NULL;

	ht->hashtable_size = hashtable_size;

	for(i = 0; i < hashtable_size; i++)
		ht->table[i] = HASH_LISTHEAD_NEW;

	return ht;
}
EXPORT_SYMBOL(_hashtable_new);

void hashtable_free(hashtable_t * table)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave (&table->lock, flags);

	for(i = 0; i < table->hashtable_size; i++)
		hash_list_free(table->table[i].next);

	kfree (table->table);
	spin_unlock_irqrestore (&table->lock, flags);

	kfree(table);
}
EXPORT_SYMBOL(hashtable_free);

int __hashtable_add(hashtable_t * table,
		    unsigned long hash,
		    void * data)
{
	int index;
	int r = 0;

	index = hash % table->hashtable_size;

	if (table->table[index].data == NULL) {
		table->table[index].hash = hash;
		table->table[index].data = data;
		table->table[index].next = NULL;
	}
	else
		r = hash_list_add(table, hash, data);

	return r;
}
EXPORT_SYMBOL(__hashtable_add);

int __hashtable_add_unique(hashtable_t * table,
			   unsigned long hash,
			   void * data)
{
	int index;
	int r = 0;

	index = hash % table->hashtable_size;

	if (!table->table[index].data) {
		table->table[index].hash = hash;
		table->table[index].data = data;
		table->table[index].next = NULL;
	}
	else if (hash_list_find(&table->table[index], hash))
		r = -EEXIST;
	else
		r = hash_list_add(table, hash, data);

	return r;
}
EXPORT_SYMBOL(__hashtable_add_unique);

void *__hashtable_remove(hashtable_t * table,
			 unsigned long hash)
{
	int index;
	struct hash_list * next;
	void *data = NULL;

	index = hash % table->hashtable_size;

	if (table->table[index].hash == hash) {
		data = table->table[index].data;

		if ((next = table->table[index].next) != NULL) {
			table->table[index].hash = next->hash;
			table->table[index].data = next->data;
			table->table[index].next = next->next;
			kfree(next);
		}
		else {
			table->table[index].hash = 0;
			table->table[index].data = NULL;
		}
	}
	else
		data = hash_list_remove(table, hash);

	return data;
}
EXPORT_SYMBOL(__hashtable_remove);

void * __hashtable_find(hashtable_t * table,
			unsigned long hash)
{
	int index;

	index = hash % table->hashtable_size;

	return hash_list_find(&table->table[index], hash);
}
EXPORT_SYMBOL(__hashtable_find);

void * __hashtable_find_next(hashtable_t * table,
			     unsigned long hash,
			     unsigned long *hash_found)
{
	unsigned long nearest_possible;
	unsigned long nearest_found, i;
	int index;
	void *found_data = NULL, *data;

	if (hash == -1UL)
		return NULL;

	nearest_found = -1UL;
	nearest_possible = hash + 1;

	for (i = hash + 1; i <= hash + table->hashtable_size; i++) {
		index = i % table->hashtable_size;
		data = hash_list_find_equal_or_next (&table->table[index],
						     i, hash_found);

		if (data && (*hash_found <= nearest_found)) {
			nearest_found = *hash_found;
			found_data = data;

			if (nearest_found == nearest_possible)
				goto done;
		}

		nearest_possible++;
	}

done:
	*hash_found = nearest_found;
	return found_data;
}
EXPORT_SYMBOL(__hashtable_find_next);

void __hashtable_foreach_key(hashtable_t * table,
			     void (* func)(unsigned long, void *),
			     void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			func(cur->hash, data);
			for(elem = cur->next; elem != NULL; elem = elem->next)
				func(elem->hash, data);
		}
	}
}
EXPORT_SYMBOL(__hashtable_foreach_key);

void __hashtable_foreach_data(hashtable_t * table,
			      void (* func)(void *, void *),
			      void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			func(cur->data, data);
			for(elem = cur->next; elem != NULL; elem = elem->next)
				func(elem->data, data);
		}
	}
}
EXPORT_SYMBOL(__hashtable_foreach_data);

void __hashtable_foreach_key_data(hashtable_t * table,
				  void (* func)(unsigned long, void *, void *),
				  void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			func(cur->hash, cur->data, data);
			for(elem = cur->next; elem != NULL; elem = elem->next)
				func(elem->hash, elem->data, data);
		}
	}
}
EXPORT_SYMBOL(__hashtable_foreach_key_data);


void * hashtable_find_data(hashtable_t * table,
			   int (* func)(void *, void *),
			   void * data)
{
	unsigned long index;
	struct hash_list *cur, *elem;
	unsigned long flags;
	void * res = NULL;

	spin_lock_irqsave (&table->lock, flags);

	for(index = 0; index < table->hashtable_size; index ++) {
		cur = &table->table[index];
		if (cur->data != NULL) {
			if (func(cur->data, data)) {
				res = cur->data;
				goto found;
			}
			for(elem = cur->next; elem != NULL; elem = elem->next)
				if (func(elem->data, data)) {
					res = elem->data;
					goto found;
				}
		}
	}

found:
	spin_unlock_irqrestore (&table->lock, flags);
	return res;
}
EXPORT_SYMBOL(hashtable_find_data);
