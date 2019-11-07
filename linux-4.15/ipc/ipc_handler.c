#ifndef NO_IPC
#include <linux/ipc.h>
#include <linux/ipc_namespace.h>
#include <linux/nsproxy.h>
#include <linux/msg.h>

struct ipc_namespace *find_get_hcc_ipcns(void)
{
	struct hcc_namespace *hcc_ns;
	struct ipc_namespace *ipc_ns;

	hcc_ns = find_get_hcc_ns();
	if (!hcc_ns)
		goto error;

	if (!hcc_ns->root_nsproxy.ipc_ns)
		goto error_ipcns;

	ipc_ns = get_ipc_ns(hcc_ns->root_nsproxy.ipc_ns);

	put_hcc_ns(hcc_ns);

	return ipc_ns;

error_ipcns:
	put_hcc_ns(hcc_ns);
error:
	return NULL;
}


int hcc_ipc_get_maxid(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map;
	int max_id;

	ipc_map = _get_object(ids->hccops->map_set, 0);
	max_id = ipc_map->alloc_map - 1;
	_put_object(ids->hccops->map_set, 0);

	return max_id;
}

int hcc_ipc_get_new_id(struct ipc_ids* ids)
{
	ipcmap_object_t *ipc_map, *max_id;
	int i = 1, id = -1, offset;

	max_id = _grab_object(ids->hccops->map_set, 0);

	while (id == -1) {
		ipc_map = _grab_object(ids->hccops->map_set, i);

		if (ipc_map->alloc_map != ULONG_MAX) {
			offset = find_first_zero_bit(&ipc_map->alloc_map,
						     BITS_PER_LONG);

			if (offset < BITS_PER_LONG) {

				id = (i-1) * BITS_PER_LONG + offset;
				set_bit(offset, &ipc_map->alloc_map);
				if (id >= max_id->alloc_map)
					max_id->alloc_map = id + 1;
			}
		}

		_put_object(ids->hccops->map_set, i);
		i++;
	}

	_put_object(ids->hccops->map_set, 0);

	return id;
}
#endif