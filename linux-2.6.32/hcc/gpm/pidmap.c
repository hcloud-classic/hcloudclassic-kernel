/*
 *  hcc/gpm/pidmap.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <linux/rwsem.h>
#include <hcc/pid.h>
#include <hcc/namespace.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/ghotplug.h>
#include <net/grpc/grpc.h>
#include <net/grpc/grpcid.h>
#include <gdm/gdm.h>

#include "pid.h"

#define BITS_PER_PAGE (PAGE_SIZE * 8)

struct pidmap_map {
	hcc_node_t host[HCC_MAX_NODES];
};

static struct gdm_set *pidmap_map_gdm_set;
static struct pidmap_map pidmap_map;
static DECLARE_RWSEM(pidmap_map_rwsem);
static struct pid_namespace *foreign_pidmap[HCC_MAX_NODES];

static int pidmap_map_alloc_object(struct gdm_obj *obj_entry,
				   struct gdm_set *set, objid_t objid)
{
	BUG_ON(objid);
	obj_entry->object = &pidmap_map;
	return 0;
}

static int pidmap_map_first_touch(struct gdm_obj *obj_entry,
				  struct gdm_set *set, objid_t objid,
				  int flags)
{
	struct pidmap_map *map;
	hcc_node_t n;
	int err;

	err = pidmap_map_alloc_object(obj_entry, set, objid);
	if (err)
		goto out;

	map = obj_entry->object;
	for (n = 0; n < HCC_MAX_NODES; n++)
		map->host[n] = HCC_NODE_ID_NONE;

out:
	return 0;
}

static int pidmap_map_import_object(struct grpc_desc *desc, struct gdm_set *set,
				    struct gdm_obj *obj_entry, objid_t objid,
				    int flags)
{
	struct pidmap_map *map = obj_entry->object;

	return grpc_unpack_type(desc, map->host);
}

static int pidmap_map_export_object(struct grpc_desc *desc, struct gdm_set *set,
				    struct gdm_obj *obj_entry, objid_t objid,
				    int flags)
{
	struct pidmap_map *map = obj_entry->object;

	return grpc_pack_type(desc, map->host);
}

static int pidmap_map_remove_object(void *object,
				    struct gdm_set *set, objid_t objid)
{
	return 0;
}

static struct iolinker_struct pidmap_map_io_linker = {
	.first_touch   = pidmap_map_first_touch,
	.linker_name   = "pidmap_map",
	.linker_id     = PIDMAP_MAP_LINKER,
	.alloc_object  = pidmap_map_alloc_object,
	.export_object = pidmap_map_export_object,
	.import_object = pidmap_map_import_object,
	.remove_object = pidmap_map_remove_object,
};

int pidmap_map_read_lock(void)
{
	struct pidmap_map *map;
	int err = 0;

	map = _gdm_get_object(pidmap_map_gdm_set, 0);
	BUG_ON(!map);
	if (IS_ERR(map))
		err = PTR_ERR(map);
	else
		down_read(&pidmap_map_rwsem);

	return err;
}

void pidmap_map_read_unlock(void)
{
	up_read(&pidmap_map_rwsem);
	_gdm_put_object(pidmap_map_gdm_set, 0);
}

int pidmap_map_write_lock(void)
{
	struct pidmap_map *map;
	int err = 0;

	map = _gdm_grab_object(pidmap_map_gdm_set, 0);
	BUG_ON(!map);
	if (IS_ERR(map))
		err = PTR_ERR(map);
	else
		down_write(&pidmap_map_rwsem);

	return err;
}

void pidmap_map_write_unlock(void)
{
	up_write(&pidmap_map_rwsem);
	_gdm_put_object(pidmap_map_gdm_set, 0);
}

static struct pid_namespace *pidmap_alloc(void)
{
	struct pid_namespace *pidmap_ns;

	pidmap_ns = create_pid_namespace(NULL);
	if (IS_ERR(pidmap_ns))
		return pidmap_ns;

	set_bit(1, pidmap_ns->pidmap[0].page);
	atomic_dec(&pidmap_ns->pidmap[0].nr_free);

	return pidmap_ns;
}

int pidmap_map_alloc(hcc_node_t node)
{
	struct pid_namespace *pidmap_ns;
	int err;

	err = pidmap_map_write_lock();
	if (err)
		goto out;

	if (pidmap_map.host[node] != HCC_NODE_ID_NONE)
		goto unlock;

	/*
	 * Stupid policy: allocate here. We could do some load balancing if
	 * required.
	 */
	pidmap_ns = pidmap_alloc();
	if (IS_ERR(pidmap_ns)) {
		err = PTR_ERR(pidmap_ns);
		goto unlock;
	}

	foreign_pidmap[node] = pidmap_ns;
	pidmap_map.host[node] = hcc_node_id;

unlock:
	pidmap_map_write_unlock();

out:
	return err;
}

hcc_node_t pidmap_node(hcc_node_t node)
{
	return pidmap_map.host[node];
}

struct pid_namespace *node_pidmap(hcc_node_t node)
{
	return foreign_pidmap[node];
}

void hcc_free_pidmap(struct upid *upid)
{
	struct pid_namespace *pidmap_ns = node_pidmap(ORIG_NODE(upid->nr));
	struct upid __upid = {
		.nr = upid->nr,
		.ns = pidmap_ns,
	};

	if (pidmap_ns)
		__free_pidmap(&__upid);
}

void pidmap_map_cleanup(struct hcc_namespace *hcc_ns)
{
	hcc_node_t node;
	struct pid_namespace *ns;

	BUG_ON(num_online_hcc_nodes());

	/*
	 * Wait until all PIDs are ready to be reused
	 * Restarted processes may have created pid gdm objects which logic
	 * delays the actual free of the pidmap entry after the last user is
	 * reaped.
	 */
	pid_wait_quiescent();

	_gdm_remove_object(pidmap_map_gdm_set, 0);

	for (node = 0; node < HCC_MAX_NODES; node++) {
		ns = foreign_pidmap[node];
		if (ns) {
			BUG_ON(next_pidmap(ns, 1) >= 0);
			put_pid_ns(ns);
			foreign_pidmap[node] = NULL;
		}
	}
}

static int recv_pidmap(struct grpc_desc *desc,
		       hcc_node_t node,
		       struct pid_namespace *pidmap_ns)
{
	void *page;
	struct pidmap *map;
	int i, nr_pages, page_index;
	int nr_free ;
	int err;

	page = (void *)__get_free_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	err = grpc_unpack_type(desc, nr_pages);
	if (err)
		goto err;
	BUG_ON(!nr_pages);

	for (i = 0; i < nr_pages; i++) {
		err = grpc_unpack_type(desc, page_index);
		if (err)
			goto err;
		map = &pidmap_ns->pidmap[page_index];
		if (!map->page) {
			err = alloc_pidmap_page(map);
			if (err)
				goto err;
		}
		err = grpc_unpack(desc, 0, page, PAGE_SIZE);
		if (err)
			goto err;
		err = grpc_unpack_type(desc, nr_free);
		if (err)
			goto err;
		if (page_index == 0) {
			/* Init's bit is set in map->page */
			BUG_ON(!test_bit(1, map->page));
			BUG_ON(atomic_read(&map->nr_free) != BITS_PER_PAGE - 2);
			BUG_ON(!test_bit(0, page));
			BUG_ON(!test_bit(1, page));
		} else {
			BUG_ON(atomic_read(&map->nr_free) != BITS_PER_PAGE);
		}
		memcpy(map->page, page, PAGE_SIZE);
		atomic_set(&map->nr_free, nr_free);
	}

	i = 1;
	while ((i = next_pidmap(pidmap_ns, i)) > 0) {
		err = __hcc_pid_link_task(GLOBAL_PID_NODE(i, node));
		if (err)
			goto err;
	}

	err = grpc_pack_type(desc, err);
	if (err)
		goto err;

freepage:
	free_page((unsigned long)page);

	return err;

err:
	if (err > 0)
		err = -EPIPE;
	i = 1;
	while ((i = next_pidmap(pidmap_ns, i)) > 0) {
		struct upid upid = {
			.nr = i,
			.ns = pidmap_ns
		};
		__free_pidmap(&upid);
	}
	goto freepage;
}

static int send_pidmap(struct grpc_desc *desc, struct pid_namespace *pidmap_ns)
{
	struct pidmap *map;
	int i, nr_pages;
	int nr_free;
	int err;

	nr_pages = 0;
	for (i = 0; i < PIDMAP_ENTRIES; i++)
		if (atomic_read(&pidmap_ns->pidmap[i].nr_free) < BITS_PER_PAGE)
			nr_pages++;
	BUG_ON(!nr_pages);

	err = grpc_pack_type(desc, nr_pages);
	if (err)
		goto out;

	for (i = 0; i < PIDMAP_ENTRIES; i++) {
		map = &pidmap_ns->pidmap[i];
		nr_free = atomic_read(&map->nr_free);
		if (nr_free == BITS_PER_PAGE)
			continue;

		err = grpc_pack_type(desc, i);
		if (err)
			goto out;
		err = grpc_pack(desc, 0, map->page, PAGE_SIZE);
		if (err)
			goto out;
		err = grpc_pack_type(desc, nr_free);
		if (err)
			goto out;
	}

	/* Make sure that the transfer went fine */
	err = grpc_unpack_type(desc, err);
	if (err > 0)
		err = -EPIPE;

out:
	return err;
}

static void handle_pidmap_steal(struct grpc_desc *desc, void *_msg, size_t size)
{
	hcc_node_t node = *(hcc_node_t *)_msg;
	struct pid_namespace *pidmap_ns = foreign_pidmap[node];

	if (send_pidmap(desc, pidmap_ns)) {
		grpc_cancel(desc);
		return;
	}

	foreign_pidmap[node] = NULL;
	put_pid_ns(pidmap_ns);
}

int pidmap_map_add(struct ghotplug_context *ctx)
{
	struct pid_namespace *ns = ctx->ns->root_nsproxy.pid_ns;
	hcc_node_t host_node;
	struct grpc_desc *desc;
	int err;

	if (!hcc_node_isset(hcc_node_id, ctx->node_set.v))
		return 0;

	err = pidmap_map_read_lock();
	if (err)
		return err;
	host_node = pidmap_node(hcc_node_id);
	pidmap_map_read_unlock();

	if (host_node == hcc_node_id)
		return 0;

	err = pidmap_map_write_lock();
	if (err)
		return err;

	host_node = pidmap_node(hcc_node_id);
	if (host_node == HCC_NODE_ID_NONE) {
		pidmap_map.host[hcc_node_id] = hcc_node_id;
		goto unlock;
	}
	BUG_ON(host_node == hcc_node_id);

	err = -ENOMEM;
	desc = grpc_begin(GPM_PIDMAP_STEAL, host_node);
	if (!desc)
		goto unlock;

	err = grpc_pack_type(desc, hcc_node_id);
	if (err)
		goto cancel;

	err = recv_pidmap(desc, hcc_node_id, ns);
	if (err)
		goto cancel;

	pidmap_map.host[hcc_node_id] = hcc_node_id;

end:
	grpc_end(desc, 0);

unlock:
	pidmap_map_write_unlock();

	return err;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	goto end;
}

void gpm_pidmap_start(void)
{
	register_io_linker(PIDMAP_MAP_LINKER, &pidmap_map_io_linker);
	pidmap_map_gdm_set = create_new_gdm_set(gdm_def_ns,
						  PIDMAP_MAP_GDM_ID,
						  PIDMAP_MAP_LINKER,
						  GDM_RR_DEF_OWNER,
						  0, 0);
	if (IS_ERR(pidmap_map_gdm_set))
		OOM;

	grpc_register_void(GPM_PIDMAP_STEAL, handle_pidmap_steal, 0);
}

void gpm_pidmap_exit(void)
{
	return;
}
