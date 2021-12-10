/*
 * Copyright (C) Sistina Software, Inc.  1997-2003 All rights reserved.
 * Copyright (C) 2004-2006 Red Hat, Inc.  All rights reserved.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU General Public License version 2.
 */

#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/buffer_head.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/gfs2_ondisk.h>
#include <linux/rcupdate.h>
#include <linux/rculist_bl.h>
#include <asm/atomic.h>
#include <linux/slow-work.h>
#include <linux/mempool.h>

#include "gfs2.h"
#include "incore.h"
#include "super.h"
#include "sys.h"
#include "util.h"
#include "glock.h"
#include "quota.h"
#include "dir.h"

static char *gl_hash_size = "32K";
module_param(gl_hash_size, charp, 0644);
MODULE_PARM_DESC(gl_hash_size, "Number of glock hash buckets (factor of 2)");

static struct shrinker qd_shrinker = {
	.shrink = gfs2_shrink_qd_memory,
	.seeks = DEFAULT_SEEKS,
};

static void gfs2_init_inode_once(void *foo)
{
	struct gfs2_inode *ip = foo;

	inode_init_once(&ip->i_inode);
	init_rwsem(&ip->i_rw_mutex);
	INIT_LIST_HEAD(&ip->i_trunc_list);
	ip->i_qadata = NULL;
	memset(&ip->i_res, 0, sizeof(ip->i_res));
	RB_CLEAR_NODE(&ip->i_res.rs_node);
	ip->i_hash_cache = NULL;
	gfs2_holder_mark_uninitialized(&ip->i_iopen_gh);
}

static void gfs2_init_glock_once(void *foo)
{
	struct gfs2_glock *gl = foo;

	INIT_HLIST_BL_NODE(&gl->gl_list);
	spin_lock_init(&gl->gl_spin);
	INIT_LIST_HEAD(&gl->gl_holders);
	INIT_LIST_HEAD(&gl->gl_lru);
	INIT_LIST_HEAD(&gl->gl_ail_list);
	atomic_set(&gl->gl_ail_count, 0);
	atomic_set(&gl->gl_revokes, 0);
}

static void gfs2_init_gl_aspace_once(void *foo)
{
	struct gfs2_glock *gl = foo;
	struct address_space *mapping = (struct address_space *)(gl + 1);

	gfs2_init_glock_once(gl);
	memset(mapping, 0, sizeof(*mapping));
	INIT_RADIX_TREE(&mapping->page_tree, GFP_ATOMIC);
	spin_lock_init(&mapping->tree_lock);
	spin_lock_init(&mapping->i_mmap_lock);
	INIT_LIST_HEAD(&mapping->private_list);
	spin_lock_init(&mapping->private_lock);
	INIT_RAW_PRIO_TREE_ROOT(&mapping->i_mmap);
	INIT_LIST_HEAD(&mapping->i_mmap_nonlinear);
}

static void *gfs2_bh_alloc(gfp_t mask, void *data)
{
	return alloc_buffer_head(mask);
}

static void gfs2_bh_free(void *ptr, void *data)
{
	return free_buffer_head(ptr);
}

/**
 * init_gfs2_fs - Register GFS2 as a filesystem
 *
 * Returns: 0 on success, error code on failure
 */

static int __init init_gfs2_fs(void)
{
	int error;
	size_t glock_hashtbl_size = 0, hts, factor = 0;
	static char *last;

	gfs2_str2qstr(&gfs2_qdot, ".");
	gfs2_str2qstr(&gfs2_qdotdot, "..");

	error = gfs2_sys_init();
	if (error)
		return error;

	if (strlen(gl_hash_size) == 0)
		goto fail_invalid_hashsize;

	glock_hashtbl_size = simple_strtoul(gl_hash_size, NULL, 0);
	if (glock_hashtbl_size == 0)
		goto fail_invalid_hashsize;

	last = gl_hash_size + strlen(gl_hash_size) - 1;

	/* Check for KB, MB, GB, and such */
	if (last && (strlen(gl_hash_size) > 1) &&
	    ((*last == 'b') || (*last == 'B')) &&
	    strchr("gmkGMK", *(last - 1)))
		last--;
	switch(*last) {
	case 'g':
	case 'G':
		glock_hashtbl_size *= 1024; /* fall through */
	case 'm':
	case 'M':
		glock_hashtbl_size *= 1024; /* fall through */
	case 'k':
	case 'K':
		glock_hashtbl_size *= 1024; /* fall through */
	default:
		break;
	};
	hts = glock_hashtbl_size;
	while (hts > 1) {
		factor++;
		hts >>= 1;
	}
	hts <<= factor;
	if (hts != glock_hashtbl_size)
		goto fail_invalid_hashsize;

	error = gfs2_glock_init(glock_hashtbl_size);
	if (error)
		goto fail_uninit;

	error = -ENOMEM;
	gfs2_glock_cachep = kmem_cache_create("gfs2_glock",
					      sizeof(struct gfs2_glock),
					      0, 0,
					      gfs2_init_glock_once);
	if (!gfs2_glock_cachep)
		goto fail;

	gfs2_glock_aspace_cachep = kmem_cache_create("gfs2_glock(aspace)",
					sizeof(struct gfs2_glock) +
					sizeof(struct address_space),
					0, 0, gfs2_init_gl_aspace_once);

	if (!gfs2_glock_aspace_cachep)
		goto fail;

	gfs2_inode_cachep = kmem_cache_create("gfs2_inode",
					      sizeof(struct gfs2_inode),
					      0,  SLAB_RECLAIM_ACCOUNT|
					          SLAB_MEM_SPREAD,
					      gfs2_init_inode_once);
	if (!gfs2_inode_cachep)
		goto fail;

	gfs2_bufdata_cachep = kmem_cache_create("gfs2_bufdata",
						sizeof(struct gfs2_bufdata),
					        0, 0, NULL);
	if (!gfs2_bufdata_cachep)
		goto fail;

	gfs2_rgrpd_cachep = kmem_cache_create("gfs2_rgrpd",
					      sizeof(struct gfs2_rgrpd),
					      0, 0, NULL);
	if (!gfs2_rgrpd_cachep)
		goto fail;

	gfs2_quotad_cachep = kmem_cache_create("gfs2_quotad",
					       sizeof(struct gfs2_quota_data),
					       0, 0, NULL);
	if (!gfs2_quotad_cachep)
		goto fail;

	gfs2_qadata_cachep = kmem_cache_create("gfs2_qadata",
					       sizeof(struct gfs2_qadata),
					       0, 0, NULL);
	if (!gfs2_qadata_cachep)
		goto fail;

	register_shrinker(&qd_shrinker);

	error = register_filesystem(&gfs2_fs_type);
	if (error)
		goto fail;

	error = register_filesystem(&gfs2meta_fs_type);
	if (error)
		goto fail_unregister;

	error = slow_work_register_user(THIS_MODULE);
	if (error)
		goto fail_slow;

	gfs2_bh_pool = mempool_create(1024, gfs2_bh_alloc, gfs2_bh_free, NULL);
	if (!gfs2_bh_pool)
		goto fail_mempool;

	gfs2_register_debugfs();

	printk("GFS2 (built %s %s) installed\n", __DATE__, __TIME__);
	if (glock_hashtbl_size != 32768)
		printk(KERN_ERR "GFS2: Using glock hash table size: %lu\n",
		       (unsigned long)glock_hashtbl_size);

	return 0;

fail_mempool:
	slow_work_unregister_user(THIS_MODULE);
fail_slow:
	unregister_filesystem(&gfs2meta_fs_type);
fail_unregister:
	unregister_filesystem(&gfs2_fs_type);
fail:
	unregister_shrinker(&qd_shrinker);
	gfs2_glock_exit();

	if (gfs2_qadata_cachep)
		kmem_cache_destroy(gfs2_qadata_cachep);

	if (gfs2_quotad_cachep)
		kmem_cache_destroy(gfs2_quotad_cachep);

	if (gfs2_rgrpd_cachep)
		kmem_cache_destroy(gfs2_rgrpd_cachep);

	if (gfs2_bufdata_cachep)
		kmem_cache_destroy(gfs2_bufdata_cachep);

	if (gfs2_inode_cachep)
		kmem_cache_destroy(gfs2_inode_cachep);

	if (gfs2_glock_aspace_cachep)
		kmem_cache_destroy(gfs2_glock_aspace_cachep);

	if (gfs2_glock_cachep)
		kmem_cache_destroy(gfs2_glock_cachep);

fail_uninit:
	gfs2_sys_uninit();
	return error;

fail_invalid_hashsize:
	printk(KERN_ERR "Glock hash table buckets %lu is invalid.\n",
	       (unsigned long)glock_hashtbl_size);
	printk(KERN_ERR "Value must be >= 1024 and should be a multiple "
	       "of 2.\n");
	printk(KERN_ERR "Value may be specified in K, M, or G. For example, "
	       "gl_hash_size=128K. Default is 32K buckets.\n");
	printk(KERN_ERR "(This is the number of hash table buckets, not the "
	       "byte size of the hash table.)\n");
	error = -EINVAL;
	goto fail_uninit;
}

/**
 * exit_gfs2_fs - Unregister the file system
 *
 */

static void __exit exit_gfs2_fs(void)
{
	unregister_shrinker(&qd_shrinker);
	gfs2_glock_exit();
	gfs2_unregister_debugfs();
	unregister_filesystem(&gfs2_fs_type);
	unregister_filesystem(&gfs2meta_fs_type);
	slow_work_unregister_user(THIS_MODULE);

	rcu_barrier();

	mempool_destroy(gfs2_bh_pool);
	kmem_cache_destroy(gfs2_qadata_cachep);
	kmem_cache_destroy(gfs2_quotad_cachep);
	kmem_cache_destroy(gfs2_rgrpd_cachep);
	kmem_cache_destroy(gfs2_bufdata_cachep);
	kmem_cache_destroy(gfs2_inode_cachep);
	kmem_cache_destroy(gfs2_glock_aspace_cachep);
	kmem_cache_destroy(gfs2_glock_cachep);

	gfs2_sys_uninit();
}

MODULE_DESCRIPTION("Global File System");
MODULE_AUTHOR("Red Hat, Inc.");
MODULE_LICENSE("GPL");

module_init(init_gfs2_fs);
module_exit(exit_gfs2_fs);

