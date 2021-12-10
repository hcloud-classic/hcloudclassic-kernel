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
#include <linux/namei.h>
#include <linux/mm.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/gfs2_ondisk.h>
#include <linux/crc32.h>
#include <linux/fiemap.h>
#include <linux/swap.h>
#include <linux/falloc.h>
#include <asm/uaccess.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>

#include "gfs2.h"
#include "incore.h"
#include "acl.h"
#include "bmap.h"
#include "dir.h"
#include "xattr.h"
#include "glock.h"
#include "inode.h"
#include "meta_io.h"
#include "quota.h"
#include "rgrp.h"
#include "trans.h"
#include "util.h"
#include "super.h"

/**
 * gfs2_create - Create a file
 * @dir: The directory in which to create the file
 * @dentry: The dentry of the new file
 * @mode: The mode of the new file
 *
 * Returns: errno
 */

static int gfs2_create(struct inode *dir, struct dentry *dentry,
		       int mode, struct nameidata *nd)
{
	int excl = 0;
	if (nd && (nd->flags & LOOKUP_EXCL))
		excl = 1;
	return gfs2_create_inode(dir, dentry, S_IFREG | mode, 0, NULL, 0, excl);
}

/**
 * gfs2_lookup - Look up a filename in a directory and return its inode
 * @dir: The directory inode
 * @dentry: The dentry of the new inode
 * @nd: passed from Linux VFS, ignored by us
 *
 * Called by the VFS layer. Lock dir and call gfs2_lookupi()
 *
 * Returns: errno
 */

static struct dentry *gfs2_lookup(struct inode *dir, struct dentry *dentry,
				  struct nameidata *nd)
{
	struct inode *inode = NULL;

	dentry->d_op = &gfs2_dops;

	inode = gfs2_lookupi(dir, &dentry->d_name, 0);
	if (inode && IS_ERR(inode))
		return ERR_CAST(inode);

	if (inode) {
		struct gfs2_glock *gl = GFS2_I(inode)->i_gl;
		struct gfs2_holder gh;
		int error;
		error = gfs2_glock_nq_init(gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
		if (error) {
			iput(inode);
			return ERR_PTR(error);
		}
		gfs2_glock_dq_uninit(&gh);
		return d_splice_alias(inode, dentry);
	}
	d_add(dentry, inode);

	return NULL;
}

/**
 * gfs2_link - Link to a file
 * @old_dentry: The inode to link
 * @dir: Add link to this directory
 * @dentry: The name of the link
 *
 * Link the inode in "old_dentry" into the directory "dir" with the
 * name in "dentry".
 *
 * Returns: errno
 */

static int gfs2_link(struct dentry *old_dentry, struct inode *dir,
		     struct dentry *dentry)
{
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	struct inode *inode = old_dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder ghs[2];
	struct buffer_head *dibh;
	int alloc_required;
	int error;

	if (S_ISDIR(inode->i_mode))
		return -EPERM;

	error = gfs2_rsqa_alloc(dip);
	if (error)
		return error;

	gfs2_holder_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + 1);

	error = gfs2_glock_nq(ghs); /* parent */
	if (error)
		goto out_parent;

	error = gfs2_glock_nq(ghs + 1); /* child */
	if (error)
		goto out_child;

	error = -ENOENT;
	if (inode->i_nlink == 0)
		goto out_gunlock;

	error = gfs2_permission(dir, MAY_WRITE | MAY_EXEC);
	if (error)
		goto out_gunlock;

	error = gfs2_dir_check(dir, &dentry->d_name, NULL);
	switch (error) {
	case -ENOENT:
		break;
	case 0:
		error = -EEXIST;
	default:
		goto out_gunlock;
	}

	error = -EINVAL;
	if (!dip->i_inode.i_nlink)
		goto out_gunlock;
	error = -EFBIG;
	if (dip->i_entries == (u32)-1)
		goto out_gunlock;
	error = -EPERM;
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		goto out_gunlock;
	error = -EINVAL;
	if (!ip->i_inode.i_nlink)
		goto out_gunlock;
	error = -EMLINK;
	if (ip->i_inode.i_nlink == (u32)-1)
		goto out_gunlock;

	alloc_required = error = gfs2_diradd_alloc_required(dir, &dentry->d_name);
	if (error < 0)
		goto out_gunlock;
	error = 0;

	if (alloc_required) {
		struct gfs2_alloc_parms ap = { .target = sdp->sd_max_dirres, };
		error = gfs2_quota_lock_check(dip);
		if (error)
			goto out_gunlock;

		error = gfs2_inplace_reserve(dip, &ap);
		if (error)
			goto out_gunlock_q;

		error = gfs2_trans_begin(sdp, sdp->sd_max_dirres +
					 gfs2_rg_blocks(dip, sdp->sd_max_dirres) +
					 2 * RES_DINODE + RES_STATFS +
					 RES_QUOTA, 0);
		if (error)
			goto out_ipres;
	} else {
		error = gfs2_trans_begin(sdp, 2 * RES_DINODE + RES_LEAF, 0);
		if (error)
			goto out_ipres;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_add(dir, &dentry->d_name, ip);
	if (error)
		goto out_brelse;

	gfs2_trans_add_meta(ip->i_gl, dibh);
	inc_nlink(&ip->i_inode);
	ip->i_inode.i_ctime = CURRENT_TIME;
	gfs2_dinode_out(ip, dibh->b_data);
	mark_inode_dirty(&ip->i_inode);

out_brelse:
	brelse(dibh);
out_end_trans:
	gfs2_trans_end(sdp);
out_ipres:
	if (alloc_required)
		gfs2_inplace_release(dip);
out_gunlock_q:
	if (alloc_required)
		gfs2_quota_unlock(dip);
out_gunlock:
	gfs2_glock_dq(ghs + 1);
out_child:
	gfs2_glock_dq(ghs);
out_parent:
	gfs2_holder_uninit(ghs);
	gfs2_holder_uninit(ghs + 1);
	if (!error) {
		atomic_inc(&inode->i_count);
		d_instantiate(dentry, inode);
		mark_inode_dirty(inode);
	}
	return error;
}

/*
 * gfs2_unlink_ok - check to see that a inode is still in a directory
 * @dip: the directory
 * @name: the name of the file
 * @ip: the inode
 *
 * Assumes that the lock on (at least) @dip is held.
 *
 * Returns: 0 if the parent/child relationship is correct, errno if it isn't
 */

static int gfs2_unlink_ok(struct gfs2_inode *dip, const struct qstr *name,
			  const struct gfs2_inode *ip)
{
	int error;

	if (IS_IMMUTABLE(&ip->i_inode) || IS_APPEND(&ip->i_inode))
		return -EPERM;

	if ((dip->i_inode.i_mode & S_ISVTX) &&
	    dip->i_inode.i_uid != current_fsuid() &&
	    ip->i_inode.i_uid != current_fsuid() && !capable(CAP_FOWNER))
		return -EPERM;

	if (IS_APPEND(&dip->i_inode))
		return -EPERM;

	error = gfs2_permission(&dip->i_inode, MAY_WRITE | MAY_EXEC);
	if (error)
		return error;

	error = gfs2_dir_check(&dip->i_inode, name, ip);
	if (error)
		return error;

	return 0;
}

/**
 * gfs2_unlink_inode - Removes an inode from its parent dir and unlinks it
 * @dip: The parent directory
 * @name: The name of the entry in the parent directory
 * @bh: The inode buffer for the inode to be removed
 * @inode: The inode to be removed
 *
 * Called with all the locks and in a transaction. This will only be
 * called for a directory after it has been checked to ensure it is empty.
 *
 * Returns: 0 on success, or an error
 */

static int gfs2_unlink_inode(struct gfs2_inode *dip,
			     const struct dentry *dentry,
			     struct buffer_head *bh)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	int error;

	error = gfs2_dir_del(dip, dentry);
	if (error)
		return error;

	ip->i_entries = 0;
	inode->i_ctime = CURRENT_TIME;
	if (S_ISDIR(inode->i_mode))
		clear_nlink(inode);
	else
		drop_nlink(inode);
	gfs2_trans_add_meta(ip->i_gl, bh);
	gfs2_dinode_out(ip, bh->b_data);
	mark_inode_dirty(inode);
	if (inode->i_nlink == 0)
		gfs2_unlink_di(inode);
	return 0;
}


/**
 * gfs2_unlink - Unlink an inode (this does rmdir as well)
 * @dir: The inode of the directory containing the inode to unlink
 * @dentry: The file itself
 *
 * This routine uses the type of the inode as a flag to figure out
 * whether this is an unlink or an rmdir.
 *
 * Returns: errno
 */

static int gfs2_unlink(struct inode *dir, struct dentry *dentry)
{
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct buffer_head *bh;
	struct gfs2_holder ghs[3];
	struct gfs2_rgrpd *rgd;
	int error;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = -EROFS;

	gfs2_holder_init(dip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	gfs2_holder_init(ip->i_gl,  LM_ST_EXCLUSIVE, 0, ghs + 1);

	rgd = gfs2_blk2rgrpd(sdp, ip->i_no_addr, 1);
	if (!rgd)
		goto out_inodes;
	gfs2_holder_init(rgd->rd_gl, LM_ST_EXCLUSIVE, 0, ghs + 2);


	error = gfs2_glock_nq(ghs); /* parent */
	if (error)
		goto out_parent;

	error = gfs2_glock_nq(ghs + 1); /* child */
	if (error)
		goto out_child;

	error = -ENOENT;
	if (inode->i_nlink == 0)
		goto out_rgrp;

	if (S_ISDIR(inode->i_mode)) {
		error = -ENOTEMPTY;
		if (ip->i_entries > 2 || inode->i_nlink > 2)
			goto out_rgrp;
	}

	error = gfs2_glock_nq(ghs + 2); /* rgrp */
	if (error)
		goto out_rgrp;

	error = gfs2_unlink_ok(dip, &dentry->d_name, ip);
	if (error)
		goto out_gunlock;

	error = gfs2_trans_begin(sdp, 2*RES_DINODE + 3*RES_LEAF + RES_RG_BIT, 0);
	if (error)
		goto out_gunlock;

	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		goto out_end_trans;

	error = gfs2_unlink_inode(dip, dentry, bh);
	brelse(bh);

out_end_trans:
	gfs2_trans_end(sdp);
out_gunlock:
	gfs2_glock_dq(ghs + 2);
out_rgrp:
	gfs2_glock_dq(ghs + 1);
out_child:
	gfs2_glock_dq(ghs);
out_parent:
	gfs2_holder_uninit(ghs + 2);
out_inodes:
	gfs2_holder_uninit(ghs + 1);
	gfs2_holder_uninit(ghs);
	return error;
}

/**
 * gfs2_symlink - Create a symlink
 * @dir: The directory to create the symlink in
 * @dentry: The dentry to put the symlink in
 * @symname: The thing which the link points to
 *
 * Returns: errno
 */

static int gfs2_symlink(struct inode *dir, struct dentry *dentry,
			const char *symname)
{
	struct gfs2_sbd *sdp = GFS2_SB(dir);
	int size;

	size = strlen(symname);
	if (size > sdp->sd_sb.sb_bsize - sizeof(struct gfs2_dinode) - 1)
		return -ENAMETOOLONG;

	return gfs2_create_inode(dir, dentry, S_IFLNK | S_IRWXUGO, 0, symname, size, 0);
}

/**
 * gfs2_mkdir - Make a directory
 * @dir: The parent directory of the new one
 * @dentry: The dentry of the new directory
 * @mode: The mode of the new directory
 *
 * Returns: errno
 */

static int gfs2_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
	return gfs2_create_inode(dir, dentry, S_IFDIR | mode, 0, NULL, 0, 0);
}

/**
 * gfs2_mknod - Make a special file
 * @dir: The directory in which the special file will reside
 * @dentry: The dentry of the special file
 * @mode: The mode of the special file
 * @rdev: The device specification of the special file
 *
 */

static int gfs2_mknod(struct inode *dir, struct dentry *dentry, int mode,
		      dev_t dev)
{
	return gfs2_create_inode(dir, dentry, mode, dev, NULL, 0, 0);
}

/*
 * gfs2_ok_to_move - check if it's ok to move a directory to another directory
 * @this: move this
 * @to: to here
 *
 * Follow @to back to the root and make sure we don't encounter @this
 * Assumes we already hold the rename lock.
 *
 * Returns: errno
 */

static int gfs2_ok_to_move(struct gfs2_inode *this, struct gfs2_inode *to)
{
	struct inode *dir = &to->i_inode;
	struct super_block *sb = dir->i_sb;
	struct inode *tmp;
	int error = 0;

	igrab(dir);

	for (;;) {
		if (dir == &this->i_inode) {
			error = -EINVAL;
			break;
		}
		if (dir == sb->s_root->d_inode) {
			error = 0;
			break;
		}

		tmp = gfs2_lookupi(dir, &gfs2_qdotdot, 1);
		if (!tmp) {
			error = -ENOENT;
			break;
		}
		if (IS_ERR(tmp)) {
			error = PTR_ERR(tmp);
			break;
		}

		iput(dir);
		dir = tmp;
	}

	iput(dir);

	return error;
}

/**
 * gfs2_rename - Rename a file
 * @odir: Parent directory of old file name
 * @odentry: The old dentry of the file
 * @ndir: Parent directory of new file name
 * @ndentry: The new dentry of the file
 *
 * Returns: errno
 */

static int gfs2_rename(struct inode *odir, struct dentry *odentry,
		       struct inode *ndir, struct dentry *ndentry)
{
	struct gfs2_inode *odip = GFS2_I(odir);
	struct gfs2_inode *ndip = GFS2_I(ndir);
	struct gfs2_inode *ip = GFS2_I(odentry->d_inode);
	struct gfs2_inode *nip = NULL;
	struct gfs2_sbd *sdp = GFS2_SB(odir);
	struct gfs2_holder ghs[5], r_gh;
	struct gfs2_rgrpd *nrgd;
	unsigned int num_gh;
	int dir_rename = 0;
	int alloc_required = 0;
	unsigned int x;
	int error;

	gfs2_holder_mark_uninitialized(&r_gh);
	if (ndentry->d_inode) {
		nip = GFS2_I(ndentry->d_inode);
		if (ip == nip)
			return 0;
	}

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	error = gfs2_rsqa_alloc(ndip);
	if (error)
		return error;

	if (odip != ndip) {
		error = gfs2_glock_nq_init(sdp->sd_rename_gl, LM_ST_EXCLUSIVE,
					   0, &r_gh);
		if (error)
			goto out;

		if (S_ISDIR(ip->i_inode.i_mode)) {
			dir_rename = 1;
			/* don't move a dirctory into it's subdir */
			error = gfs2_ok_to_move(ip, ndip);
			if (error)
				goto out_gunlock_r;
		}
	}

	num_gh = 1;
	gfs2_holder_init(odip->i_gl, LM_ST_EXCLUSIVE, 0, ghs);
	if (odip != ndip) {
		gfs2_holder_init(ndip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
	}
	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
	num_gh++;

	if (nip) {
		gfs2_holder_init(nip->i_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh);
		num_gh++;
		/* grab the resource lock for unlink flag twiddling 
		 * this is the case of the target file already existing
		 * so we unlink before doing the rename
		 */
		nrgd = gfs2_blk2rgrpd(sdp, nip->i_no_addr, 1);
		if (nrgd)
			gfs2_holder_init(nrgd->rd_gl, LM_ST_EXCLUSIVE, 0, ghs + num_gh++);
	}

	for (x = 0; x < num_gh; x++) {
		error = gfs2_glock_nq(ghs + x);
		if (error)
			goto out_gunlock;
	}

	error = -ENOENT;
	if (ip->i_inode.i_nlink == 0)
		goto out_gunlock;

	/* Check out the old directory */

	error = gfs2_unlink_ok(odip, &odentry->d_name, ip);
	if (error)
		goto out_gunlock;

	/* Check out the new directory */

	if (nip) {
		error = gfs2_unlink_ok(ndip, &ndentry->d_name, nip);
		if (error)
			goto out_gunlock;

		if (nip->i_inode.i_nlink == 0) {
			error = -EAGAIN;
			goto out_gunlock;
		}

		if (S_ISDIR(nip->i_inode.i_mode)) {
			if (nip->i_entries < 2) {
				if (gfs2_consist_inode(nip))
					gfs2_dinode_print(nip);
				error = -EIO;
				goto out_gunlock;
			}
			if (nip->i_entries > 2) {
				error = -ENOTEMPTY;
				goto out_gunlock;
			}
		}
	} else {
		error = gfs2_permission(ndir, MAY_WRITE | MAY_EXEC);
		if (error)
			goto out_gunlock;

		error = gfs2_dir_check(ndir, &ndentry->d_name, NULL);
		switch (error) {
		case -ENOENT:
			error = 0;
			break;
		case 0:
			error = -EEXIST;
		default:
			goto out_gunlock;
		};

		if (odip != ndip) {
			if (!ndip->i_inode.i_nlink) {
				error = -ENOENT;
				goto out_gunlock;
			}
			if (ndip->i_entries == (u32)-1) {
				error = -EFBIG;
				goto out_gunlock;
			}
			if (S_ISDIR(ip->i_inode.i_mode) &&
			    ndip->i_inode.i_nlink == (u32)-1) {
				error = -EMLINK;
				goto out_gunlock;
			}
		}
	}

	/* Check out the dir to be renamed */

	if (dir_rename) {
		error = gfs2_permission(odentry->d_inode, MAY_WRITE);
		if (error)
			goto out_gunlock;
	}

	if (nip == NULL)
		alloc_required = gfs2_diradd_alloc_required(ndir, &ndentry->d_name);
	error = alloc_required;
	if (error < 0)
		goto out_gunlock;

	if (alloc_required) {
		struct gfs2_alloc_parms ap = { .target = sdp->sd_max_dirres, };
		error = gfs2_quota_lock_check(ndip);
		if (error)
			goto out_gunlock;

		error = gfs2_inplace_reserve(ndip, &ap);
		if (error)
			goto out_gunlock_q;

		error = gfs2_trans_begin(sdp, sdp->sd_max_dirres +
					 gfs2_rg_blocks(ndip, sdp->sd_max_dirres) +
					 4 * RES_DINODE + 4 * RES_LEAF +
					 RES_STATFS + RES_QUOTA + 4, 0);
		if (error)
			goto out_ipreserv;
	} else {
		error = gfs2_trans_begin(sdp, 4 * RES_DINODE +
					 5 * RES_LEAF + 4, 0);
		if (error)
			goto out_gunlock;
	}

	/* Remove the target file, if it exists */

	if (nip) {
		struct buffer_head *bh;
		error = gfs2_meta_inode_buffer(nip, &bh);
		if (error)
			goto out_end_trans;
		error = gfs2_unlink_inode(ndip, ndentry, bh);
		brelse(bh);
	}

	if (dir_rename) {
		error = gfs2_dir_mvino(ip, &gfs2_qdotdot, ndip, DT_DIR);
		if (error)
			goto out_end_trans;
	} else {
		struct buffer_head *dibh;
		error = gfs2_meta_inode_buffer(ip, &dibh);
		if (error)
			goto out_end_trans;
		ip->i_inode.i_ctime = CURRENT_TIME;
		gfs2_trans_add_meta(ip->i_gl, dibh);
		gfs2_dinode_out(ip, dibh->b_data);
		brelse(dibh);
	}

	error = gfs2_dir_del(odip, odentry);
	if (error)
		goto out_end_trans;

	error = gfs2_dir_add(ndir, &ndentry->d_name, ip);
	if (error)
		goto out_end_trans;

out_end_trans:
	gfs2_trans_end(sdp);
out_ipreserv:
	if (alloc_required)
		gfs2_inplace_release(ndip);
out_gunlock_q:
	if (alloc_required)
		gfs2_quota_unlock(ndip);
out_gunlock:
	while (x--) {
		gfs2_glock_dq(ghs + x);
		gfs2_holder_uninit(ghs + x);
	}
out_gunlock_r:
	if (gfs2_holder_initialized(&r_gh))
		gfs2_glock_dq_uninit(&r_gh);
out:
	return error;
}

/**
 * gfs2_readlinki - return the contents of a symlink
 * @ip: the symlink's inode
 * @buf: a pointer to the buffer to be filled
 * @len: a pointer to the length of @buf
 *
 * If @buf is too small, a piece of memory is kmalloc()ed and needs
 * to be freed by the caller.
 *
 * Returns: errno
 */

static int gfs2_readlinki(struct gfs2_inode *ip, char **buf, unsigned int *len)
{
	struct gfs2_holder i_gh;
	struct buffer_head *dibh;
	unsigned int x, size;
	int error;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &i_gh);
	error = gfs2_glock_nq(&i_gh);
	if (error) {
		gfs2_holder_uninit(&i_gh);
		return error;
	}

	size = (unsigned int)i_size_read(&ip->i_inode);
	if (size == 0) {
		gfs2_consist_inode(ip);
		error = -EIO;
		goto out;
	}

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out;

	x = size + 1;
	if (x > *len) {
		*buf = kmalloc(x, GFP_NOFS);
		if (!*buf) {
			error = -ENOMEM;
			goto out_brelse;
		}
	}

	memcpy(*buf, dibh->b_data + sizeof(struct gfs2_dinode), x);
	*len = x;

out_brelse:
	brelse(dibh);
out:
	gfs2_glock_dq_uninit(&i_gh);
	return error;
}

/**
 * gfs2_readlink - Read the value of a symlink
 * @dentry: the symlink
 * @buf: the buffer to read the symlink data into
 * @size: the size of the buffer
 *
 * Returns: errno
 */

static int gfs2_readlink(struct dentry *dentry, char __user *user_buf,
			 int user_size)
{
	struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
	char array[GFS2_FAST_NAME_SIZE], *buf = array;
	unsigned int len = GFS2_FAST_NAME_SIZE;
	int error;

	error = gfs2_readlinki(ip, &buf, &len);
	if (error)
		return error;

	if (user_size > len - 1)
		user_size = len - 1;

	if (copy_to_user(user_buf, buf, user_size))
		error = -EFAULT;
	else
		error = user_size;

	if (buf != array)
		kfree(buf);

	return error;
}

/**
 * gfs2_follow_link - Follow a symbolic link
 * @dentry: The dentry of the link
 * @nd: Data that we pass to vfs_follow_link()
 *
 * This can handle symlinks of any size. It is optimised for symlinks
 * under GFS2_FAST_NAME_SIZE.
 *
 * Returns: 0 on success or error code
 */

static void *gfs2_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
	char array[GFS2_FAST_NAME_SIZE], *buf = array;
	unsigned int len = GFS2_FAST_NAME_SIZE;
	int error;

	error = gfs2_readlinki(ip, &buf, &len);
	if (!error) {
		error = vfs_follow_link(nd, buf);
		if (buf != array)
			kfree(buf);
	} else
		path_put(&nd->path);

	return ERR_PTR(error);
}

/**
 * gfs2_permission -
 * @inode:
 * @mask:
 * @nd: passed from Linux VFS, ignored by us
 *
 * This may be called from the VFS directly, or from within GFS2 with the
 * inode locked, so we look to see if the glock is already locked and only
 * lock the glock if its not already been done.
 *
 * Returns: errno
 */

int gfs2_permission(struct inode *inode, int mask)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	int error;
	int frozen_root = 0;

	gfs2_holder_mark_uninitialized(&i_gh);
	if (gfs2_glock_is_locked_by_me(ip->i_gl) == NULL) {
		if (unlikely(gfs2_glock_is_held_dfrd(sdp->sd_trans_gl) &&
			     inode == sdp->sd_root_dir->d_inode &&
			     atomic_inc_not_zero(&sdp->sd_frozen_root)))
			frozen_root = 1;
		else {
			error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED,
						   LM_FLAG_ANY, &i_gh);
			if (error)
				return error;
		}
	}

	if ((mask & MAY_WRITE) && IS_IMMUTABLE(inode))
		error = -EACCES;
	else
		error = generic_permission(inode, mask, gfs2_check_acl);
	if (gfs2_holder_initialized(&i_gh))
		gfs2_glock_dq_uninit(&i_gh);
	else if (frozen_root && atomic_dec_and_test(&sdp->sd_frozen_root))
		wake_up(&sdp->sd_frozen_root_wait);

	return error;
}

static int setattr_chown(struct inode *inode, struct iattr *attr)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct buffer_head *dibh;
	u32 ouid, ogid, nuid, ngid;
	int error;

	ouid = inode->i_uid;
	ogid = inode->i_gid;
	nuid = attr->ia_uid;
	ngid = attr->ia_gid;

	if (!(attr->ia_valid & ATTR_UID) || ouid == nuid)
		ouid = nuid = NO_QUOTA_CHANGE;
	if (!(attr->ia_valid & ATTR_GID) || ogid == ngid)
		ogid = ngid = NO_QUOTA_CHANGE;

	if (ouid != NO_QUOTA_CHANGE || ogid != NO_QUOTA_CHANGE) {
		error = gfs2_rsqa_alloc(ip);
		if (error)
			goto out;
	}

	error = gfs2_rindex_update(sdp);
	if (error)
		goto out;

	error = gfs2_quota_lock(ip, nuid, ngid);
	if (error)
		goto out;

	if (ouid != NO_QUOTA_CHANGE || ogid != NO_QUOTA_CHANGE) {
		error = gfs2_quota_check(ip, nuid, ngid);
		if (error)
			goto out_gunlock_q;
	}

	error = gfs2_trans_begin(sdp, RES_DINODE + 2 * RES_QUOTA, 0);
	if (error)
		goto out_gunlock_q;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (error)
		goto out_end_trans;

	error = inode_setattr(inode, attr);
	gfs2_assert_warn(sdp, !error);

	gfs2_trans_add_meta(ip->i_gl, dibh);
	gfs2_dinode_out(ip, dibh->b_data);
	brelse(dibh);

	if (ouid != NO_QUOTA_CHANGE || ogid != NO_QUOTA_CHANGE) {
		u64 blocks = gfs2_get_inode_blocks(&ip->i_inode);
		gfs2_quota_change(ip, -blocks, ouid, ogid);
		gfs2_quota_change(ip, blocks, nuid, ngid);
	}

out_end_trans:
	gfs2_trans_end(sdp);
out_gunlock_q:
	gfs2_quota_unlock(ip);
out:
	return error;
}

/**
 * gfs2_setattr - Change attributes on an inode
 * @dentry: The dentry which is changing
 * @attr: The structure describing the change
 *
 * The VFS layer wants to change one or more of an inodes attributes.  Write
 * that change out to disk.
 *
 * Returns: errno
 */

static int gfs2_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	int error;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &i_gh);
	if (error)
		return error;

	error = -EPERM;
	if (IS_IMMUTABLE(inode) || IS_APPEND(inode))
		goto out;

	error = inode_change_ok(inode, attr);
	if (error)
		goto out;

	if (attr->ia_valid & ATTR_SIZE)
		error = gfs2_setattr_size(inode, attr->ia_size);
	else if (attr->ia_valid & (ATTR_UID | ATTR_GID))
		error = setattr_chown(inode, attr);
	else if ((attr->ia_valid & ATTR_MODE) && IS_POSIXACL(inode))
		error = gfs2_acl_chmod(ip, attr);
	else
		error = gfs2_setattr_simple(inode, attr);

out:
	if (!error)
		mark_inode_dirty(inode);
	gfs2_glock_dq_uninit(&i_gh);
	return error;
}

/**
 * gfs2_getattr - Read out an inode's attributes
 * @mnt: The vfsmount the inode is being accessed from
 * @dentry: The dentry to stat
 * @stat: The inode's stats
 *
 * This may be called from the VFS directly, or from within GFS2 with the
 * inode locked, so we look to see if the glock is already locked and only
 * lock the glock if its not already been done. Note that its the NFS
 * readdirplus operation which causes this to be called (from filldir)
 * with the glock already held.
 *
 * Returns: errno
 */

static int gfs2_getattr(struct vfsmount *mnt, struct dentry *dentry,
			struct kstat *stat)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	int error;
	int frozen_root = 0;

	gfs2_holder_mark_uninitialized(&gh);
	if (gfs2_glock_is_locked_by_me(ip->i_gl) == NULL) {
		if (unlikely(gfs2_glock_is_held_dfrd(sdp->sd_trans_gl) &&
			     inode == sdp->sd_root_dir->d_inode &&
			     atomic_inc_not_zero(&sdp->sd_frozen_root)))
			frozen_root = 1;
		else {
			error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
			if (error)
				return error;
		}
	}

	generic_fillattr(inode, stat);
	if (gfs2_holder_initialized(&gh))
		gfs2_glock_dq_uninit(&gh);
	else if (frozen_root && atomic_dec_and_test(&sdp->sd_frozen_root))
		wake_up(&sdp->sd_frozen_root_wait);

	return 0;
}

static int gfs2_setxattr(struct dentry *dentry, const char *name,
			 const void *data, size_t size, int flags)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret == 0) {
		ret = gfs2_rsqa_alloc(ip);
		if (ret == 0)
			ret = generic_setxattr(dentry, name, data, size, flags);
		gfs2_glock_dq(&gh);
	}
	gfs2_holder_uninit(&gh);
	return ret;
}

static ssize_t gfs2_getxattr(struct dentry *dentry, const char *name,
			     void *data, size_t size)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret == 0) {
		ret = generic_getxattr(dentry, name, data, size);
		gfs2_glock_dq(&gh);
	}
	gfs2_holder_uninit(&gh);
	return ret;
}

static int gfs2_removexattr(struct dentry *dentry, const char *name)
{
	struct inode *inode = dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret == 0) {
		ret = gfs2_rsqa_alloc(ip);
		if (ret == 0)
			ret = generic_removexattr(dentry, name);
		gfs2_glock_dq(&gh);
	}
	gfs2_holder_uninit(&gh);
	return ret;
}

static int fallocate_chunk(struct inode *inode, loff_t offset, loff_t len,
			   int mode)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct buffer_head *dibh;
	int error;
	unsigned int nr_blks;
	sector_t lblock = offset >> inode->i_blkbits;

	error = gfs2_meta_inode_buffer(ip, &dibh);
	if (unlikely(error))
		return error;

	gfs2_trans_add_meta(ip->i_gl, dibh);

	if (gfs2_is_stuffed(ip)) {
		error = gfs2_unstuff_dinode(ip, NULL);
		if (unlikely(error))
			goto out;
	}

	while (len) {
		struct buffer_head bh_map = { .b_state = 0, .b_blocknr = 0 };
		bh_map.b_size = len;
		set_buffer_zeronew(&bh_map);

		error = gfs2_block_map(inode, lblock, &bh_map, 1);
		if (unlikely(error))
			goto out;
		len -= bh_map.b_size;
		nr_blks = bh_map.b_size >> inode->i_blkbits;
		lblock += nr_blks;
		if (!buffer_new(&bh_map))
			continue;
		if (unlikely(!buffer_zeronew(&bh_map))) {
			error = -EIO;
			goto out;
		}
	}
out:
	brelse(dibh);
	return error;
}

static void calc_max_reserv(struct gfs2_inode *ip, loff_t max, loff_t *len,
			    unsigned int *data_blocks, unsigned int *ind_blocks)
{
	const struct gfs2_sbd *sdp = GFS2_SB(&ip->i_inode);
	unsigned int max_blocks = ip->i_rgd->rd_free_clone -
		ip->i_rgd->rd_reserved + ip->i_res.rs_free;
	unsigned int tmp, max_data = max_blocks - 3 * (sdp->sd_max_height - 1);

	for (tmp = max_data; tmp > sdp->sd_diptrs;) {
		tmp = DIV_ROUND_UP(tmp, sdp->sd_inptrs);
		max_data -= tmp;
	}
	/* This calculation isn't the exact reverse of gfs2_write_calc_reserve,
 	   so it might end up with fewer data blocks */
	if (max_data <= *data_blocks)
		return;
	*data_blocks = max_data;
	*ind_blocks = max_blocks - max_data;
	*len = ((loff_t)max_data - 3) << sdp->sd_sb.sb_bsize_shift;
	if (*len > max) {
		*len = max;
		gfs2_write_calc_reserv(ip, max, data_blocks, ind_blocks);
	}
}

static long __gfs2_fallocate(struct inode *inode, int mode, loff_t offset, loff_t len)
{
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_alloc_parms ap = { .aflags = 0, };
	int alloc_required;
	unsigned int data_blocks = 0, ind_blocks = 0, rblocks;
	loff_t bytes, max_bytes;
	int error;
	const loff_t pos = offset;
	const loff_t count = len;
	loff_t bsize_mask = ~((loff_t)sdp->sd_sb.sb_bsize - 1);
	loff_t next = (offset + len - 1) >> sdp->sd_sb.sb_bsize_shift;
	loff_t max_chunk_size = UINT_MAX & bsize_mask;

	next = (next + 1) << sdp->sd_sb.sb_bsize_shift;

	error = gfs2_rindex_update(sdp);
	if (error)
		return error;

	offset &= bsize_mask;

	len = next - offset;
	bytes = sdp->sd_max_rg_data * sdp->sd_sb.sb_bsize / 2;
	if (!bytes)
		bytes = UINT_MAX;
	bytes &= bsize_mask;
	if (bytes == 0)
		bytes = sdp->sd_sb.sb_bsize;

	gfs2_size_hint(inode, offset, len);
	while (len > 0) {
		if (len < bytes)
			bytes = len;
		gfs2_write_alloc_required(ip, offset, bytes, &alloc_required);
		if (!alloc_required) {
			len -= bytes;
			offset += bytes;
			continue;
		}
		error = gfs2_quota_lock_check(ip);
		if (error)
			return error;

retry:
		gfs2_write_calc_reserv(ip, bytes, &data_blocks, &ind_blocks);

		ap.target = data_blocks + ind_blocks;
		error = gfs2_inplace_reserve(ip, &ap);
		if (error) {
			if (error == -ENOSPC && bytes > sdp->sd_sb.sb_bsize) {
				bytes >>= 1;
				bytes &= bsize_mask;
				if (bytes == 0)
					bytes = sdp->sd_sb.sb_bsize;
				goto retry;
			}
			goto out_qunlock;
		}
		max_bytes = bytes;
		calc_max_reserv(ip, (len > max_chunk_size)? max_chunk_size: len,
				&max_bytes, &data_blocks, &ind_blocks);

		rblocks = RES_DINODE + ind_blocks + RES_STATFS + RES_QUOTA +
			  RES_RG_HDR + gfs2_rg_blocks(ip, data_blocks + ind_blocks);
		if (gfs2_is_jdata(ip))
			rblocks += data_blocks ? data_blocks : 1;

		error = gfs2_trans_begin(sdp, rblocks,
					 PAGE_CACHE_SIZE/sdp->sd_sb.sb_bsize);
		if (error)
			goto out_trans_fail;

		error = fallocate_chunk(inode, offset, max_bytes, mode);
		gfs2_trans_end(sdp);

		if (error)
			goto out_trans_fail;

		len -= max_bytes;
		offset += max_bytes;
		gfs2_inplace_release(ip);
		gfs2_quota_unlock(ip);
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && (pos + count) > inode->i_size) {
		struct timespec now;

		i_size_write(inode, pos + count);
		now = current_fs_time(inode->i_sb);
		inode->i_mtime = now;
		inode->i_ctime = now;
		mark_inode_dirty(inode);
	}

	return error;

out_trans_fail:
	gfs2_inplace_release(ip);
out_qunlock:
	gfs2_quota_unlock(ip);
	return error;
}

static long gfs2_fallocate(struct inode *inode, int mode, loff_t offset, loff_t len)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	mutex_lock(&inode->i_mutex);

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret)
		goto out_uninit;

	if (!(mode & FALLOC_FL_KEEP_SIZE) &&
	    (offset + len) > inode->i_size) {
		ret = inode_newsize_ok(inode, offset + len);
		if (ret)
			goto out_unlock;
	}

	ret = get_write_access(inode);
	if (ret)
		goto out_unlock;

	ret = gfs2_rsqa_alloc(ip);
	if (ret)
		goto out_putw;

	ret = __gfs2_fallocate(inode, mode, offset, len);
	if (ret)
		gfs2_rs_deltree(&ip->i_res);
out_putw:
	put_write_access(inode);
out_unlock:
	gfs2_glock_dq(&gh);
out_uninit:
	gfs2_holder_uninit(&gh);
	mutex_unlock(&inode->i_mutex);
	return ret;
}


static int gfs2_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		       u64 start, u64 len)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	ret = fiemap_check_flags(fieinfo, FIEMAP_FLAG_SYNC);
	if (ret)
		return ret;

	mutex_lock(&inode->i_mutex);

	ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	if (ret)
		goto out;

	if (gfs2_is_stuffed(ip)) {
		u64 phys = ip->i_no_addr << inode->i_blkbits;
		u64 size = i_size_read(inode);
		u32 flags = FIEMAP_EXTENT_LAST|FIEMAP_EXTENT_NOT_ALIGNED|
			    FIEMAP_EXTENT_DATA_INLINE;
		phys += sizeof(struct gfs2_dinode);
		phys += start;
		if (start + len > size)
			len = size - start;
		if (start < size)
			ret = fiemap_fill_next_extent(fieinfo, start, phys,
						      len, flags);
		if (ret == 1)
			ret = 0;
	} else {
		ret = __generic_block_fiemap(inode, fieinfo, start, len,
					     gfs2_block_map);
	}

	gfs2_glock_dq_uninit(&gh);
out:
	mutex_unlock(&inode->i_mutex);
	return ret;
}

const struct inode_operations gfs2_file_iops = {
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.setxattr = gfs2_setxattr,
	.getxattr = gfs2_getxattr,
	.listxattr = gfs2_listxattr,
	.removexattr = gfs2_removexattr,
	.fallocate = gfs2_fallocate,
	.fiemap = gfs2_fiemap,
};

const struct inode_operations gfs2_dir_iops = {
	.create = gfs2_create,
	.lookup = gfs2_lookup,
	.link = gfs2_link,
	.unlink = gfs2_unlink,
	.symlink = gfs2_symlink,
	.mkdir = gfs2_mkdir,
	.rmdir = gfs2_unlink,
	.mknod = gfs2_mknod,
	.rename = gfs2_rename,
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.setxattr = gfs2_setxattr,
	.getxattr = gfs2_getxattr,
	.listxattr = gfs2_listxattr,
	.removexattr = gfs2_removexattr,
	.fiemap = gfs2_fiemap,
};

const struct inode_operations gfs2_symlink_iops = {
	.readlink = gfs2_readlink,
	.follow_link = gfs2_follow_link,
	.permission = gfs2_permission,
	.setattr = gfs2_setattr,
	.getattr = gfs2_getattr,
	.setxattr = gfs2_setxattr,
	.getxattr = gfs2_getxattr,
	.listxattr = gfs2_listxattr,
	.removexattr = gfs2_removexattr,
	.fiemap = gfs2_fiemap,
};

