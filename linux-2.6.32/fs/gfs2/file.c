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
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/blkdev.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/gfs2_ondisk.h>
#include <linux/ext2_fs.h>
#include <linux/crc32.h>
#include <linux/writeback.h>
#include <asm/uaccess.h>
#include <linux/dlm.h>
#include <linux/dlm_plock.h>
#include <linux/delay.h>

#include "gfs2.h"
#include "incore.h"
#include "bmap.h"
#include "dir.h"
#include "glock.h"
#include "glops.h"
#include "inode.h"
#include "log.h"
#include "meta_io.h"
#include "quota.h"
#include "rgrp.h"
#include "trans.h"
#include "util.h"

/**
 * gfs2_llseek - seek to a location in a file
 * @file: the file
 * @offset: the offset
 * @origin: Where to seek from (SEEK_SET, SEEK_CUR, or SEEK_END)
 *
 * SEEK_END requires the glock for the file because it references the
 * file's size.
 *
 * Returns: The new offset, or errno
 */

static loff_t gfs2_llseek(struct file *file, loff_t offset, int origin)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);
	struct gfs2_holder i_gh;
	loff_t error;

	if (origin == 2) {
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (!error) {
			error = generic_file_llseek_unlocked(file, offset, origin);
			gfs2_glock_dq_uninit(&i_gh);
		}
	} else
		error = generic_file_llseek_unlocked(file, offset, origin);

	return error;
}

/**
 * gfs2_readdir - Read directory entries from a directory
 * @file: The directory to read from
 * @dirent: Buffer for dirents
 * @filldir: Function used to do the copying
 *
 * Returns: errno
 */

static int gfs2_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct inode *dir = file->f_mapping->host;
	struct gfs2_inode *dip = GFS2_I(dir);
	struct gfs2_holder d_gh;
	u64 offset = file->f_pos;
	int error;

	gfs2_holder_init(dip->i_gl, LM_ST_SHARED, 0, &d_gh);
	error = gfs2_glock_nq(&d_gh);
	if (error) {
		gfs2_holder_uninit(&d_gh);
		return error;
	}

	error = gfs2_dir_read(dir, &offset, dirent, filldir, &file->f_ra);

	gfs2_glock_dq_uninit(&d_gh);

	file->f_pos = offset;

	return error;
}

/**
 * fsflags_cvt
 * @table: A table of 32 u32 flags
 * @val: a 32 bit value to convert
 *
 * This function can be used to convert between fsflags values and
 * GFS2's own flags values.
 *
 * Returns: the converted flags
 */
static u32 fsflags_cvt(const u32 *table, u32 val)
{
	u32 res = 0;
	while(val) {
		if (val & 1)
			res |= *table;
		table++;
		val >>= 1;
	}
	return res;
}

static const u32 fsflags_to_gfs2[32] = {
	[3] = GFS2_DIF_SYNC,
	[4] = GFS2_DIF_IMMUTABLE,
	[5] = GFS2_DIF_APPENDONLY,
	[7] = GFS2_DIF_NOATIME,
	[12] = GFS2_DIF_EXHASH,
	[14] = GFS2_DIF_INHERIT_JDATA,
	[17] = GFS2_DIF_TOPDIR,
};

static const u32 gfs2_to_fsflags[32] = {
	[gfs2fl_Sync] = FS_SYNC_FL,
	[gfs2fl_Immutable] = FS_IMMUTABLE_FL,
	[gfs2fl_AppendOnly] = FS_APPEND_FL,
	[gfs2fl_NoAtime] = FS_NOATIME_FL,
	[gfs2fl_ExHash] = FS_INDEX_FL,
	[gfs2fl_TopLevel] = FS_TOPDIR_FL,
	[gfs2fl_InheritJdata] = FS_JOURNAL_DATA_FL,
};

static int gfs2_get_flags(struct file *filp, u32 __user *ptr)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int error;
	u32 fsflags;

	gfs2_holder_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	error = gfs2_glock_nq(&gh);
	if (error)
		return error;

	fsflags = fsflags_cvt(gfs2_to_fsflags, ip->i_diskflags);
	if (!S_ISDIR(inode->i_mode) && ip->i_diskflags & GFS2_DIF_JDATA)
		fsflags |= FS_JOURNAL_DATA_FL;
	if (put_user(fsflags, ptr))
		error = -EFAULT;

	gfs2_glock_dq(&gh);
	gfs2_holder_uninit(&gh);
	return error;
}

void gfs2_set_inode_flags(struct inode *inode)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	unsigned int flags = inode->i_flags;

	flags &= ~(S_SYNC|S_APPEND|S_IMMUTABLE|S_NOATIME|S_DIRSYNC);
	if (ip->i_diskflags & GFS2_DIF_IMMUTABLE)
		flags |= S_IMMUTABLE;
	if (ip->i_diskflags & GFS2_DIF_APPENDONLY)
		flags |= S_APPEND;
	if (ip->i_diskflags & GFS2_DIF_NOATIME)
		flags |= S_NOATIME;
	if (ip->i_diskflags & GFS2_DIF_SYNC)
		flags |= S_SYNC;
	inode->i_flags = flags;
}

/* Flags that can be set by user space */
#define GFS2_FLAGS_USER_SET (GFS2_DIF_JDATA|			\
			     GFS2_DIF_IMMUTABLE|		\
			     GFS2_DIF_APPENDONLY|		\
			     GFS2_DIF_NOATIME|			\
			     GFS2_DIF_SYNC|			\
			     GFS2_DIF_SYSTEM|			\
			     GFS2_DIF_TOPDIR|                   \
			     GFS2_DIF_INHERIT_JDATA)

/**
 * gfs2_set_flags - set flags on an inode
 * @inode: The inode
 * @flags: The flags to set
 * @mask: Indicates which flags are valid
 *
 */
static int do_gfs2_set_flags(struct file *filp, u32 reqflags, u32 mask)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct buffer_head *bh;
	struct gfs2_holder gh;
	int error;
	u32 new_flags, flags;

	error = mnt_want_write(filp->f_path.mnt);
	if (error)
		return error;

	error = gfs2_glock_nq_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	if (error)
		goto out_drop_write;

	error = -EACCES;
	if (!is_owner_or_cap(inode))
		goto out;

	error = 0;
	flags = ip->i_diskflags;
	new_flags = (flags & ~mask) | (reqflags & mask);
	if ((new_flags ^ flags) == 0)
		goto out;

	error = -EINVAL;
	if ((new_flags ^ flags) & ~GFS2_FLAGS_USER_SET)
		goto out;

	error = -EPERM;
	if (IS_IMMUTABLE(inode) && (new_flags & GFS2_DIF_IMMUTABLE))
		goto out;
	if (IS_APPEND(inode) && (new_flags & GFS2_DIF_APPENDONLY))
		goto out;
	if (((new_flags ^ flags) & GFS2_DIF_IMMUTABLE) &&
	    !capable(CAP_LINUX_IMMUTABLE))
		goto out;
	if (!IS_IMMUTABLE(inode)) {
		error = gfs2_permission(inode, MAY_WRITE);
		if (error)
			goto out;
	}
	if ((flags ^ new_flags) & GFS2_DIF_JDATA) {
		if (flags & GFS2_DIF_JDATA)
			gfs2_log_flush(sdp, ip->i_gl);
		error = filemap_fdatawrite(inode->i_mapping);
		if (error)
			goto out;
		error = filemap_fdatawait(inode->i_mapping);
		if (error)
			goto out;
	}
	error = gfs2_trans_begin(sdp, RES_DINODE, 0);
	if (error)
		goto out;
	error = gfs2_meta_inode_buffer(ip, &bh);
	if (error)
		goto out_trans_end;
	gfs2_trans_add_meta(ip->i_gl, bh);
	ip->i_diskflags = new_flags;
	gfs2_dinode_out(ip, bh->b_data);
	brelse(bh);
	gfs2_set_inode_flags(inode);
	gfs2_set_aops(inode);
out_trans_end:
	gfs2_trans_end(sdp);
out:
	gfs2_glock_dq_uninit(&gh);
out_drop_write:
	mnt_drop_write(filp->f_path.mnt);
	return error;
}

static int gfs2_set_flags(struct file *filp, u32 __user *ptr)
{
	struct inode *inode = filp->f_path.dentry->d_inode;
	u32 fsflags, gfsflags;

	if (get_user(fsflags, ptr))
		return -EFAULT;

	gfsflags = fsflags_cvt(fsflags_to_gfs2, fsflags);
	if (!S_ISDIR(inode->i_mode)) {
		gfsflags &= ~GFS2_DIF_TOPDIR;
		if (gfsflags & GFS2_DIF_INHERIT_JDATA)
			gfsflags ^= (GFS2_DIF_JDATA | GFS2_DIF_INHERIT_JDATA);
		return do_gfs2_set_flags(filp, gfsflags, ~GFS2_DIF_SYSTEM);
	}
	return do_gfs2_set_flags(filp, gfsflags, ~(GFS2_DIF_SYSTEM | GFS2_DIF_JDATA));
}

static long gfs2_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
	case FS_IOC_GETFLAGS:
		return gfs2_get_flags(filp, (u32 __user *)arg);
	case FS_IOC_SETFLAGS:
		return gfs2_set_flags(filp, (u32 __user *)arg);
	case FITRIM:
		return gfs2_fitrim(filp, (void __user *)arg);
	}
	return -ENOTTY;
}

/**
 * gfs2_allocate_page_backing - Use bmap to allocate blocks
 * @page: The (locked) page to allocate backing for
 *
 * We try to allocate all the blocks required for the page in
 * one go. This might fail for various reasons, so we keep
 * trying until all the blocks to back this page are allocated.
 * If some of the blocks are already allocated, thats ok too.
 */

static int gfs2_allocate_page_backing(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct buffer_head bh;
	unsigned long size = PAGE_CACHE_SIZE;
	u64 lblock = page->index << (PAGE_CACHE_SHIFT - inode->i_blkbits);

	do {
		bh.b_state = 0;
		bh.b_size = size;
		gfs2_block_map(inode, lblock, &bh, 1);
		if (!buffer_mapped(&bh))
			return -EIO;
		size -= bh.b_size;
		lblock += (bh.b_size >> inode->i_blkbits);
	} while(size > 0);
	return 0;
}

/**
 * gfs2_page_mkwrite - Make a shared, mmap()ed, page writable
 * @vma: The virtual memory area
 * @page: The page which is about to become writable
 *
 * When the page becomes writable, we need to ensure that we have
 * blocks allocated on disk to back that page.
 */

static int gfs2_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = vma->vm_file->f_path.dentry->d_inode;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_sbd *sdp = GFS2_SB(inode);
	struct gfs2_alloc_parms ap = { .aflags = 0, };
	unsigned long last_index;
	u64 pos = page->index << PAGE_CACHE_SHIFT;
	unsigned int data_blocks, ind_blocks, rblocks;
	int alloc_required = 0;
	struct gfs2_holder gh;
	loff_t size;
	int ret;

	sb_start_pagefault(inode->i_sb);

	ret = gfs2_rsqa_alloc(ip);
	if (ret)
		goto out;

	gfs2_holder_init(ip->i_gl, LM_ST_EXCLUSIVE, 0, &gh);
	ret = gfs2_glock_nq(&gh);
	if (ret)
		goto out_uninit;

	/* Update file times before taking page lock */
	file_update_time(vma->vm_file);

	set_bit(GLF_DIRTY, &ip->i_gl->gl_flags);
	set_bit(GIF_SW_PAGED, &ip->i_flags);

	gfs2_size_hint(inode, pos, PAGE_CACHE_SIZE);

	ret = gfs2_write_alloc_required(ip, pos, PAGE_CACHE_SIZE, &alloc_required);
	if (ret)
		goto out_unlock;

	if (!alloc_required) {
		lock_page(page);
		if (!PageUptodate(page) || page->mapping != inode->i_mapping) {
			ret = -EAGAIN;
			unlock_page(page);
		}
		goto out_unlock;
	}

	ret = gfs2_rindex_update(sdp);
	if (ret)
		goto out_unlock;

	ret = gfs2_quota_lock_check(ip);
	if (ret)
		goto out_unlock;
	gfs2_write_calc_reserv(ip, PAGE_CACHE_SIZE, &data_blocks, &ind_blocks);
	ap.target = data_blocks + ind_blocks;
	ret = gfs2_inplace_reserve(ip, &ap);
	if (ret)
		goto out_quota_unlock;

	rblocks = RES_DINODE + ind_blocks;
	if (gfs2_is_jdata(ip))
		rblocks += data_blocks ? data_blocks : 1;
	if (ind_blocks || data_blocks) {
		rblocks += RES_STATFS + RES_QUOTA;
		rblocks += gfs2_rg_blocks(ip, data_blocks + ind_blocks);
	}
	ret = gfs2_trans_begin(sdp, rblocks, 0);
	if (ret)
		goto out_trans_fail;

	lock_page(page);
	ret = -EINVAL;
	size = i_size_read(inode);
	last_index = (size - 1) >> PAGE_CACHE_SHIFT;
	/* Check page index against inode size */
	if (size == 0 || (page->index > last_index))
		goto out_trans_end;

	ret = -EAGAIN;
	/* If truncated, we must retry the operation, we may have raced
	 * with the glock demotion code.
	 */
	if (!PageUptodate(page) || page->mapping != inode->i_mapping)
		goto out_trans_end;

	/* Unstuff, if required, and allocate backing blocks for page */
	ret = 0;
	if (gfs2_is_stuffed(ip))
		ret = gfs2_unstuff_dinode(ip, page);
	if (ret == 0)
		ret = gfs2_allocate_page_backing(page);

out_trans_end:
	if (ret)
		unlock_page(page);
	gfs2_trans_end(sdp);
out_trans_fail:
	gfs2_inplace_release(ip);
out_quota_unlock:
	gfs2_quota_unlock(ip);
out_unlock:
	gfs2_glock_dq(&gh);
out_uninit:
	gfs2_holder_uninit(&gh);
	if (ret == 0) {
		set_page_dirty(page);
		wait_for_stable_page(page);
	}
out:
	sb_end_pagefault(inode->i_sb);
	return block_page_mkwrite_return(ret);
}

#ifndef CONFIG_HCC
static const 
#endif
struct vm_operations_struct gfs2_vm_ops = {
	.fault = filemap_fault,
	.page_mkwrite = gfs2_page_mkwrite,
};

/**
 * gfs2_mmap -
 * @file: The file to map
 * @vma: The VMA which described the mapping
 *
 * There is no need to get a lock here unless we should be updating
 * atime. We ignore any locking errors since the only consequence is
 * a missed atime update (which will just be deferred until later).
 *
 * Returns: 0
 */

static int gfs2_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);

	if (!(file->f_flags & O_NOATIME) &&
	    !IS_NOATIME(&ip->i_inode)) {
		struct gfs2_holder i_gh;
		int error;

		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (error)
			return error;
		/* grab lock to update inode */
		gfs2_glock_dq_uninit(&i_gh);
		file_accessed(file);
	}
	vma->vm_ops = &gfs2_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	return 0;
}

/**
 * gfs2_open - open a file
 * @inode: the inode to open
 * @file: the struct file for this opening
 *
 * Returns: errno
 */

static int gfs2_open(struct inode *inode, struct file *file)
{
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder i_gh;
	struct gfs2_file *fp;
	int error;

	fp = kzalloc(sizeof(struct gfs2_file), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;

	mutex_init(&fp->f_fl_mutex);

	gfs2_assert_warn(GFS2_SB(inode), !file->private_data);
	file->private_data = fp;

	if (S_ISREG(ip->i_inode.i_mode)) {
		error = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, LM_FLAG_ANY,
					   &i_gh);
		if (error)
			goto fail;

		if (!(file->f_flags & O_LARGEFILE) &&
		    i_size_read(inode) > MAX_NON_LFS) {
			error = -EOVERFLOW;
			goto fail_gunlock;
		}

		gfs2_glock_dq_uninit(&i_gh);
	}

	return 0;

fail_gunlock:
	gfs2_glock_dq_uninit(&i_gh);
fail:
	file->private_data = NULL;
	kfree(fp);
	return error;
}

/**
 * gfs2_release - called to close a struct file
 * @inode: the inode the struct file belongs to
 * @file: the struct file being closed
 *
 * Returns: errno
 */

static int gfs2_release(struct inode *inode, struct file *file)
{
	struct gfs2_inode *ip = GFS2_I(inode);

	kfree(file->private_data);
	file->private_data = NULL;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;

	gfs2_rsqa_delete(ip, &inode->i_writecount);
	return 0;
}

/**
 * gfs2_fsync - sync the dirty data for a file (across the cluster)
 * @file: the file that points to the dentry
 * @start: the start position in the file to sync
 * @end: the end position in the file to sync
 * @datasync: set if we can ignore timestamp changes
 *
 * The VFS will flush data for us. We only need to worry
 * about metadata here.
 *
 * Returns: errno
 */

static int gfs2_fsync(struct file *file, struct dentry *dentry, int datasync)
{
	struct inode *inode = dentry->d_inode;
	int sync_state = inode->i_state & I_DIRTY;
	struct gfs2_inode *ip = GFS2_I(inode);
	int ret;

	if (!gfs2_is_jdata(ip))
		sync_state &= ~I_DIRTY_PAGES;
	if (datasync)
		sync_state &= ~I_DIRTY_SYNC;

	if (sync_state) {
		ret = sync_inode_metadata(inode, 1);
		if (ret)
			return ret;
		if (gfs2_is_jdata(ip))
			filemap_write_and_wait(inode->i_mapping);
		gfs2_ail_flush(ip->i_gl, 1);
	}

	return 0;
}

/**
 * gfs2_file_aio_write - Perform a write to a file
 * @iocb: The io context
 * @iov: The data to write
 * @nr_segs: Number of @iov segments
 * @pos: The file position
 *
 * We have to do a lock/unlock here to refresh the inode size for
 * O_APPEND writes, otherwise we can land up writing at the wrong
 * offset. There is still a race, but provided the app is using its
 * own file locking, this will make O_APPEND work as expected.
 *
 */

static ssize_t gfs2_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				   unsigned long nr_segs, loff_t pos)
{
	struct file *file = iocb->ki_filp;
	size_t writesize = iov_length(iov, nr_segs);
	struct dentry *dentry = file->f_dentry;
	struct gfs2_inode *ip = GFS2_I(dentry->d_inode);
	struct gfs2_sbd *sdp;
	int ret;

	sdp = GFS2_SB(file->f_mapping->host);
	ret = gfs2_rsqa_alloc(ip);
	if (ret)
		return ret;

	gfs2_size_hint(file->f_dentry->d_inode, pos, writesize);
	if (file->f_flags & O_APPEND) {
		struct gfs2_holder gh;

		ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
		if (ret)
			return ret;
		gfs2_glock_dq_uninit(&gh);
	}

	return generic_file_aio_write(iocb, iov, nr_segs, pos);
}

static ssize_t gfs2_file_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe, size_t len,
				     unsigned int flags)
{
	struct inode *inode = in->f_mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);
	struct gfs2_holder gh;
	int ret;

	mutex_lock(&inode->i_mutex);

	ret = gfs2_glock_nq_init(ip->i_gl, LM_ST_SHARED, 0, &gh);
	if (ret) {
		mutex_unlock(&inode->i_mutex);
		return ret;
	}

	gfs2_glock_dq_uninit(&gh);
	mutex_unlock(&inode->i_mutex);

	return generic_file_splice_read(in, ppos, pipe, len, flags);
}

static ssize_t gfs2_file_splice_write(struct pipe_inode_info *pipe,
				      struct file *out, loff_t *ppos,
				      size_t len, unsigned int flags)
{
	int error;
	struct inode *inode = out->f_mapping->host;
	struct gfs2_inode *ip = GFS2_I(inode);

	error = gfs2_rsqa_alloc(ip);
	if (error)
		return (ssize_t)error;

	gfs2_size_hint(inode, *ppos, len);

	return generic_file_splice_write(pipe, out, ppos, len, flags);
}

#ifdef CONFIG_GFS2_FS_LOCKING_DLM

/**
 * gfs2_setlease - acquire/release a file lease
 * @file: the file pointer
 * @arg: lease type
 * @fl: file lock
 *
 * We don't currently have a way to enforce a lease across the whole
 * cluster; until we do, disable leases (by just returning -EINVAL),
 * unless the administrator has requested purely local locking.
 *
 * Returns: errno
 */

static int gfs2_setlease(struct file *file, long arg, struct file_lock **fl)
{
	return -EINVAL;
}

/**
 * gfs2_lock - acquire/release a posix lock on a file
 * @file: the file pointer
 * @cmd: either modify or retrieve lock state, possibly wait
 * @fl: type and range of lock
 *
 * Returns: errno
 */

static int gfs2_lock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_inode *ip = GFS2_I(file->f_mapping->host);
	struct gfs2_sbd *sdp = GFS2_SB(file->f_mapping->host);
	struct lm_lockstruct *ls = &sdp->sd_lockstruct;

	if (!(fl->fl_flags & FL_POSIX))
		return -ENOLCK;
	if (__mandatory_lock(&ip->i_inode) && fl->fl_type != F_UNLCK)
		return -ENOLCK;

	if (cmd == F_CANCELLK) {
		/* Hack: */
		cmd = F_SETLK;
		fl->fl_type = F_UNLCK;
	}
	if (unlikely(test_bit(SDF_SHUTDOWN, &sdp->sd_flags))) {
		if (fl->fl_type == F_UNLCK)
			posix_lock_file_wait(file, fl);
		return -EIO;
	}
	if (IS_GETLK(cmd))
		return dlm_posix_get(ls->ls_dlm, ip->i_no_addr, file, fl);
	else if (fl->fl_type == F_UNLCK)
		return dlm_posix_unlock(ls->ls_dlm, ip->i_no_addr, file, fl);
	else
		return dlm_posix_lock(ls->ls_dlm, ip->i_no_addr, file, cmd, fl);
}

static int do_flock(struct file *file, int cmd, struct file_lock *fl)
{
	struct gfs2_file *fp = file->private_data;
	struct gfs2_holder *fl_gh = &fp->f_fl_gh;
	struct gfs2_inode *ip = GFS2_I(file->f_path.dentry->d_inode);
	struct gfs2_glock *gl;
	unsigned int state;
	u16 flags;
	int error = 0;
	int sleeptime;

	state = (fl->fl_type == F_WRLCK) ? LM_ST_EXCLUSIVE : LM_ST_SHARED;
	flags = (IS_SETLKW(cmd) ? 0 : LM_FLAG_TRY_1CB) | GL_EXACT;

	mutex_lock(&fp->f_fl_mutex);

	if (gfs2_holder_initialized(fl_gh)) {
		if (fl_gh->gh_state == state)
			goto out;
		flock_lock_file_wait(file,
				     &(struct file_lock){.fl_type = F_UNLCK});
		gfs2_glock_dq(fl_gh);
		gfs2_holder_reinit(state, flags, fl_gh);
	} else {
		error = gfs2_glock_get(GFS2_SB(&ip->i_inode), ip->i_no_addr,
				       &gfs2_flock_glops, CREATE, &gl);
		if (error)
			goto out;
		gfs2_holder_init(gl, state, flags, fl_gh);
		gfs2_glock_put(gl);
	}
	for (sleeptime = 1; sleeptime <= 4; sleeptime <<= 1) {
		error = gfs2_glock_nq(fl_gh);
		if (error != GLR_TRYFAILED)
			break;
		fl_gh->gh_flags = LM_FLAG_TRY | GL_EXACT;
		fl_gh->gh_error = 0;
		msleep(sleeptime);
	}
	if (error) {
		gfs2_holder_uninit(fl_gh);
		if (error == GLR_TRYFAILED)
			error = -EAGAIN;
	} else {
		error = flock_lock_file_wait(file, fl);
		gfs2_assert_warn(GFS2_SB(&ip->i_inode), !error);
	}

out:
	mutex_unlock(&fp->f_fl_mutex);
	return error;
}

static void do_unflock(struct file *file, struct file_lock *fl)
{
	struct gfs2_file *fp = file->private_data;
	struct gfs2_holder *fl_gh = &fp->f_fl_gh;

	mutex_lock(&fp->f_fl_mutex);
	flock_lock_file_wait(file, fl);
	if (gfs2_holder_initialized(fl_gh)) {
		gfs2_glock_dq(fl_gh);
		gfs2_holder_uninit(fl_gh);
	}
	mutex_unlock(&fp->f_fl_mutex);
}

/**
 * gfs2_flock - acquire/release a flock lock on a file
 * @file: the file pointer
 * @cmd: either modify or retrieve lock state, possibly wait
 * @fl: type and range of lock
 *
 * Returns: errno
 */

static int gfs2_flock(struct file *file, int cmd, struct file_lock *fl)
{
	if (!(fl->fl_flags & FL_FLOCK))
		return -ENOLCK;
	if (fl->fl_type & LOCK_MAND)
		return -EOPNOTSUPP;

	if (fl->fl_type == F_UNLCK) {
		do_unflock(file, fl);
		return 0;
	} else {
		return do_flock(file, cmd, fl);
	}
}

const struct file_operations gfs2_file_fops = {
	.llseek		= gfs2_llseek,
	.read		= do_sync_read,
	.aio_read	= generic_file_aio_read,
	.write		= do_sync_write,
	.aio_write	= gfs2_file_aio_write,
	.unlocked_ioctl	= gfs2_ioctl,
	.mmap		= gfs2_mmap,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
	.splice_read	= gfs2_file_splice_read,
	.splice_write	= gfs2_file_splice_write,
	.setlease	= gfs2_setlease,
};

const struct file_operations gfs2_dir_fops = {
	.readdir	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.lock		= gfs2_lock,
	.flock		= gfs2_flock,
};

#endif /* CONFIG_GFS2_FS_LOCKING_DLM */

const struct file_operations gfs2_file_fops_nolock = {
	.llseek		= gfs2_llseek,
	.read		= do_sync_read,
	.aio_read	= generic_file_aio_read,
	.write		= do_sync_write,
	.aio_write	= gfs2_file_aio_write,
	.unlocked_ioctl	= gfs2_ioctl,
	.mmap		= gfs2_mmap,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
	.splice_read	= gfs2_file_splice_read,
	.splice_write	= gfs2_file_splice_write,
	.setlease	= generic_setlease,
};

const struct file_operations gfs2_dir_fops_nolock = {
	.readdir	= gfs2_readdir,
	.unlocked_ioctl	= gfs2_ioctl,
	.open		= gfs2_open,
	.release	= gfs2_release,
	.fsync		= gfs2_fsync,
};

