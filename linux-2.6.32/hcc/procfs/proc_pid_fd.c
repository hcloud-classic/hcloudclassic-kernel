/** Global /proc/<pid>/fd management
 *  @file proc_pid_fd.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/procfs_internal.h>

#include "proc_pid.h"

static int hcc_proc_readfd(struct file *filp, void *dirent, filldir_t filldir)
{
	return 0;
}

struct file_operations hcc_proc_fd_operations = {
	.read = generic_read_dir,
	.readdir = hcc_proc_readfd,
};

static struct dentry *hcc_proc_lookupfd(struct inode *dir,
					struct dentry *dentry,
					struct nameidata *nd)
{
	return ERR_PTR(-ENOENT);
}

/*
 * proc directories can do almost nothing..
 */
struct inode_operations hcc_proc_fd_inode_operations = {
	.lookup = hcc_proc_lookupfd,
	.setattr = proc_setattr,
};
