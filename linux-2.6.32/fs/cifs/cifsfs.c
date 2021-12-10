/*
 *   fs/cifs/cifsfs.c
 *
 *   Copyright (C) International Business Machines  Corp., 2002,2008
 *   Author(s): Steve French (sfrench@us.ibm.com)
 *
 *   Common Internet FileSystem (CIFS) client
 *
 *   This library is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU Lesser General Public License as published
 *   by the Free Software Foundation; either version 2.1 of the License, or
 *   (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public License
 *   along with this library; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/* Note that BB means BUGBUG (ie something to fix eventually) */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/vfs.h>
#include <linux/mempool.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/smp_lock.h>
#include <net/ipv6.h>
#include "cifsfs.h"
#include "cifspdu.h"
#define DECLARE_GLOBALS_HERE
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "cifs_fs_sb.h"
#include <linux/mm.h>
#include <linux/key-type.h>
#include "dns_resolve.h"
#include "cifs_spnego.h"
#include "fscache.h"
#define CIFS_MAGIC_NUMBER 0xFF534D42	/* the first four bytes of SMB PDUs */

int cifsFYI = 0;
int cifsERROR = 1;
int traceSMB = 0;
bool enable_oplocks = true;
unsigned int linuxExtEnabled = 1;
unsigned int lookupCacheEnabled = 1;
unsigned int multiuser_mount = 0;
unsigned int global_secflags = CIFSSEC_DEF;
/* unsigned int ntlmv2_support = 0; */
unsigned int sign_CIFS_PDUs = 1;
static const struct super_operations cifs_super_ops;
unsigned int CIFSMaxBufSize = CIFS_MAX_MSGSIZE;
module_param(CIFSMaxBufSize, int, 0);
MODULE_PARM_DESC(CIFSMaxBufSize, "Network buffer size (not including header). "
				 "Default: 16384 Range: 8192 to 130048");
unsigned int cifs_min_rcv = CIFS_MIN_RCV_POOL;
module_param(cifs_min_rcv, int, 0);
MODULE_PARM_DESC(cifs_min_rcv, "Network buffers in pool. Default: 4 Range: "
				"1 to 64");
unsigned int cifs_min_small = 30;
module_param(cifs_min_small, int, 0);
MODULE_PARM_DESC(cifs_min_small, "Small network buffers in pool. Default: 30 "
				 "Range: 2 to 256");
unsigned int cifs_max_pending = CIFS_MAX_REQ;
module_param(cifs_max_pending, int, 0);
MODULE_PARM_DESC(cifs_max_pending, "Simultaneous requests to server. "
				   "Default: 32767 Range: 2 to 32767.");
module_param(enable_oplocks, bool, 0644);
MODULE_PARM_DESC(enable_oplocks, "Enable or disable oplocks (bool). Default:"
				 "y/Y/1");

extern mempool_t *cifs_sm_req_poolp;
extern mempool_t *cifs_req_poolp;
extern mempool_t *cifs_mid_poolp;

struct workqueue_struct *cifsiod_workqueue;

/*
 * Bumps refcount for cifs super block.
 * Note that it should be only called if a referece to VFS super block is
 * already held, e.g. in open-type syscalls context. Otherwise it can race with
 * atomic_dec_and_test in deactivate_locked_super.
 */
void
cifs_sb_active(struct super_block *sb)
{
	struct cifs_sb_info *server = CIFS_SB(sb);

	if (atomic_inc_return(&server->active) == 1)
		atomic_inc(&sb->s_active);
}

void
cifs_sb_deactive(struct super_block *sb)
{
	struct cifs_sb_info *server = CIFS_SB(sb);

	if (atomic_dec_and_test(&server->active))
		deactivate_super(sb);
}

static int
cifs_read_super(struct super_block *sb)
{
	struct inode *inode;
	struct cifs_sb_info *cifs_sb;
	int rc = 0;

	cifs_sb = CIFS_SB(sb);

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_POSIXACL)
		sb->s_flags |= MS_POSIXACL;

	if (cifs_sb_master_tcon(cifs_sb)->ses->capabilities & CAP_LARGE_FILES)
		sb->s_maxbytes = MAX_LFS_FILESIZE;
	else
		sb->s_maxbytes = MAX_NON_LFS;

	/* BB FIXME fix time_gran to be larger for LANMAN sessions */
	sb->s_time_gran = 100;

	sb->s_magic = CIFS_MAGIC_NUMBER;
	sb->s_op = &cifs_super_ops;
	sb->s_blocksize = CIFS_MAX_MSGSIZE;
	sb->s_blocksize_bits = 14;	/* default 2**14 = CIFS_MAX_MSGSIZE */
	inode = cifs_root_iget(sb);

	if (IS_ERR(inode)) {
		rc = PTR_ERR(inode);
		inode = NULL;
		goto out_no_root;
	}

	sb->s_root = d_alloc_root(inode);

	if (!sb->s_root) {
		rc = -ENOMEM;
		goto out_no_root;
	}

#ifdef CIFS_NFSD_EXPORT
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM) {
		cFYI(1, "export ops supported");
		sb->s_export_op = &cifs_export_ops;
	}
#endif /* CIFS_NFSD_EXPORT */

	return 0;

out_no_root:
	cERROR(1, "cifs_read_super: get root inode failed");
	if (inode)
		iput(inode);

	return rc;
}

static void cifs_kill_sb(struct super_block *sb)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	kill_anon_super(sb);
	cifs_umount(cifs_sb);
}

static int
cifs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifs_tcon *tcon = cifs_sb_master_tcon(cifs_sb);
	int rc = -EOPNOTSUPP;
	int xid;

	xid = GetXid();

	buf->f_type = CIFS_MAGIC_NUMBER;

	/*
	 * PATH_MAX may be too long - it would presumably be total path,
	 * but note that some servers (includinng Samba 3) have a shorter
	 * maximum path.
	 *
	 * Instead could get the real value via SMB_QUERY_FS_ATTRIBUTE_INFO.
	 */
	buf->f_namelen = PATH_MAX;
	buf->f_files = 0;	/* undefined */
	buf->f_ffree = 0;	/* unlimited */

	/*
	 * We could add a second check for a QFS Unix capability bit
	 */
	if ((tcon->ses->capabilities & CAP_UNIX) &&
	    (CIFS_POSIX_EXTENSIONS & le64_to_cpu(tcon->fsUnixInfo.Capability)))
		rc = CIFSSMBQFSPosixInfo(xid, tcon, buf);

	/*
	 * Only need to call the old QFSInfo if failed on newer one,
	 * e.g. by OS/2.
	 **/
	if (rc && (tcon->ses->capabilities & CAP_NT_SMBS))
		rc = CIFSSMBQFSInfo(xid, tcon, buf);

	/*
	 * Some old Windows servers also do not support level 103, retry with
	 * older level one if old server failed the previous call or we
	 * bypassed it because we detected that this was an older LANMAN sess
	 */
	if (rc)
		rc = SMBOldQFSInfo(xid, tcon, buf);

	FreeXid(xid);
	return 0;
}

static int cifs_permission(struct inode *inode, int mask)
{
	struct cifs_sb_info *cifs_sb;

	cifs_sb = CIFS_SB(inode->i_sb);

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_PERM) {
		if ((mask & MAY_EXEC) && !execute_ok(inode))
			return -EACCES;
		else
			return 0;
	} else /* file mode might have been restricted at mount time
		on the client (above and beyond ACL on servers) for
		servers which do not support setting and viewing mode bits,
		so allowing client to check permissions is useful */
		return generic_permission(inode, mask, NULL);
}

static struct kmem_cache *cifs_inode_cachep;
static struct kmem_cache *cifs_req_cachep;
static struct kmem_cache *cifs_mid_cachep;
static struct kmem_cache *cifs_sm_req_cachep;
mempool_t *cifs_sm_req_poolp;
mempool_t *cifs_req_poolp;
mempool_t *cifs_mid_poolp;

static struct inode *
cifs_alloc_inode(struct super_block *sb)
{
	struct cifsInodeInfo *cifs_inode;
	cifs_inode = kmem_cache_alloc(cifs_inode_cachep, GFP_KERNEL);
	if (!cifs_inode)
		return NULL;
	cifs_inode->cifsAttrs = 0x20;	/* default */
	cifs_inode->time = 0;
	/* Until the file is open and we have gotten oplock
	info back from the server, can not assume caching of
	file data or metadata */
	cifs_set_oplock_level(cifs_inode, 0);
	cifs_inode->delete_pending = false;
	cifs_inode->invalid_mapping = false;
	cifs_inode->vfs_inode.i_blkbits = 14;  /* 2**14 = CIFS_MAX_MSGSIZE */
	cifs_inode->server_eof = 0;

	/* Can not set i_flags here - they get immediately overwritten
	   to zero by the VFS */
/*	cifs_inode->vfs_inode.i_flags = S_NOATIME | S_NOCMTIME;*/
	INIT_LIST_HEAD(&cifs_inode->openFileList);
	return &cifs_inode->vfs_inode;
}

static void
cifs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(cifs_inode_cachep, CIFS_I(inode));
}

static void
cifs_clear_inode(struct inode *inode)
{
	cifs_fscache_release_inode_cookie(inode);
}

static void
cifs_show_address(struct seq_file *s, struct TCP_Server_Info *server)
{
	struct sockaddr_in *sa = (struct sockaddr_in *) &server->dstaddr;
	struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &server->dstaddr;

	seq_printf(s, ",addr=");

	switch (server->dstaddr.ss_family) {
	case AF_INET:
		seq_printf(s, "%pI4", &sa->sin_addr.s_addr);
		break;
	case AF_INET6:
		seq_printf(s, "%pI6", &sa6->sin6_addr.s6_addr);
		if (sa6->sin6_scope_id)
			seq_printf(s, "%%%u", sa6->sin6_scope_id);
		break;
	default:
		seq_printf(s, "(unknown)");
	}
}

static void
cifs_show_security(struct seq_file *s, struct TCP_Server_Info *server)
{
	seq_printf(s, ",sec=");

	switch (server->secType) {
	case LANMAN:
		seq_printf(s, "lanman");
		break;
	case NTLMv2:
		seq_printf(s, "ntlmv2");
		break;
	case NTLM:
		seq_printf(s, "ntlm");
		break;
	case Kerberos:
		seq_printf(s, "krb5");
		break;
	case RawNTLMSSP:
		seq_printf(s, "ntlmssp");
		break;
	default:
		/* shouldn't ever happen */
		seq_printf(s, "unknown");
		break;
	}

	if (server->sec_mode & (SECMODE_SIGN_REQUIRED | SECMODE_SIGN_ENABLED))
		seq_printf(s, "i");
}

static void
cifs_show_cache_flavor(struct seq_file *s, struct cifs_sb_info *cifs_sb)
{
	seq_printf(s, ",cache=");

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_STRICT_IO)
		seq_printf(s, "strict");
	else if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_DIRECT_IO)
		seq_printf(s, "none");
	else
		seq_printf(s, "loose");
}

/*
 * cifs_show_options() is for displaying mount options in /proc/mounts.
 * Not all settable options are displayed but most of the important
 * ones are.
 */
static int
cifs_show_options(struct seq_file *s, struct vfsmount *m)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(m->mnt_sb);
	struct cifs_tcon *tcon = cifs_sb_master_tcon(cifs_sb);
	struct sockaddr *srcaddr;
	srcaddr = (struct sockaddr *)&tcon->ses->server->srcaddr;

	cifs_show_security(s, tcon->ses->server);
	cifs_show_cache_flavor(s, cifs_sb);

	seq_printf(s, ",unc=");
	seq_escape(s, tcon->treeName, " \t\n\\");

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MULTIUSER)
		seq_printf(s, ",multiuser");
	else if (tcon->ses->user_name)
		seq_show_option(s, "username", tcon->ses->user_name);

	if (tcon->ses->domainName)
		seq_show_option(s, "domain", tcon->ses->domainName);

	if (srcaddr->sa_family != AF_UNSPEC) {
		struct sockaddr_in *saddr4;
		struct sockaddr_in6 *saddr6;
		saddr4 = (struct sockaddr_in *)srcaddr;
		saddr6 = (struct sockaddr_in6 *)srcaddr;
		if (srcaddr->sa_family == AF_INET6)
			seq_printf(s, ",srcaddr=%pI6c",
				   &saddr6->sin6_addr);
		else if (srcaddr->sa_family == AF_INET)
			seq_printf(s, ",srcaddr=%pI4",
				   &saddr4->sin_addr.s_addr);
		else
			seq_printf(s, ",srcaddr=BAD-AF:%i",
				   (int)(srcaddr->sa_family));
	}

	seq_printf(s, ",uid=%u", cifs_sb->mnt_uid);
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_OVERR_UID)
		seq_printf(s, ",forceuid");
	else
		seq_printf(s, ",noforceuid");

	seq_printf(s, ",gid=%u", cifs_sb->mnt_gid);
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_OVERR_GID)
		seq_printf(s, ",forcegid");
	else
		seq_printf(s, ",noforcegid");

	cifs_show_address(s, tcon->ses->server);

	if (!tcon->unix_ext)
		seq_printf(s, ",file_mode=0%o,dir_mode=0%o",
					   cifs_sb->mnt_file_mode,
					   cifs_sb->mnt_dir_mode);
	if (tcon->seal)
		seq_printf(s, ",seal");
	if (tcon->nocase)
		seq_printf(s, ",nocase");
	if (tcon->retry)
		seq_printf(s, ",hard");
	if (tcon->unix_ext)
		seq_printf(s, ",unix");
	else
		seq_printf(s, ",nounix");
	if (cifs_sb->prepath) {
		seq_printf(s, ",prepath=");
		seq_escape(s, cifs_sb->prepath, " \t\n\\");
	}
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_POSIX_PATHS)
		seq_printf(s, ",posixpaths");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SET_UID)
		seq_printf(s, ",setuids");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM)
		seq_printf(s, ",serverino");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_RWPIDFORWARD)
		seq_printf(s, ",rwpidforward");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOPOSIXBRL)
		seq_printf(s, ",forcemand");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_XATTR)
		seq_printf(s, ",nouser_xattr");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MAP_SPECIAL_CHR)
		seq_printf(s, ",mapchars");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_UNX_EMUL)
		seq_printf(s, ",sfu");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_BRL)
		seq_printf(s, ",nobrl");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_ACL)
		seq_printf(s, ",cifsacl");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_DYNPERM)
		seq_printf(s, ",dynperm");
	if (m->mnt_sb->s_flags & MS_POSIXACL)
		seq_printf(s, ",acl");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_MF_SYMLINKS)
		seq_printf(s, ",mfsymlinks");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_FSCACHE)
		seq_printf(s, ",fsc");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NOSSYNC)
		seq_printf(s, ",nostrictsync");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_PERM)
		seq_printf(s, ",noperm");
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_BACKUPUID)
		seq_printf(s, ",backupuid=%u", cifs_sb->mnt_backupuid);
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_CIFS_BACKUPGID)
		seq_printf(s, ",backupgid=%u", cifs_sb->mnt_backupgid);

	seq_printf(s, ",rsize=%u", cifs_sb->rsize);
	seq_printf(s, ",wsize=%u", cifs_sb->wsize);
	seq_printf(s, ",echo_interval=%lu",
			tcon->ses->server->echo_interval / HZ);
	/* convert actimeo and display it in seconds */
	seq_printf(s, ",actimeo=%lu", cifs_sb->actimeo / HZ);

	return 0;
}

static void cifs_umount_begin(struct super_block *sb)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(sb);
	struct cifs_tcon *tcon;

	if (cifs_sb == NULL)
		return;

	tcon = cifs_sb_master_tcon(cifs_sb);

	spin_lock(&cifs_tcp_ses_lock);
	if ((tcon->tc_count > 1) || (tcon->tidStatus == CifsExiting)) {
		/* we have other mounts to same share or we have
		   already tried to force umount this and woken up
		   all waiting network requests, nothing to do */
		spin_unlock(&cifs_tcp_ses_lock);
		return;
	} else if (tcon->tc_count == 1)
		tcon->tidStatus = CifsExiting;
	spin_unlock(&cifs_tcp_ses_lock);

	/* cancel_brl_requests(tcon); */ /* BB mark all brl mids as exiting */
	/* cancel_notify_requests(tcon); */
	if (tcon->ses && tcon->ses->server) {
		cFYI(1, "wake up tasks now - umount begin not complete");
		wake_up_all(&tcon->ses->server->request_q);
		wake_up_all(&tcon->ses->server->response_q);
		msleep(1); /* yield */
		/* we have to kick the requests once more */
		wake_up_all(&tcon->ses->server->response_q);
		msleep(1);
	}

	return;
}

#ifdef CONFIG_CIFS_STATS2
static int cifs_show_stats(struct seq_file *s, struct vfsmount *mnt)
{
	/* BB FIXME */
	return 0;
}
#endif

static int cifs_remount(struct super_block *sb, int *flags, char *data)
{
	*flags |= MS_NODIRATIME;
	return 0;
}

void cifs_drop_inode(struct inode *inode)
{
	struct cifs_sb_info *cifs_sb = CIFS_SB(inode->i_sb);

	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_SERVER_INUM)
		return generic_drop_inode(inode);

	return generic_delete_inode(inode);
}

static const struct super_operations cifs_super_ops = {
	.statfs = cifs_statfs,
	.alloc_inode = cifs_alloc_inode,
	.destroy_inode = cifs_destroy_inode,
	.drop_inode	= cifs_drop_inode,
	.clear_inode	= cifs_clear_inode,
/*	.delete_inode	= cifs_delete_inode,  */  /* Do not need above
	function unless later we add lazy close of inodes or unless the
	kernel forgets to call us with the same number of releases (closes)
	as opens */
	.show_options = cifs_show_options,
	.umount_begin   = cifs_umount_begin,
	.remount_fs = cifs_remount,
#ifdef CONFIG_CIFS_STATS2
	.show_stats = cifs_show_stats,
#endif
};

static int cifs_set_super(struct super_block *sb, void *data)
{
	struct cifs_mnt_data *mnt_data = data;
	sb->s_fs_info = mnt_data->cifs_sb;
	return set_anon_super(sb, NULL);
}

static int
cifs_get_sb(struct file_system_type *fs_type,
	    int flags, const char *dev_name, void *data, struct vfsmount *mnt)
{
	int rc = 0;
	struct super_block *sb;
	struct cifs_sb_info *cifs_sb;
	struct smb_vol *volume_info;
	struct cifs_mnt_data mnt_data;

	cFYI(1, "Devname: %s flags: %d ", dev_name, flags);

	volume_info = cifs_get_volume_info((char *)data, dev_name);
	if (IS_ERR(volume_info))
		return PTR_ERR(volume_info);

	cifs_sb = kzalloc(sizeof(struct cifs_sb_info), GFP_KERNEL);
	if (cifs_sb == NULL) {
		rc = -ENOMEM;
		goto out_nls;
	}

	/*
	 * Copy mount params for use in submounts. Better to do
	 * the copy here and deal with the error before cleanup gets
	 * complicated post-mount.
	 */
	cifs_sb->mountdata = kstrndup(data, PAGE_SIZE, GFP_KERNEL);
	if (cifs_sb->mountdata == NULL) {
		rc = -ENOMEM;
		goto out_cifs_sb;
	}

	cifs_setup_cifs_sb(volume_info, cifs_sb);

	rc = cifs_mount(cifs_sb, volume_info);
	if (rc) {
		if (!(flags & MS_SILENT))
			cERROR(1, "cifs_mount failed w/return code = %d", rc);
		goto out_mountdata;
	}

	mnt_data.vol = volume_info;
	mnt_data.cifs_sb = cifs_sb;
	mnt_data.flags = flags;

	sb = sget(fs_type, NULL, cifs_set_super, &mnt_data);
	if (IS_ERR(sb)) {
		rc = PTR_ERR(sb);
		cifs_umount(cifs_sb);
		goto out;
	}

	sb->s_flags = flags;
	/* BB should we make this contingent on mount parm? */
	sb->s_flags |= MS_NODIRATIME | MS_NOATIME;

	rc = cifs_read_super(sb);
	if (rc)
		goto out_super;

	sb->s_flags |= MS_ACTIVE;

	simple_set_mnt(mnt, sb);
	goto out;

out_super:
	deactivate_locked_super(sb);
out:
	cifs_cleanup_volume_info(volume_info);
	return rc;
out_mountdata:
	kfree(cifs_sb->mountdata);
out_cifs_sb:
	kfree(cifs_sb);
out_nls:
	unload_nls(volume_info->local_nls);
	goto out;
}

static ssize_t cifs_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				   unsigned long nr_segs, loff_t pos)
{
	struct inode *inode = iocb->ki_filp->f_path.dentry->d_inode;
	ssize_t written;
	int rc;

	written = generic_file_aio_write(iocb, iov, nr_segs, pos);

	if (CIFS_I(inode)->clientCanCacheAll)
		return written;

	rc = filemap_fdatawrite(inode->i_mapping);
	if (rc)
		cFYI(1, "cifs_file_aio_write: %d rc on %p inode", rc, inode);

	return written;
}

static loff_t cifs_llseek(struct file *file, loff_t offset, int origin)
{
	/* origin == SEEK_END => we must revalidate the cached file length */
	if (origin == SEEK_END) {
		int rc;
		struct inode *inode = file->f_path.dentry->d_inode;

		/*
		 * We need to be sure that all dirty pages are written and the
		 * server has the newest file length.
		 */
		if (!CIFS_I(inode)->clientCanCacheRead && inode->i_mapping &&
		    inode->i_mapping->nrpages != 0) {
			rc = filemap_fdatawait(inode->i_mapping);
			if (rc) {
				mapping_set_error(inode->i_mapping, rc);
				return rc;
			}
		}
		/*
		 * Some applications poll for the file length in this strange
		 * way so we must seek to end on non-oplocked files by
		 * setting the revalidate time to zero.
		 */
		CIFS_I(inode)->time = 0;

		rc = cifs_revalidate_file_attr(file);
		if (rc < 0)
			return (loff_t)rc;
	}
	return generic_file_llseek_unlocked(file, offset, origin);
}

static int cifs_setlease(struct file *file, long arg, struct file_lock **lease)
{
	/* note that this is called by vfs setlease with the BKL held
	   although I doubt that BKL is needed here in cifs */
	struct inode *inode = file->f_path.dentry->d_inode;
	struct cifsFileInfo *cfile = file->private_data;

	if (!(S_ISREG(inode->i_mode)))
		return -EINVAL;

	/* check if file is oplocked */
	if (((arg == F_RDLCK) &&
		(CIFS_I(inode)->clientCanCacheRead)) ||
	    ((arg == F_WRLCK) &&
		(CIFS_I(inode)->clientCanCacheAll)))
		return generic_setlease(file, arg, lease);
	else if (tlink_tcon(cfile->tlink)->local_lease &&
		 !CIFS_I(inode)->clientCanCacheRead)
		/* If the server claims to support oplock on this
		   file, then we still need to check oplock even
		   if the local_lease mount option is set, but there
		   are servers which do not support oplock for which
		   this mount option may be useful if the user
		   knows that the file won't be changed on the server
		   by anyone else */
		return generic_setlease(file, arg, lease);
	else
		return -EAGAIN;
}

struct file_system_type cifs_fs_type = {
	.owner = THIS_MODULE,
	.name = "cifs",
	.get_sb = cifs_get_sb,
	.kill_sb = cifs_kill_sb,
	/*  .fs_flags */
};
const struct inode_operations cifs_dir_inode_ops = {
	.create = cifs_create,
	.lookup = cifs_lookup,
	.getattr = cifs_getattr,
	.unlink = cifs_unlink,
	.link = cifs_hardlink,
	.mkdir = cifs_mkdir,
	.rmdir = cifs_rmdir,
	.rename = cifs_rename,
	.permission = cifs_permission,
/*	revalidate:cifs_revalidate,   */
	.setattr = cifs_setattr,
	.symlink = cifs_symlink,
	.mknod   = cifs_mknod,
#ifdef CONFIG_CIFS_XATTR
	.setxattr = cifs_setxattr,
	.getxattr = cifs_getxattr,
	.listxattr = cifs_listxattr,
	.removexattr = cifs_removexattr,
#endif
};

const struct inode_operations cifs_file_inode_ops = {
/*	revalidate:cifs_revalidate, */
	.setattr = cifs_setattr,
	.getattr = cifs_getattr, /* do we need this anymore? */
	.rename = cifs_rename,
	.permission = cifs_permission,
#ifdef CONFIG_CIFS_XATTR
	.setxattr = cifs_setxattr,
	.getxattr = cifs_getxattr,
	.listxattr = cifs_listxattr,
	.removexattr = cifs_removexattr,
#endif
};

const struct inode_operations cifs_symlink_inode_ops = {
	.readlink = generic_readlink,
	.follow_link = cifs_follow_link,
	.put_link = cifs_put_link,
	.permission = cifs_permission,
	/* BB add the following two eventually */
	/* revalidate: cifs_revalidate,
	   setattr:    cifs_notify_change, *//* BB do we need notify change */
#ifdef CONFIG_CIFS_XATTR
	.setxattr = cifs_setxattr,
	.getxattr = cifs_getxattr,
	.listxattr = cifs_listxattr,
	.removexattr = cifs_removexattr,
#endif
};

const struct file_operations cifs_file_ops = {
	.read = do_sync_read,
	.write = do_sync_write,
	.aio_read = generic_file_aio_read,
	.aio_write = cifs_file_aio_write,
	.open = cifs_open,
	.release = cifs_close,
	.lock = cifs_lock,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap  = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
	.llseek = cifs_llseek,
#ifdef CONFIG_CIFS_POSIX
	.unlocked_ioctl	= cifs_ioctl,
#endif /* CONFIG_CIFS_POSIX */
	.setlease = cifs_setlease,
};

const struct file_operations cifs_file_strict_ops = {
	.read = do_sync_read,
	.write = do_sync_write,
	.aio_read = cifs_strict_readv,
	.aio_write = cifs_strict_writev,
	.open = cifs_open,
	.release = cifs_close,
	.lock = cifs_lock,
	.fsync = cifs_strict_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_strict_mmap,
	.splice_read = generic_file_splice_read,
	.llseek = cifs_llseek,
#ifdef CONFIG_CIFS_POSIX
	.unlocked_ioctl	= cifs_ioctl,
#endif /* CONFIG_CIFS_POSIX */
	.setlease = cifs_setlease,
};

const struct file_operations cifs_file_direct_ops = {
	/* BB reevaluate whether they can be done with directio, no cache */
	.read = do_sync_read,
	.write = do_sync_write,
	.aio_read = cifs_user_readv,
	.aio_write = cifs_user_writev,
	.open = cifs_open,
	.release = cifs_close,
	.lock = cifs_lock,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
#ifdef CONFIG_CIFS_POSIX
	.unlocked_ioctl  = cifs_ioctl,
#endif /* CONFIG_CIFS_POSIX */
	.llseek = cifs_llseek,
	.setlease = cifs_setlease,
};

const struct file_operations cifs_file_nobrl_ops = {
	.read = do_sync_read,
	.write = do_sync_write,
	.aio_read = generic_file_aio_read,
	.aio_write = cifs_file_aio_write,
	.open = cifs_open,
	.release = cifs_close,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.mmap  = cifs_file_mmap,
	.splice_read = generic_file_splice_read,
	.llseek = cifs_llseek,
#ifdef CONFIG_CIFS_POSIX
	.unlocked_ioctl	= cifs_ioctl,
#endif /* CONFIG_CIFS_POSIX */
	.setlease = cifs_setlease,
};

const struct file_operations cifs_file_strict_nobrl_ops = {
	.read = do_sync_read,
	.write = do_sync_write,
	.aio_read = cifs_strict_readv,
	.aio_write = cifs_strict_writev,
	.open = cifs_open,
	.release = cifs_close,
	.fsync = cifs_strict_fsync,
	.flush = cifs_flush,
	.mmap = cifs_file_strict_mmap,
	.splice_read = generic_file_splice_read,
	.llseek = cifs_llseek,
#ifdef CONFIG_CIFS_POSIX
	.unlocked_ioctl	= cifs_ioctl,
#endif /* CONFIG_CIFS_POSIX */
	.setlease = cifs_setlease,
};

const struct file_operations cifs_file_direct_nobrl_ops = {
	/* BB reevaluate whether they can be done with directio, no cache */
	.read = do_sync_read,
	.write = do_sync_write,
	.aio_read = cifs_user_readv,
	.aio_write = cifs_user_writev,
	.open = cifs_open,
	.release = cifs_close,
	.fsync = cifs_fsync,
	.flush = cifs_flush,
	.splice_read = generic_file_splice_read,
#ifdef CONFIG_CIFS_POSIX
	.unlocked_ioctl  = cifs_ioctl,
#endif /* CONFIG_CIFS_POSIX */
	.llseek = cifs_llseek,
	.setlease = cifs_setlease,
};

const struct file_operations cifs_dir_ops = {
	.readdir = cifs_readdir,
	.release = cifs_closedir,
	.read    = generic_read_dir,
	.unlocked_ioctl  = cifs_ioctl,
	.llseek = generic_file_llseek,
};

static void
cifs_init_once(void *inode)
{
	struct cifsInodeInfo *cifsi = inode;

	inode_init_once(&cifsi->vfs_inode);
	INIT_LIST_HEAD(&cifsi->lockList);
}

static int
cifs_init_inodecache(void)
{
	cifs_inode_cachep = kmem_cache_create("cifs_inode_cache",
					      sizeof(struct cifsInodeInfo),
					      0, (SLAB_RECLAIM_ACCOUNT|
						SLAB_MEM_SPREAD),
					      cifs_init_once);
	if (cifs_inode_cachep == NULL)
		return -ENOMEM;

	return 0;
}

static void
cifs_destroy_inodecache(void)
{
	kmem_cache_destroy(cifs_inode_cachep);
}

static int
cifs_init_request_bufs(void)
{
	if (CIFSMaxBufSize < 8192) {
	/* Buffer size can not be smaller than 2 * PATH_MAX since maximum
	Unicode path name has to fit in any SMB/CIFS path based frames */
		CIFSMaxBufSize = 8192;
	} else if (CIFSMaxBufSize > 1024*127) {
		CIFSMaxBufSize = 1024 * 127;
	} else {
		CIFSMaxBufSize &= 0x1FE00; /* Round size to even 512 byte mult*/
	}
/*	cERROR(1, "CIFSMaxBufSize %d 0x%x",CIFSMaxBufSize,CIFSMaxBufSize); */
	cifs_req_cachep = kmem_cache_create("cifs_request",
					    CIFSMaxBufSize +
					    MAX_CIFS_HDR_SIZE, 0,
					    SLAB_HWCACHE_ALIGN, NULL);
	if (cifs_req_cachep == NULL)
		return -ENOMEM;

	if (cifs_min_rcv < 1)
		cifs_min_rcv = 1;
	else if (cifs_min_rcv > 64) {
		cifs_min_rcv = 64;
		cERROR(1, "cifs_min_rcv set to maximum (64)");
	}

	cifs_req_poolp = mempool_create_slab_pool(cifs_min_rcv,
						  cifs_req_cachep);

	if (cifs_req_poolp == NULL) {
		kmem_cache_destroy(cifs_req_cachep);
		return -ENOMEM;
	}
	/* MAX_CIFS_SMALL_BUFFER_SIZE bytes is enough for most SMB responses and
	almost all handle based requests (but not write response, nor is it
	sufficient for path based requests).  A smaller size would have
	been more efficient (compacting multiple slab items on one 4k page)
	for the case in which debug was on, but this larger size allows
	more SMBs to use small buffer alloc and is still much more
	efficient to alloc 1 per page off the slab compared to 17K (5page)
	alloc of large cifs buffers even when page debugging is on */
	cifs_sm_req_cachep = kmem_cache_create("cifs_small_rq",
			MAX_CIFS_SMALL_BUFFER_SIZE, 0, SLAB_HWCACHE_ALIGN,
			NULL);
	if (cifs_sm_req_cachep == NULL) {
		mempool_destroy(cifs_req_poolp);
		kmem_cache_destroy(cifs_req_cachep);
		return -ENOMEM;
	}

	if (cifs_min_small < 2)
		cifs_min_small = 2;
	else if (cifs_min_small > 256) {
		cifs_min_small = 256;
		cFYI(1, "cifs_min_small set to maximum (256)");
	}

	cifs_sm_req_poolp = mempool_create_slab_pool(cifs_min_small,
						     cifs_sm_req_cachep);

	if (cifs_sm_req_poolp == NULL) {
		mempool_destroy(cifs_req_poolp);
		kmem_cache_destroy(cifs_req_cachep);
		kmem_cache_destroy(cifs_sm_req_cachep);
		return -ENOMEM;
	}

	return 0;
}

static void
cifs_destroy_request_bufs(void)
{
	mempool_destroy(cifs_req_poolp);
	kmem_cache_destroy(cifs_req_cachep);
	mempool_destroy(cifs_sm_req_poolp);
	kmem_cache_destroy(cifs_sm_req_cachep);
}

static int
cifs_init_mids(void)
{
	cifs_mid_cachep = kmem_cache_create("cifs_mpx_ids",
					    sizeof(struct mid_q_entry), 0,
					    SLAB_HWCACHE_ALIGN, NULL);
	if (cifs_mid_cachep == NULL)
		return -ENOMEM;

	/* 3 is a reasonable minimum number of simultaneous operations */
	cifs_mid_poolp = mempool_create_slab_pool(3, cifs_mid_cachep);
	if (cifs_mid_poolp == NULL) {
		kmem_cache_destroy(cifs_mid_cachep);
		return -ENOMEM;
	}

	return 0;
}

static void
cifs_destroy_mids(void)
{
	mempool_destroy(cifs_mid_poolp);
	kmem_cache_destroy(cifs_mid_cachep);
}

static int __init
init_cifs(void)
{
	int rc = 0;
	cifs_proc_init();
	INIT_LIST_HEAD(&cifs_tcp_ses_list);
#ifdef CONFIG_CIFS_DNOTIFY_EXPERIMENTAL /* unused temporarily */
	INIT_LIST_HEAD(&GlobalDnotifyReqList);
	INIT_LIST_HEAD(&GlobalDnotifyRsp_Q);
#endif /* was needed for dnotify, and will be needed for inotify when VFS fix */
/*
 *  Initialize Global counters
 */
	atomic_set(&sesInfoAllocCount, 0);
	atomic_set(&tconInfoAllocCount, 0);
	atomic_set(&tcpSesAllocCount, 0);
	atomic_set(&tcpSesReconnectCount, 0);
	atomic_set(&tconInfoReconnectCount, 0);

	atomic_set(&bufAllocCount, 0);
	atomic_set(&smBufAllocCount, 0);
#ifdef CONFIG_CIFS_STATS2
	atomic_set(&totBufAllocCount, 0);
	atomic_set(&totSmBufAllocCount, 0);
#endif /* CONFIG_CIFS_STATS2 */

	atomic_set(&midCount, 0);
	GlobalCurrentXid = 0;
	GlobalTotalActiveXid = 0;
	GlobalMaxActiveXid = 0;
	memset(Local_System_Name, 0, 15);
	spin_lock_init(&cifs_tcp_ses_lock);
	spin_lock_init(&cifs_file_list_lock);
	spin_lock_init(&GlobalMid_Lock);

	if (cifs_max_pending < 2) {
		cifs_max_pending = 2;
		cFYI(1, "cifs_max_pending set to min of 2");
	} else if (cifs_max_pending > CIFS_MAX_REQ) {
		cifs_max_pending = CIFS_MAX_REQ;
		cFYI(1, "cifs_max_pending set to max of %u", CIFS_MAX_REQ);
	}

	cifsiod_workqueue = create_singlethread_workqueue("cifsiod");
	if (cifsiod_workqueue == NULL) {
		rc = -ENOMEM;
		goto out_clean_proc;
	}

	rc = cifs_fscache_register();
	if (rc)
		goto out_destroy_wq;

	rc = cifs_init_inodecache();
	if (rc)
		goto out_unreg_fscache;

	rc = cifs_init_mids();
	if (rc)
		goto out_destroy_inodecache;

	rc = cifs_init_request_bufs();
	if (rc)
		goto out_destroy_mids;

#ifdef CONFIG_CIFS_UPCALL
	rc = init_cifs_spnego();
	if (rc)
		goto out_destroy_request_bufs;
#endif /* CONFIG_CIFS_UPCALL */
#ifdef CONFIG_CIFS_ACL
	rc = init_cifs_idmap();
	if (rc)
		goto out_register_key_type;
#endif /* CONFIG_CIFS_ACL */

#ifdef CONFIG_CIFS_DFS_UPCALL
	rc = cifs_init_dns_resolver();
	if (rc)
		goto out_init_cifs_idmap;
#endif
	rc = slow_work_register_user(THIS_MODULE);
	if (rc)
		goto out_unregister_resolver_key;

	rc = register_filesystem(&cifs_fs_type);
	if (rc)
		goto out_unregister_slow_work;

	return 0;

out_unregister_slow_work:
	slow_work_unregister_user(THIS_MODULE);
out_unregister_resolver_key:
#ifdef CONFIG_CIFS_DFS_UPCALL
	cifs_exit_dns_resolver();
out_init_cifs_idmap:
#endif
#ifdef CONFIG_CIFS_ACL
	exit_cifs_idmap();
out_register_key_type:
#endif
#ifdef CONFIG_CIFS_UPCALL
	exit_cifs_spnego();
out_destroy_request_bufs:
#endif
	cifs_destroy_request_bufs();
out_destroy_mids:
	cifs_destroy_mids();
out_destroy_inodecache:
	cifs_destroy_inodecache();
out_unreg_fscache:
	cifs_fscache_unregister();
out_destroy_wq:
	destroy_workqueue(cifsiod_workqueue);
out_clean_proc:
	cifs_proc_clean();
	return rc;
}

static void __exit
exit_cifs(void)
{
	cFYI(DBG2, "exit_cifs");
	destroy_workqueue(cifsiod_workqueue);
	slow_work_unregister_user(THIS_MODULE);
	cifs_proc_clean();
	cifs_fscache_unregister();
#ifdef CONFIG_CIFS_DFS_UPCALL
	cifs_dfs_release_automount_timer();
	cifs_exit_dns_resolver();
#endif
#ifdef CONFIG_CIFS_ACL
	exit_cifs_idmap();
#endif
#ifdef CONFIG_CIFS_UPCALL
	unregister_key_type(&cifs_spnego_key_type);
#endif
	unregister_filesystem(&cifs_fs_type);
	cifs_destroy_inodecache();
	cifs_destroy_mids();
	cifs_destroy_request_bufs();
}

MODULE_AUTHOR("Steve French <sfrench@us.ibm.com>");
MODULE_LICENSE("GPL");	/* combination of LGPL + GPL source behaves as GPL */
MODULE_DESCRIPTION
    ("VFS to access servers complying with the SNIA CIFS Specification "
     "e.g. Samba and Windows");
MODULE_VERSION(CIFS_VERSION);
module_init(init_cifs)
module_exit(exit_cifs)
