/** HCC FAF Hooks.
 *  @file file_hooks.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/namei.h>
#include <linux/socket.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/statfs.h>
#include <linux/types.h>
#include <linux/remote_sleep.h>
#include <hcc/faf.h>
#include <hcc/physical_fs.h>
#include <hcc/remote_cred.h>
#include <asm/uaccess.h>

#include <gdm/gdm.h>
#include <hcc/ghotplug.h>
#include <net/grpc/grpc.h>
#include <net/grpc/grpcid.h>
#include <hcc/file.h>
#include "../file_struct_io_linker.h"

#include "faf_internal.h"
#include "faf_server.h"
#include "faf_tools.h"
#include <hcc/faf_file_mgr.h>
#include "ruaccess.h"

static DEFINE_MUTEX(faf_poll_mutex);

static int pack_path(struct grpc_desc *desc, const struct path *path)
{
	char *tmp, *name;
	struct path phys_root;
	int len, err;

	err = -EPERM;
	get_physical_root(&phys_root);
	if (path->mnt->mnt_ns != phys_root.mnt->mnt_ns)
		/* path lives in a child mount namespace: not supported yet */
		goto out;

	err = -ENOMEM;
	tmp = (char *)__get_free_page(GFP_KERNEL);
	if (!tmp)
		goto out;

	err = -EINVAL;
	name = physical_d_path(path, tmp, false);
	if (!name)
		goto out_free;
	len = strlen(name) + 1;

	err = grpc_pack_type(desc, len);
	if (err)
		goto out_free;
	err = grpc_pack(desc, 0, name, len);

out_free:
	free_page((unsigned long)tmp);
out:
	path_put(&phys_root);

	return err;
}

static int pack_root(struct grpc_desc *desc)
{
	struct path root;
	int ret;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);

	ret = pack_path(desc, &root);

	path_put(&root);

	return ret;
}

static int pack_root_pwd(struct grpc_desc *desc)
{
	struct path root, pwd;
	int ret;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	pwd = current->fs->pwd;
	path_get(&pwd);
	read_unlock(&current->fs->lock);

	ret = pack_path(desc, &root);
	if (!ret)
		ret = pack_path(desc, &pwd);

	path_put(&root);
	path_put(&pwd);

	return ret;
}

static int pack_context(struct grpc_desc *desc)
{
	int err;

	err = pack_creds(desc, current_cred());
	if (err)
		goto out;
	err = pack_root_pwd(desc);

out:
	return err;
}

/** HCC kernel hook for FAF lseek function.
 *  @author Innogrid HCC
 *
 *  @param file    File to seek in.
 *  @param offset  Offset to seek at.
 *  @param origin  Origin of the seek.
 */
off_t hcc_faf_lseek (struct file * file,
		     off_t offset,
		     unsigned int origin)
{
	faf_client_data_t *data = file->private_data;
	struct faf_seek_msg msg;
	off_t r;
	struct grpc_desc* desc;

	msg.server_fd = data->server_fd;
	msg.offset = offset;
	msg.origin = origin;

	desc = grpc_begin(GRPC_FAF_LSEEK, data->server_id);

	grpc_pack_type(desc, msg);

	grpc_unpack_type(desc, r);

	grpc_end(desc, 0);

	return r;
}

/** HCC kernel hook for FAF llseek function.
 *  @author Innogrid HCC
 *
 *  @param file          File to seek in.
 *  @param offset_high   High part of the offset to seek at.
 *  @param offset_low    Low part of the offset to seek at.
 *  @param result        ...
 *  @param origin        Origin of the seek.
 */
long hcc_faf_llseek (struct file *file,
		     unsigned long offset_high,
		     unsigned long offset_low,
		     loff_t * result,
		     unsigned int origin)
{
	faf_client_data_t *data = file->private_data;
	struct faf_llseek_msg msg;
	long r;
	struct grpc_desc* desc;

	msg.server_fd = data->server_fd;
	msg.offset_high = offset_high;
	msg.offset_low = offset_low;
	msg.origin = origin;

	desc = grpc_begin(GRPC_FAF_LLSEEK, data->server_id);

	grpc_pack_type(desc, msg);

	grpc_unpack_type(desc, r);
	grpc_unpack(desc, 0, result, sizeof(*result));

	grpc_end(desc, 0);

	return r;
}

/** HCC kernel hook for FAF read function.
 *  @author Innogrid HCC
 *
 *  @param file          File to read from.
 *  @param buf           Buffer to store data in.
 *  @param count         Number of bytes to read.
 *  @param pos           Offset to read from (updated at the end).
 */
ssize_t hcc_faf_read(struct file * file, char *buf, size_t count, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	ssize_t nr;
	ssize_t received = 0;
	loff_t fpos;
	char *kbuff;
	int err;
	struct grpc_desc *desc;

	kbuff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuff)
		return -ENOMEM;

	msg.server_fd = data->server_fd;
	msg.count = count;
	msg.pos = *pos;

	nr = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_READ, data->server_id);
	if (!desc)
		goto out;

	/* Send read request */
	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;

	/* Get number of bytes to receive */
	err = unpack_remote_sleep_res_type(desc, nr);
	if (err)
		goto cancel;

	while (nr > 0) {
		/* Receive file data */
		err = grpc_unpack(desc, 0, kbuff, nr);
		if (err)
			goto cancel;
		err = copy_to_user(&buf[received], kbuff, nr);
		if (err) {
			nr = -EFAULT;
			break;
		}
		received += nr;
		err = unpack_remote_sleep_res_type(desc, nr);
		if (err)
			goto cancel;
	}

	if (!nr)
		/* no error occurs when reading */
		nr = received;

	/* Receive the updated offset */
	err = grpc_unpack_type(desc, fpos);
	if (err)
		goto cancel;
	*pos = fpos;

out_end:
	grpc_end(desc, 0);

out:
	kfree(kbuff);

	return nr;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	nr = err;
	goto out_end;
}

/** HCC kernel hook for FAF write function.
 *  @author Innogrid HCC
 *
 *  @param file          File to write to.
 *  @param buf           Buffer of data to write.
 *  @param count         Number of bytes to write.
 *  @param pos           Offset to write from (updated at the end).
 */
ssize_t hcc_faf_write(struct file * file, const char *buf,
		      size_t count, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	ssize_t buf_size = PAGE_SIZE, nr;
	long offset = 0;
	long to_send = count;
	loff_t fpos;
	char *kbuff;
	int err;
	struct grpc_desc *desc;

	kbuff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!kbuff)
		return -ENOMEM;

	msg.server_fd = data->server_fd;
	msg.count = count;
	msg.pos = *pos;

	nr = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_WRITE, data->server_id);
	if (!desc)
		goto out;

	/* Send write request */
	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;

	while (to_send > 0) {
		if (to_send < PAGE_SIZE)
			buf_size = to_send;

		err = copy_from_user(kbuff, &buf[offset], buf_size);
		if (err)
			buf_size = -EFAULT;

		err = grpc_pack_type(desc, buf_size);
		if (err)
			goto cancel;

		if (buf_size < 0) /* copy_from_user has failed */
			break;

		err = grpc_pack(desc, 0, kbuff, buf_size);
		if (err)
			goto cancel;

		to_send -= buf_size;
		offset += buf_size;
	}

	err = unpack_remote_sleep_res_type(desc, nr);
	if (err)
		nr = err;
	else if (nr == -EPIPE)
		send_sig(SIGPIPE, current, 0);

	/* Receive the updated offset */
	err = grpc_unpack_type(desc, fpos);
	if (err)
		goto cancel;
	*pos = fpos;

out_end:
	grpc_end(desc, 0);

out:
	kfree(kbuff);

	return nr;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	nr = err;
	goto out_end;
}

ssize_t hcc_faf_readv(struct file *file, const struct iovec __user *vec,
		      unsigned long vlen, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	struct faf_rw_ret ret;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	int iovcnt;
	size_t total_len;
	struct grpc_desc *desc;
	int err;

	ret.ret = rw_copy_check_uvector(READ, vec, vlen,
					ARRAY_SIZE(iovstack), iovstack, &iov, 1);
	if (ret.ret < 0)
		return ret.ret;
	iovcnt = vlen;
	total_len = ret.ret;

	ret.ret = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_READV, data->server_id);
	if (!desc)
		goto out;

	msg.server_fd = data->server_fd;
	msg.count = total_len;
	msg.pos = *pos;
	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, ret);
	if (err)
		goto cancel;

	*pos = ret.pos;
	if (ret.ret <= 0)
		goto out_end;

	err = recv_iov(desc, iov, iovcnt, ret.ret, MSG_USER);
	if (err)
		goto cancel;

out_end:
	grpc_end(desc, 0);

out:
	if (iov != iovstack)
		kfree(iov);

	return ret.ret;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	ret.ret = err;
	goto out_end;
}

ssize_t hcc_faf_writev(struct file *file, const struct iovec __user *vec,
		       unsigned long vlen, loff_t *pos)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	struct faf_rw_ret ret;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	int iovcnt;
	size_t total_len;
	struct grpc_desc *desc;
	int err;

	ret.ret = rw_copy_check_uvector(WRITE, vec, vlen,
					ARRAY_SIZE(iovstack), iovstack, &iov, 1);
	if (ret.ret < 0)
		return ret.ret;
	iovcnt = vlen;
	total_len = ret.ret;

	ret.ret = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_WRITEV, data->server_id);
	if (!desc)
		goto out;

	msg.server_fd = data->server_fd;
	msg.count = total_len;
	msg.pos = *pos;
	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = send_iov(desc, iov, iovcnt, total_len, MSG_USER);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, ret);
	if (err)
		goto cancel;

	*pos = ret.pos;
	if (ret.ret == -EPIPE)
		send_sig(SIGPIPE, current, 0);

out_end:
	grpc_end(desc, 0);

out:
	if (iov != iovstack)
		kfree(iov);

	return ret.ret;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	ret.ret = err;
	goto out_end;
}

int hcc_faf_getdents(struct file *file, enum getdents_filler filler,
		     void *dirent, unsigned int count)
{
	faf_client_data_t *data = file->private_data;
	struct faf_getdents_msg msg;
	struct grpc_desc *desc;
	int err, err_grpc;

	err = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_GETDENTS, data->server_id);
	if (!desc)
		goto out;

	msg.server_fd = data->server_fd;
	msg.filler = filler;
	msg.count = count;

	err_grpc = grpc_pack_type(desc, msg);
	if (err_grpc)
		goto cancel;

	err_grpc = grpc_unpack_type(desc, err);
	if (err_grpc)
		goto cancel;

	if (err <= 0)
		goto out_end;

	/* err contains the used size of the buffer */
	err_grpc = grpc_unpack(desc, 0, dirent, err);

	if (err_grpc)
		goto cancel;

out_end:
	grpc_end(desc, 0);

out:
	return err;

cancel:
	grpc_cancel(desc);
	err = err_grpc;
	goto out;
}

/** HCC kernel hook for FAF ioctl function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do an ioctl to.
 *  @param cmd           IOCTL command.
 *  @param arg           IOCTL argument.
 */
long hcc_faf_ioctl (struct file *file,
		    unsigned int cmd,
		    unsigned long arg)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	long r;
	struct grpc_desc *desc;
	int err;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;
	msg.arg = arg;

	err = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_IOCTL, data->server_id);
	if (!desc)
		goto out_err;

	err = grpc_pack_type(desc, msg);
	if (err)
		goto out_cancel;
	err = pack_context(desc);
	if (err)
		goto out_cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto out_cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto out_cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto out_cancel;
	grpc_end(desc, 0);

out:
	return r;

out_cancel:
	grpc_cancel(desc);
	grpc_end(desc, 0);
	if (err > 0)
		err = -ENOMEM;
out_err:
	r = err;
	goto out;
}

/** HCC kernel hook for FAF fcntl function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do an fcntl to.
 *  @param cmd           FCNTL command.
 *  @param arg           FCNTL argument.
 */
long hcc_faf_fcntl (struct file *file,
		    unsigned int cmd,
		    unsigned long arg)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	struct grpc_desc *desc;
	int err;
	long r;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;
	r = -EFAULT;
	if ((cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK)
	    && copy_from_user(&msg.flock,
			      (struct flock __user *) arg, sizeof(msg.flock)))
			goto out;
	else if ((cmd == F_GETOWN_EX || cmd == F_SETOWN_EX)
	    && copy_from_user(&msg.owner,
			      (struct f_owner_ex __user *) arg, sizeof(msg.owner)))
			goto out;
	else
		msg.arg = arg;

	r = -ENOLCK;
	desc = grpc_begin(GRPC_FAF_FCNTL, data->server_id);
	if (unlikely(!desc))
		goto out;

	err = grpc_pack_type(desc, msg);
	if (unlikely(err))
		goto cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (unlikely(err))
		goto cancel;

	if (!r) {
		if (cmd == F_GETLK) {
			err = grpc_unpack_type(desc, msg.flock);
			if (unlikely(err))
				goto cancel;
			r = -EFAULT;
			if (!copy_to_user((struct flock __user *) arg,
					&msg.flock, sizeof(msg.flock)))
				r = 0;
		} else if (cmd == F_GETOWN_EX) {
			err = grpc_unpack_type(desc, msg.owner);
			if (unlikely(err))
				goto cancel;
			r = -EFAULT;
			if (!copy_to_user((struct f_owner_ex __user *) arg,
					&msg.owner, sizeof(msg.owner)))
				r = 0;
		}
	}

out_end:
	grpc_end(desc, 0);

out:
	return r;

cancel:
	grpc_cancel(desc);
	goto out_end;
}

#if BITS_PER_LONG == 32
/** HCC kernel hook for FAF fcntl64 function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do an fcntl to.
 *  @param cmd           FCNTL command.
 *  @param arg           FCNTL argument.
 */
long hcc_faf_fcntl64 (struct file *file,
		      unsigned int cmd,
		      unsigned long arg)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	long r;
	struct grpc_desc* desc;
	int err;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;
	r = -EFAULT;
	if ((cmd == F_GETLK64 || cmd == F_SETLK64 || cmd == F_SETLKW64)
	    && copy_from_user(&msg.flock64,
			      (struct flock64 __user *) arg, sizeof(msg.flock64)))
			goto out;
	else
		msg.arg = arg;

	r = -ENOLCK;
	desc = grpc_begin(GRPC_FAF_FCNTL64,
			 data->server_id);
	if (unlikely(!desc))
		goto out;

	err = grpc_pack_type(desc, msg);
	if (unlikely(err))
		goto cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (unlikely(err))
		goto cancel;

	if (!r && cmd == F_GETLK64) {
		err = grpc_unpack_type(desc, msg.flock64);
		if (unlikely(err))
			goto cancel;
		r = -EFAULT;
		if (!copy_to_user((struct flock64 __user *) arg,
				  &msg.flock64, sizeof(msg.flock64)))
			r = 0;
	}

out_end:
	grpc_end(desc, 0);

out:
	return r;

cancel:
	grpc_cancel(desc);
	goto out_end;
}
#endif

/** HCC kernel hook for FAF fstat function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do an fcntl to.
 *  @param statbuf       Kernel buffer to store file stats.
 */
long hcc_faf_fstat (struct file *file,
		    struct kstat *statbuf)
{
	struct kstat buffer;
	faf_client_data_t *data = file->private_data;
	struct faf_stat_msg msg;
	long r;
	struct grpc_desc* desc;

	msg.server_fd = data->server_fd;

	desc = grpc_begin(GRPC_FAF_FSTAT, data->server_id);

	grpc_pack_type(desc, msg);

	grpc_unpack_type(desc, r);
	grpc_unpack_type(desc, buffer);

	grpc_end(desc, 0);

	*statbuf = buffer;

	return r;
}

/** HCC kernel hook for FAF fstat function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do an fcntl to.
 *  @param statbuf       Kernel buffer to store file stats.
 */
long hcc_faf_fstatfs(struct file *file,
		     struct statfs *statfsbuf)
{
	struct statfs buffer;
	faf_client_data_t *data = file->private_data;
	struct faf_statfs_msg msg;
	long r;
	enum grpc_error err;
	struct grpc_desc *desc;

	msg.server_fd = data->server_fd;

	desc = grpc_begin(GRPC_FAF_FSTATFS, data->server_id);

	r = grpc_pack_type(desc, msg);
	if (r)
		goto exit;

	err = grpc_unpack_type(desc, r);
	if (err)
		goto err_grpc;

	if (!r)
		err = grpc_unpack_type(desc, buffer);

	grpc_end(desc, 0);

	*statfsbuf = buffer;

exit:
	return r;
err_grpc:
	r = -EPIPE;
	goto exit;
}

/** HCC kernel hook for FAF fsync function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do a fsync to.
 */
long hcc_faf_fsync (struct file *file)
{
	faf_client_data_t *data = file->private_data;
	struct faf_rw_msg msg;
	long r;

	msg.server_fd = data->server_fd;

	r = grpc_sync(GRPC_FAF_FSYNC, data->server_id, &msg, sizeof(msg));

	return r;
}

/** HCC kernel hook for FAF flock function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do a flock to.
 */
long hcc_faf_flock (struct file *file,
		    unsigned int cmd)
{
	faf_client_data_t *data = file->private_data;
	struct faf_ctl_msg msg;
	struct grpc_desc *desc;
	long r;
	int err;

	msg.server_fd = data->server_fd;
	msg.cmd = cmd;

	desc = grpc_begin(GRPC_FAF_FLOCK, data->server_id);
	if (!desc)
		return -ENOMEM;

	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;

out_end:
	grpc_end(desc, 0);
	return r;

cancel:
	grpc_cancel(desc);
	r = err;
	goto out_end;
}

static char *__hcc_faf_d_path(const struct path *root, const struct file *file,
			      char *buff, int size, bool *deleted)
{
	faf_client_data_t *data = file->private_data;
	struct faf_d_path_msg msg;
	struct grpc_desc* desc;
	int len;
	int err;

	BUG_ON(file->f_flags & O_FAF_SRV);

	msg.server_fd = data->server_fd;
	msg.deleted = !!deleted;
	msg.count = size;

	desc = grpc_begin(GRPC_FAF_D_PATH, data->server_id);
	if (!desc)
		return ERR_PTR(-ENOMEM);
	err = grpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	err = pack_creds(desc, current_cred());
	if (err)
		goto err_cancel;
	err = pack_path(desc, root);
	if (err)
		goto err_cancel;

	err = grpc_unpack_type(desc, len);
	if (err)
		goto err_cancel;
	if (len >= 0) {
		err = grpc_unpack(desc, 0, buff, len);
		if (err)
			goto err_cancel;
		if (deleted) {
			err = grpc_unpack_type(desc, *deleted);
			if (err)
				goto err_cancel;
		}
	} else {
		buff = ERR_PTR(len);
	}
out_end:
	grpc_end(desc, 0);

	return buff;

err_cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	buff = ERR_PTR(err);
	goto out_end;
}

char *hcc_faf_phys_d_path(const struct file *file, char *buff, int size,
			  bool *deleted)
{
	struct path root;
	char *ret;

	get_physical_root(&root);
	ret = __hcc_faf_d_path(&root, file, buff, size, deleted);
	path_put(&root);

	return ret;
}

/** HCC FAF d_path function.
 *  @author Innogrid HCC
 *
 *  @param file     The file to get the path.
 *  @param buff     Buffer to store the path in.
 */
char *
hcc_faf_d_path(const struct file *file, char *buff, int size, bool *deleted)
{
	struct path root;
	char *ret;

	read_lock(&current->fs->lock);
	root = current->fs->root;
	path_get(&root);
	read_unlock(&current->fs->lock);

	ret = __hcc_faf_d_path(&root, file, buff, size, deleted);

	path_put(&root);

	return ret;
}

int hcc_faf_do_path_lookup(struct file *file,
			   const char *name,
			   unsigned int flags,
			   struct nameidata *nd)
{
	char *tmp = (char *) __get_free_page (GFP_KERNEL);
	char *path;
	bool deleted;
	int len, err = 0;

	path = hcc_faf_d_path(file, tmp, PAGE_SIZE, &deleted);

	if (IS_ERR(path)) {
		err = PTR_ERR(path);
		goto exit;
	}
	if (deleted) {
		err = -ENOENT;
		goto exit;
	}


	if (likely(path != tmp)) {
		strncpy(tmp, path, PAGE_SIZE);
		path = tmp;
	}

	len = strlen (path);
	strncpy(&path[len], name, PAGE_SIZE - len);

	err = path_lookup(path, flags, nd);
exit:
	free_page ((unsigned long) tmp);
	return err;
}

long hcc_faf_bind (struct file * file,
		   struct sockaddr __user *umyaddr,
		   int addrlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct grpc_desc *desc;
	int err, r;

	msg.server_fd = data->server_fd;

	r = move_addr_to_kernel(umyaddr, addrlen, (struct sockaddr *)&msg.sa);
	if (r)
		goto out;

	msg.addrlen = addrlen;

	r = -ENOMEM;
	desc = grpc_begin(GRPC_FAF_BIND, data->server_id);
	if (!desc)
		goto out;

	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;
	err = pack_context(desc);
	if (err)
		goto cancel;

	err = grpc_unpack_type(desc, r);
	if (err)
		goto cancel;

out_end:
	grpc_end(desc, 0);
out:
	return r;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	r = err;
	goto out_end;
}



long hcc_faf_connect (struct file * file,
		      struct sockaddr __user *uservaddr,
		      int addrlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct grpc_desc *desc;
	int r, err;

	msg.server_fd = data->server_fd;

	r = move_addr_to_kernel(uservaddr, addrlen, (struct sockaddr *)&msg.sa);
	if (r)
		goto out;

	msg.addrlen = addrlen;

	desc = grpc_begin(GRPC_FAF_CONNECT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;
	err = pack_context(desc);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;

out_end:
	grpc_end(desc, 0);

out:
	return r;

cancel:
	grpc_cancel(desc);
	r = err;
	goto out_end;
}

long hcc_faf_listen (struct file * file,
		     int backlog)
{
	faf_client_data_t *data = file->private_data;
	struct faf_listen_msg msg;
	int r;

	msg.server_fd = data->server_fd;

	msg.backlog = backlog;

	r = grpc_sync(GRPC_FAF_LISTEN, data->server_id, &msg, sizeof(msg));

	return r;
}

long hcc_faf_accept(struct file * file,
		    struct sockaddr __user *upeer_sockaddr,
		    int __user *upeer_addrlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	int r, err;
	struct sockaddr_storage sa;
	int sa_len;
	struct file *newfile;
	int fd;
	struct grpc_desc* desc;

	BUG_ON (data->server_id == hcc_node_id);

	fd = get_unused_fd();
	if (fd < 0) {
		r = fd;
		goto out;
	}

	msg.server_fd = data->server_fd;

	if (upeer_sockaddr) {
		if (get_user(msg.addrlen, upeer_addrlen)) {
			r = -EFAULT;
			goto out_put_fd;
		}
	} else {
		msg.addrlen = 0;
	}

	desc = grpc_begin(GRPC_FAF_ACCEPT, data->server_id);
	if (!desc)
		goto out_put_fd;

	r = grpc_pack_type(desc, msg);
	if (r)
		goto err_cancel;

	r = unpack_remote_sleep_res_prepare(desc);
	if (r)
		goto err_cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err) {
		r = err;
		goto err_cancel;
	}

	if (r<0) {
		grpc_end(desc, 0);
		goto out_put_fd;
	}

	r = grpc_unpack_type(desc, sa_len);
	if (r)
		goto err_cancel;

	r = grpc_unpack(desc, 0, &sa, sa_len);
	if (r)
		goto err_cancel;

	newfile = rcv_faf_file_desc(desc);
	if (IS_ERR(newfile)) {
		r = PTR_ERR(newfile);
		goto err_cancel;
	}

	/*
	 * We have enough to clean up the new file ourself if needed. Tell it
	 * to the server.
	 */
	r = grpc_pack_type(desc, fd);
	if (r)
		goto err_close_faf_file;

	grpc_end(desc, 0);

	if (upeer_sockaddr) {
		r = move_addr_to_user((struct sockaddr *)&sa, sa_len,
				      upeer_sockaddr, upeer_addrlen);
		if (r)
			goto err_close_faf_file;
	}

	fd_install(fd, newfile);
	r = fd;

out:
	return r;

err_cancel:
	grpc_cancel(desc);
	grpc_end(desc, 0);
out_put_fd:
	put_unused_fd(fd);
	goto out;

err_close_faf_file:
	fput(newfile);
	goto out_put_fd;
}

long hcc_faf_getsockname (struct file * file,
			  struct sockaddr __user *usockaddr,
			  int __user *usockaddr_len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct sockaddr_storage sa;
	int sa_len;
	struct grpc_desc *desc;
	int r = -EFAULT;

	msg.server_fd = data->server_fd;
	if (get_user(msg.addrlen, usockaddr_len))
		goto out;

	desc = grpc_begin(GRPC_FAF_GETSOCKNAME, data->server_id);
	grpc_pack_type(desc, msg);
	pack_root(desc);

	grpc_unpack_type(desc, r);
	grpc_unpack_type(desc, sa_len);
	grpc_unpack(desc, 0, &sa, sa_len);
	grpc_end(desc, 0);

	if (!r)
		r = move_addr_to_user((struct sockaddr *)&sa, sa_len,
				      usockaddr, usockaddr_len);

out:
	return r;
}

long hcc_faf_getpeername (struct file * file,
			  struct sockaddr __user *usockaddr,
			  int __user *usockaddr_len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_bind_msg msg;
	struct sockaddr_storage sa;
	int sa_len;
	struct grpc_desc *desc;
	int r;

	msg.server_fd = data->server_fd;

	if (get_user(msg.addrlen, usockaddr_len))
		return -EFAULT;

	desc = grpc_begin(GRPC_FAF_GETPEERNAME, data->server_id);
	grpc_pack_type(desc, msg);
	pack_root(desc);
	grpc_unpack_type(desc, r);
	grpc_unpack_type(desc, sa_len);
	grpc_unpack(desc, 0, &sa, sa_len);
	grpc_end(desc, 0);

	if (!r)
		r = move_addr_to_user((struct sockaddr *)&sa, sa_len,
				      usockaddr, usockaddr_len);

	return r;
}

long hcc_faf_shutdown (struct file * file,
		       int how)
{
	faf_client_data_t *data = file->private_data;
	struct faf_shutdown_msg msg ;
	int r;

	msg.server_fd = data->server_fd;

	msg.how = how;

	r = grpc_sync(GRPC_FAF_SHUTDOWN, data->server_id, &msg, sizeof(msg));

	return r;
}

long hcc_faf_setsockopt (struct file * file,
			 int level,
			 int optname,
			 char __user *optval,
			 int optlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_setsockopt_msg msg;
	struct grpc_desc *desc;
	int r, err;

	msg.server_fd = data->server_fd;

	msg.level = level;
	msg.optname = optname;
	msg.optval = optval;
	msg.optlen = optlen;

	desc = grpc_begin(GRPC_FAF_SETSOCKOPT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = grpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	err = pack_context(desc);
	if (err)
		goto err_cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto err_cancel;
	err = grpc_unpack_type(desc, r);
	if (err)
		goto err_cancel;

out_end:
	grpc_end(desc, 0);

out:
	return r;

err_cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -ENOMEM;
	r = err;
	goto out_end;
}

long hcc_faf_getsockopt (struct file * file,
			 int level,
			 int optname,
			 char __user *optval,
			 int __user *optlen)
{
	faf_client_data_t *data = file->private_data;
	struct faf_getsockopt_msg msg;
	int r, err;
	struct grpc_desc *desc;

	msg.server_fd = data->server_fd;

	msg.level = level;
	msg.optname = optname;
	msg.optval = optval;
	msg.optlen = optlen;

	desc = grpc_begin(GRPC_FAF_GETSOCKOPT, data->server_id);
	if (!desc) {
		r = -ENOMEM;
		goto out;
	}

	err = grpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	err = pack_context(desc);
	if (err)
		goto err_cancel;
	err = handle_ruaccess(desc);
	if (err)
		goto err_cancel;
	err = grpc_unpack_type(desc, r);
	if (err)
		goto err_cancel;

out_end:
	grpc_end(desc, 0);

out:
	return r;

err_cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -ENOMEM;
	r = err;
	goto out_end;
}

ssize_t hcc_faf_sendmsg(struct file *file, struct msghdr *msghdr,
			size_t total_len)
{
	faf_client_data_t *data = file->private_data;
	struct faf_sendmsg_msg msg;
	ssize_t r;
	int err;
	struct grpc_desc* desc;

	msg.server_fd = data->server_fd;
	msg.total_len = total_len;
	msg.flags = msghdr->msg_flags;

	desc = grpc_begin(GRPC_FAF_SENDMSG, data->server_id);
	if (!desc)
		return -ENOMEM;
	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = send_msghdr(desc, msghdr, total_len, MSG_USER);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;
	if (r == -EPIPE && !(msghdr->msg_flags & MSG_NOSIGNAL))
		send_sig(SIGPIPE, current, 0);

out_end:
	grpc_end(desc, 0);

	return r;

cancel:
	grpc_cancel(desc);
	r = err;
	goto out_end;
}

ssize_t hcc_faf_recvmsg(struct file *file, struct msghdr *msghdr,
			size_t total_len, unsigned int flags)
{
	faf_client_data_t *data = file->private_data;
	struct faf_sendmsg_msg msg;
	ssize_t r;
	int err;
	struct grpc_desc* desc;

	msg.server_fd = data->server_fd;
	msg.total_len = total_len;
	msg.flags = flags;

	desc = grpc_begin(GRPC_FAF_RECVMSG, data->server_id);
	if (!desc)
		return -ENOMEM;
	err = grpc_pack_type(desc, msg);
	if (err)
		goto cancel;

	err = send_msghdr(desc, msghdr, total_len, MSG_USER|MSG_HDR_ONLY);
	if (err)
		goto cancel;

	err = unpack_remote_sleep_res_prepare(desc);
	if (err)
		goto cancel;
	err = unpack_remote_sleep_res_type(desc, r);
	if (err)
		goto cancel;

	if (r < 0)
		goto out_end;

	/* Careful, caller may have set MSG_TRUNC */
	err = recv_msghdr(desc, msghdr, min_t(size_t, r, total_len), MSG_USER);
	if (err)
		goto cancel;

	/* Behave as sock_recvmsg() */
	msghdr->msg_control += msghdr->msg_controllen;

out_end:
	grpc_end(desc, 0);

	return r;

cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -EPIPE;
	r = err;
	goto out_end;
}

void hcc_faf_srv_close(struct file *file)
{
	check_close_faf_srv_file(file);
}

int hcc_faf_poll_wait(struct file *file, int wait)
{
	faf_client_data_t *data = file->private_data;
	struct faf_poll_wait_msg msg;
	struct grpc_desc *desc;
	unsigned int revents;
	int err = -ENOMEM, res = 0;
	long old_state = current->state;

	data->poll_revents = 0;

	msg.server_fd = data->server_fd;
	msg.objid = file->f_objid;
	msg.wait = wait;

	desc = grpc_begin(GRPC_FAF_POLL_WAIT, data->server_id);
	if (!desc)
		goto out;
	err = grpc_pack_type(desc, msg);
	if (err)
		goto err_cancel;
	if (wait) {
		err = grpc_unpack_type(desc, res);
		if (err)
			goto err_cancel;
	}
	err = grpc_unpack_type(desc, revents);
	if (err)
		goto err_cancel;

	if (res)
		err = res;
	data->poll_revents = revents;

out_end:
	grpc_end(desc, 0);

out:
	/*
	 * after sleeping grpc_unpack() returns with
	 * current->state == TASK_RUNNING
	 */
	set_current_state(old_state);
	return err;

err_cancel:
	grpc_cancel(desc);
	if (err > 0)
		err = -ENOMEM;
	goto out_end;
}

void hcc_faf_poll_dequeue(struct file *file)
{
	faf_client_data_t *data = file->private_data;
	struct faf_notify_msg msg;
	int err;

	msg.server_fd = data->server_fd;
	msg.objid = file->f_objid;
	err = grpc_async(GRPC_FAF_POLL_DEQUEUE, data->server_id,
			&msg, sizeof(msg));
	if (err)
		printk("faf_poll: memory leak on server %d!\n", data->server_id);
}

/** HCC kernel hook for FAF poll function.
 *  @author Innogrid HCC
 *
 *  @param file          File to do a poll to.
 */
unsigned int faf_poll (struct file *file,
		       struct poll_table_struct *wait)
{
	faf_client_data_t *data = file->private_data;
	unsigned int revents;
	long old_state = current->state;

	mutex_lock(&faf_poll_mutex);
	/* Waking up from mutex_lock() sets current->state to TASK_RUNNING */
	set_current_state(old_state);
	poll_wait(file, &data->poll_wq, wait);
	if (!wait)
		hcc_faf_poll_wait(file, 0);
	revents = data->poll_revents;
	mutex_unlock(&faf_poll_mutex);

	return revents;
}

static void handle_faf_poll_notify(struct grpc_desc *desc,
				   void *_msg,
				   size_t size)
{
	unsigned long dvfs_id = *(unsigned long *)_msg;
	struct dvfs_file_struct *dvfs_file;
	faf_client_data_t *data;

	dvfs_file = _gdm_get_object_no_ft(dvfs_file_struct_ctnr, dvfs_id);
	if (dvfs_file && dvfs_file->file) {
		/* TODO: still required? */
		if (atomic_long_read (&dvfs_file->file->f_count) == 0)
			dvfs_file->file = NULL;
	}
	if (!dvfs_file || !dvfs_file->file)
		goto out_put_dvfs_file;

	data = dvfs_file->file->private_data;
	wake_up_interruptible_all(&data->poll_wq);

out_put_dvfs_file:
	_gdm_put_object(dvfs_file_struct_ctnr, dvfs_id);
}

struct file_operations faf_file_ops = {
	poll: faf_poll,
};



/* FAF Hooks Initialisation */

void faf_hooks_init (void)
{
	grpc_register_void(GRPC_FAF_POLL_NOTIFY, handle_faf_poll_notify, 0);
}

/* FAF Hooks Finalization */
void faf_hooks_finalize (void)
{
}
