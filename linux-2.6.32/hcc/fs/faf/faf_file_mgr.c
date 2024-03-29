/** Global management of faf files.
 *  @file faf_file_mgr.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/file.h>
#include <linux/wait.h>
#include <gdm/gdm.h>
#include <net/grpc/grpc.h>
#include <hcc/file.h>
#include <hcc/physical_fs.h>
#include "../mobility.h"
#include <hcc/action.h>
#include <hcc/app_shared.h>

#include "faf_internal.h"
#include "faf_hooks.h"
#include <hcc/regular_file_mgr.h>

struct kmem_cache *faf_client_data_cachep;
extern const struct file_operations tty_fops;
extern const struct file_operations hung_up_tty_fops;

/** Create a faf file struct from a HCC file descriptor.
 *  @author Innogrid HCC
 *
 *  @param task    Task to create the file for.
 *  @param desc    HCC file descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
struct file *create_faf_file_from_hcc_desc (struct task_struct *task,
                                            void *_desc)
{
	faf_client_data_t *desc = _desc, *data;
	struct file *file = NULL;

	data = kmem_cache_alloc (faf_client_data_cachep, GFP_KERNEL);
	if (!data)
		return NULL;

	file = get_empty_filp ();

	if (!file) {
		kmem_cache_free (faf_client_data_cachep, data);
		goto exit;
	}

	*data = *desc;
	init_waitqueue_head(&data->poll_wq);

	file->f_dentry = NULL;
	file->f_op = &faf_file_ops;
	file->f_flags = desc->f_flags | O_FAF_CLT;
	file->f_mode = desc->f_mode;
	file->f_pos = desc->f_pos;
	file->private_data = data;

exit:
	return file;
}

void fill_faf_file_hcc_desc(faf_client_data_t *data, struct file *file)
{
	unsigned int flags = file->f_flags & (~O_FAF_SRV);

	if (file->f_op == &tty_fops
	    || file->f_op == &hung_up_tty_fops)
		flags |= O_FAF_TTY;

	data->f_flags = flags;
	data->f_mode = file->f_mode;
	data->f_pos = file->f_pos;
	data->server_id = hcc_node_id;
	data->server_fd = file->f_faf_srv_index;
	data->i_mode = file->f_dentry->d_inode->i_mode;

	if (S_ISFIFO(file->f_dentry->d_inode->i_mode)
	    && strlen(file->f_dentry->d_name.name))
		data->is_named_pipe = 1;
	else
		data->is_named_pipe = 0;
}


/** Return a hcc descriptor corresponding to the given file.
 *  @author Innogrid HCC
 *
 *  @param file       The file to get a HCC descriptor for.
 *  @param desc       The returned descriptor.
 *  @param desc_size  Size of the returned descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int get_faf_file_hcc_desc (struct file *file,
                           void **desc,
                           int *desc_size)
{
	faf_client_data_t *data, *ldata;

	data = kmalloc(sizeof(faf_client_data_t), GFP_KERNEL);
	if (data == NULL)
		return -ENOMEM;

	/* The file descriptor is already a FAF client desc */

	if (file->f_flags & O_FAF_CLT) {
		ldata = file->private_data;
		*data = *ldata;
		goto done;
	}

	BUG_ON (!(file->f_flags & O_FAF_SRV));

	fill_faf_file_hcc_desc(data, file);

done:
	*desc = data;
	*desc_size = sizeof (faf_client_data_t);

	return 0;
}

/*****************************************************************************/
/*                                                                           */
/*                            FAF FILES IMPORT/EXPORT                        */
/*                                                                           */
/*****************************************************************************/

/** Export a faf file descriptor into the given ghost.
 *  @author Innogrid HCC
 *
 *  @param ghost    The ghost to write data to.
 *  @param tsk      Task we are exporting.
 *  @parem index    Index of the exported file in the open files array.
 *  @param file     The file to export.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int faf_file_export (struct gpm_action *action,
		     ghost_t *ghost,
		     struct task_struct *task,
		     int index,
		     struct file *file)
{
	void *desc;
	int desc_size;
	int r = 0;

	BUG_ON(action->type == GPM_CHECKPOINT);

	r = get_faf_file_hcc_desc(file, &desc, &desc_size);
	if (r)
		goto error;

	r = ghost_write_file_hcc_desc(ghost, desc, desc_size);
	kfree(desc);

error:
	return r;
}

/** Import a faf file descriptor from the given ghost.
 *  @author Innogrid HCC
 *
 *  @param ghost          The ghost to read data from.
 *  @param task           The task data are imported for.
 *  @param returned_file  The file struct where data should be imported to.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int faf_file_import (struct gpm_action *action,
		     ghost_t *ghost,
		     struct task_struct *task,
		     struct file **returned_file)
{
	void *desc;
	struct file *file;
	int r, desc_size;

	BUG_ON(action->type == GPM_CHECKPOINT);

	r = ghost_read_file_hcc_desc(ghost, &desc, &desc_size);
	if (r)
		goto exit;

	file = create_faf_file_from_hcc_desc (task, desc);

	if (IS_ERR(file)) {
		r = PTR_ERR(file);
		goto exit_free_desc;
	}
	*returned_file = file;

exit_free_desc:
	kfree(desc);
exit:
	return r;
}

struct dvfs_mobility_operations dvfs_mobility_faf_ops = {
	.file_export = faf_file_export,
	.file_import = faf_file_import,
};

int __send_faf_file_desc(struct grpc_desc *desc, struct file *file)
{
	int r, fdesc_size;
	void *fdesc;

	BUG_ON(!file->f_objid);
	BUG_ON(!(file->f_flags & (O_FAF_SRV|O_FAF_CLT)));

	r = get_faf_file_hcc_desc(file, &fdesc, &fdesc_size);
	if (r)
		goto out;

	r = grpc_pack_type(desc, file->f_objid);
	if (r)
		goto out_free_fdesc;

	r = grpc_pack_type(desc, fdesc_size);
	if (r)
		goto out_free_fdesc;

	r = grpc_pack(desc, 0, fdesc, fdesc_size);
	if (r)
		goto out_free_fdesc;

out_free_fdesc:
	kfree(fdesc);

out:
	return r;
}

int send_faf_file_desc(struct grpc_desc *desc, struct file *file)
{
	int r;

	if (!file->f_objid) {
		r = create_gdm_file_object(file);
		if (r)
			goto out;
	}

	if (!(file->f_flags & (O_FAF_SRV|O_FAF_CLT))) {
		r = setup_faf_file(file);
		if (r && r != -EALREADY)
			goto out;
	}

	r = __send_faf_file_desc(desc, file);

out:
	return r;
}

struct file *rcv_faf_file_desc(struct grpc_desc *desc)
{
	int r, first_import;
	void *fdesc;
	int fdesc_size;
	long fobjid;
	struct dvfs_file_struct *dvfs_file = NULL;
	struct file *file = NULL;

	r = grpc_unpack_type(desc, fobjid);
	if (r)
		goto error;

	r = grpc_unpack_type(desc, fdesc_size);
	if (r)
		goto error;

	fdesc = kmalloc(GFP_KERNEL, fdesc_size);
	if (!fdesc) {
		r = -ENOMEM;
		goto error;
	}

	r = grpc_unpack(desc, 0, fdesc, fdesc_size);
	if (r)
		goto err_free_desc;

	/* Check if the file struct is already present */
	first_import = 0;

	file = begin_import_dvfs_file(fobjid, &dvfs_file);

	if (!file) {
		file = create_faf_file_from_hcc_desc(current, fdesc);
		first_import = 1;
	}

	r = end_import_dvfs_file(fobjid, dvfs_file, file, first_import);
	if (r)
		goto err_free_desc;

err_free_desc:
	kfree(fdesc);

error:
	if (r)
		file = ERR_PTR(r);

	return file;
}
