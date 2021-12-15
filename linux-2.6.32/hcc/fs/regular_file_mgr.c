/** Global management of regular files.
 *  @file regular_file_mgr.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/file.h>
#ifdef CONFIG_HCC_GIPC
#include <linux/ipc.h>
#include <linux/shm.h>
#include <linux/msg.h>
#include <linux/ipc_namespace.h>
#endif
#include <gdm/gdm.h>
#include <hcc/action.h>
#include <hcc/application.h>
#include <hcc/app_shared.h>
#ifdef CONFIG_HCC_FAF
#include <hcc/faf.h>
#include "faf/faf_internal.h"
#include <hcc/faf_file_mgr.h>
#endif
#include <hcc/file.h>
#include <hcc/file_stat.h>
#include <hcc/ghost_helpers.h>
#include <hcc/regular_file_mgr.h>
#include <hcc/physical_fs.h>
#include <hcc/pid.h>
#include "mobility.h"

/*****************************************************************************/
/*                                                                           */
/*                             REGULAR FILES CREATION                        */
/*                                                                           */
/*****************************************************************************/

struct file *reopen_file_entry_from_hcc_desc (struct task_struct *task,
                                              struct regular_file_hcc_desc *desc)
{
	struct file *file = NULL;

	BUG_ON (!task);
	BUG_ON (!desc);

	file = open_physical_file (desc->file.filename, desc->file.flags,
				   desc->file.mode, desc->file.uid,
				   desc->file.gid);

	if (IS_ERR (file))
		return file;

	file->f_pos = desc->file.pos;

	return file;
}

struct file *create_file_entry_from_hcc_desc (struct task_struct *task,
                                              struct regular_file_hcc_desc *desc)
{
	struct file *file = NULL;

	BUG_ON (!task);
	BUG_ON (!desc);

	file = open_physical_file(desc->file.filename, desc->file.flags,
				  desc->file.mode,
				  task->cred->fsuid, task->cred->fsgid);

	if (IS_ERR (file))
		return file;

	file->f_pos = desc->file.pos;
	file->f_dentry->d_inode->i_mode |= desc->file.mode;

	return file;
}

/** Create a regular file struct from a HCC file descriptor.
 *  @author Innogrid HCC
 *
 *  @param task    Task to create the file for.
 *  @param desc    HCC file descriptor.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
static struct file *import_regular_file_from_hcc_desc(
	struct gpm_action *action,
	struct task_struct *task,
	struct regular_file_hcc_desc *desc)
{
	struct file *file;

	BUG_ON (!task);
	BUG_ON (!desc);

	if (desc->type == PIPE)
		file = reopen_pipe_file_entry_from_hcc_desc(task, desc);
#ifdef CONFIG_HCC_GIPC
	else if (desc->type == SHM)
		file = reopen_shm_file_entry_from_hcc_desc(task, desc);
#endif
	else {
		desc->file.filename = (char *) &desc[1];

		if (desc->file.ctnrid != GDM_SET_UNUSED)
			file = create_file_entry_from_hcc_desc(task, desc);
		else
			file = reopen_file_entry_from_hcc_desc(task, desc);

		if (IS_ERR(file))
			ckpt_err(action, PTR_ERR(file),
				 "App %ld - Fail to import file %s",
				 action->restart.app->app_id,
				 desc->file.filename);
	}

	return file;
}

int check_flush_file (struct gpm_action *action,
		      fl_owner_t id,
		      struct file *file)
{
	int err = 0;

	switch (action->type) {
	case GPM_REMOTE_CLONE:
	case GPM_MIGRATE:
	case GPM_CHECKPOINT:
		  if (file->f_dentry) {
			  if (file->f_op && file->f_op->flush)
				  err = file->f_op->flush(file, id);
		  }

		  break;

	  default:
		  break;
	}

	return err;
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
int get_regular_file_hcc_desc(struct file *file, void **desc,
			      int *desc_size)
{
	char *tmp, *file_name;
	struct regular_file_hcc_desc *data;
	int size = 0, name_len;
	int r = -ENOENT;

#ifdef CONFIG_HCC_GIPC
	if (is_shm(file)) {
		r = get_shm_file_hcc_desc(file, desc, desc_size);
		goto exit;
	}
#endif
	if (is_anonymous_pipe(file)) {
		r = get_pipe_file_hcc_desc(file, desc, desc_size);
		goto exit;
	}

	tmp = (char *)__get_free_page(GFP_KERNEL);
	if (!tmp) {
		r = -ENOMEM;
		goto exit;
	}

	file_name = get_phys_filename(file, tmp, false);
	if (!file_name)
		goto exit_free_page;

	name_len = strlen (file_name) + 1;
	size = sizeof (struct regular_file_hcc_desc) + name_len;

	data = kmalloc (size, GFP_KERNEL);
	if (!data) {
		r = -ENOMEM;
		goto exit_free_page;
	}

	data->type = FILE;
	data->file.filename = (char *) &data[1];

	strncpy(data->file.filename, file_name, name_len);

	data->file.flags = file->f_flags
#ifdef CONFIG_HCC_FAF
		& (~(O_FAF_SRV | O_FAF_CLT));
#endif
	data->file.mode = file->f_mode;
	data->file.pos = file->f_pos;
	data->file.uid = file->f_cred->uid;
	data->file.gid = file->f_cred->gid;

	if (
#ifdef CONFIG_HCC_FAF
	    !(file->f_flags & (O_FAF_CLT | O_FAF_SRV)) &&
#endif
	    file->f_dentry->d_inode->i_mapping->gdm_set
		)
		data->file.ctnrid =
			file->f_dentry->d_inode->i_mapping->gdm_set->id;
	else
		data->file.ctnrid = GDM_SET_UNUSED;

	*desc = data;
	*desc_size = size;
	r = 0;
exit_free_page:
	free_page ((unsigned long) tmp);
exit:
	return r;
}

/*****************************************************************************/

int ghost_read_file_hcc_desc(ghost_t *ghost, void **desc, int *desc_size)
{
	int r;
	r = ghost_read(ghost, desc_size, sizeof (int));
	if (r)
		goto error;

	*desc = kmalloc(*desc_size, GFP_KERNEL);
	if (!(*desc)) {
		r = -ENOMEM;
		goto error;
	}

	r = ghost_read(ghost, *desc, *desc_size);
	if (r) {
		kfree(*desc);
		*desc = NULL;
	}
error:
	return r;
}

int ghost_write_file_hcc_desc(ghost_t *ghost, void *desc, int desc_size)
{
	int r;

	r = ghost_write (ghost, &desc_size, sizeof (int));
	if (r)
		goto error;

	r = ghost_write (ghost, desc, desc_size);
error:
	return r;
}

static int ghost_write_regular_file_hcc_desc(ghost_t *ghost, struct file *file)
{
	int r;
	void *desc;
	int desc_size;

	r = get_regular_file_hcc_desc(file, &desc, &desc_size);
	if (r)
		goto error;

	r = ghost_write_file_hcc_desc(ghost, desc, desc_size);
	kfree (desc);
error:
	return r;
}

/*****************************************************************************/

struct file *begin_import_dvfs_file(unsigned long dvfs_objid,
				    struct dvfs_file_struct **dvfs_file)
{
	struct file *file = NULL;

	/* Check if the file struct is already present */
	*dvfs_file = grab_dvfs_file_struct(dvfs_objid);
	file = (*dvfs_file)->file;
	if (file)
		get_file(file);

	return file;
}

int end_import_dvfs_file(unsigned long dvfs_objid,
			 struct dvfs_file_struct *dvfs_file,
			 struct file *file, int first_import)
{
	int r = 0;

	if (IS_ERR(file)) {
		r = PTR_ERR (file);
		goto error;
	}

	if (first_import) {
		/* This is the first time the file is imported on this node
		* Setup the DVFS file field and inc the DVFS counter.
		*/
		file->f_objid = dvfs_objid;
		dvfs_file->file = file;

		dvfs_file->count++;
	}

error:
	put_dvfs_file_struct(dvfs_objid);
	return r;
}

/*****************************************************************************/

enum cr_file_desc_type {
	CR_FILE_NONE,
	CR_FILE_POINTER,
	CR_FILE_REGULAR_DESC,
	CR_FILE_FAF_DESC
};

struct cr_file_link {
	enum cr_file_desc_type desc_type;
	bool from_substitution;
	unsigned long dvfs_objid;
	void *desc;
};

static int __cr_link_to_file(struct gpm_action *action, ghost_t *ghost,
			     struct task_struct *task,
			     struct cr_file_link *file_link,
			     struct file **returned_file)
{
	int r = 0;

	if (!file_link) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	BUG_ON(file_link->desc_type == CR_FILE_NONE);

	if (file_link->desc_type != CR_FILE_POINTER
	    && file_link->desc_type != CR_FILE_REGULAR_DESC
	    && file_link->desc_type != CR_FILE_FAF_DESC) {
		BUG();
		r = -E_CR_BADDATA;
		goto exit;
	}

	if (file_link->desc_type == CR_FILE_POINTER) {
		*returned_file = file_link->desc;
		get_file(*returned_file);
	} else {
		struct file *file;
		struct dvfs_file_struct *dvfs_file;
		int first_import = 0;

		file_link->desc = &file_link[1];

		/* Check if the file struct is already present */
		file = begin_import_dvfs_file(file_link->dvfs_objid,
					      &dvfs_file);

		/* the file is not yet opened on this node */
		if (!file) {
#ifdef CONFIG_HCC_FAF
			if (file_link->desc_type == CR_FILE_FAF_DESC)
				file = create_faf_file_from_hcc_desc(
							task, file_link->desc);
			else
#endif
				file = import_regular_file_from_hcc_desc(
					action, task, file_link->desc);
			first_import = 1;
		}

		r = end_import_dvfs_file(file_link->dvfs_objid, dvfs_file, file,
					 first_import);

		if (r)
			goto exit;

		BUG_ON(file->f_objid != file_link->dvfs_objid);

		*returned_file = file;
	}
exit:
	return r;
}

int cr_link_to_file(struct gpm_action *action, ghost_t *ghost,
		    struct task_struct *task, struct file **returned_file)
{
	int r;
	long key;
	enum shared_obj_type type;
	struct cr_file_link *file_link;

	BUG_ON(action->type != GPM_CHECKPOINT);

	/* files are linked while loading files_struct or mm_struct */
	BUG_ON(action->restart.shared != CR_LOAD_NOW);

	r = ghost_read(ghost, &type, sizeof(enum shared_obj_type));
	if (r)
		goto error;

	if (type != LOCAL_FILE
	    && type != DVFS_FILE)
		goto err_bad_data;

	r = ghost_read(ghost, &key, sizeof(long));
	if (r)
		goto error;

	/* look in the table to find the new allocated data
	 * imported in import_shared_objects */

	file_link = get_imported_shared_object(action->restart.app,
					       type, key);

	if (file_link->desc_type == CR_FILE_NONE) {
		*returned_file = NULL;
		r = 0;
	} else
		r = __cr_link_to_file(action, ghost, task, file_link,
				      returned_file);

error:
	if (r)
		ckpt_err(NULL, r,
			 "Fail to relink process %d of application %ld"
			 " to file %d:%lu",
			 task_pid_knr(task), action->restart.app->app_id,
			 type, key);

	return r;

err_bad_data:
	r = -E_CR_BADDATA;
	goto error;
}

/*****************************************************************************/
/*                                                                           */
/*                          REGULAR FILES IMPORT/EXPORT                      */
/*                                                                           */
/*****************************************************************************/

/** Export a regular file descriptor into the given ghost.
 *  @author Innogrid HCC
 *
 *  @param ghost      the ghost to write data to.
 *  @param file       The file to export.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int regular_file_export (struct gpm_action *action,
			 ghost_t *ghost,
                         struct task_struct *task,
                         int index,
                         struct file *file)
{
	int r = 0;

	BUG_ON(action->type == GPM_CHECKPOINT
	       && action->checkpoint.shared == CR_SAVE_LATER);

	check_flush_file(action, task->files, file);

	r = ghost_write_regular_file_hcc_desc(ghost, file);

	return r;
}

int __regular_file_import_from_desc(struct gpm_action *action,
				    struct regular_file_hcc_desc *desc,
				    struct task_struct *task,
				    struct file **returned_file)
{
	int r = 0;
	struct file *file;

	file = import_regular_file_from_hcc_desc(action, task, desc);
	if (IS_ERR(file)) {
		r = PTR_ERR (file);
		goto exit;
	}

	check_flush_file(action, task->files, file);
	*returned_file = file;

exit:
	return r;
}

/** Import a regular file descriptor from the given ghost.
 *  @author Innogrid HCC
 *
 *  @param ghost          The ghost to read data from.
 *  @param task           The task data are imported for.
 *  @param returned_file  The file struct where data should be imported to.
 *
 *  @return   0 if everything ok.
 *            Negative value otherwise.
 */
int regular_file_import(struct gpm_action *action,
			ghost_t *ghost,
			struct task_struct *task,
			struct file **returned_file)
{
	struct regular_file_hcc_desc *desc;
	int desc_size, r = 0;

	BUG_ON(action->type == GPM_CHECKPOINT);

	r = ghost_read_file_hcc_desc(ghost, (void **)(&desc), &desc_size);
	if (r)
		goto exit;

	r = __regular_file_import_from_desc(action, desc, task, returned_file);

	kfree (desc);
exit:
	return r;
}



struct dvfs_mobility_operations dvfs_mobility_regular_ops = {
	.file_export = regular_file_export,
	.file_import = regular_file_import,
};

static int cr_export_now_file(struct gpm_action *action, ghost_t *ghost,
			      struct task_struct *task,
			      union export_args *args)
{
	int r, supported;

	supported = can_checkpoint_file(args->file_args.file);

	r = ghost_write(ghost, &supported, sizeof(supported));
	if (r)
		goto error;

	if (supported)
		r = regular_file_export(action, ghost, task,
					args->file_args.index,
					args->file_args.file);

error:
	if (r) {
		char *buffer, *filename;
		filename = alloc_filename(args->file_args.file, &buffer);
		if (!IS_ERR(filename)) {
			ckpt_err(action, r,
				 "Fail to save information needed to reopen "
				 "file %s as fd %d of process %d (%s)",
				 filename, args->file_args.index,
				 task_pid_knr(task), task->comm);
			free_filename(buffer);
		} else {
			ckpt_err(action, r,
				 "Fail to save information needed to reopen "
				 "fd %d of process %d (%s)",
				 args->file_args.index,
				 task_pid_knr(task), task->comm);
		}
	}

	return r;
}

int cr_export_user_info_file(struct gpm_action *action, ghost_t *ghost,
			     unsigned long key, struct export_obj_info *export)
{
	int r, index, keylen, nodelen;
	char *tmp, *file_name;
	struct file *file;
	struct task_struct *task;
	struct export_obj_info *_export;
	hcc_node_t file_node;

	/* do not export info about mapped file */
	if (export->args.file_args.index == -1)
		return 0;

	file = export->args.file_args.file;

	file_name = alloc_filename(file, &tmp);
	if (IS_ERR(file_name)) {
		r = PTR_ERR(file_name);
		goto exit;
	}

	if (is_socket(file))
		r = ghost_printf(ghost, "socket  ");

	else if (is_anonymous_pipe(file))
		r = ghost_printf(ghost, "pipe    ");

	else if (is_named_pipe(file))
		r = ghost_printf(ghost, "fifo    ");

	else if (is_tty(file))
		r = ghost_printf(ghost, "tty     ");

	else if (is_char_device(file))
		r = ghost_printf(ghost, "char    ");

	else if (is_block_device(file))
		r = ghost_printf(ghost, "block   ");

	else if (is_link(file))
		r = ghost_printf(ghost, "link    ");

	else if (is_directory(file))
		r = ghost_printf(ghost, "dir     ");

	else
		r = ghost_printf(ghost, "file    ");

	if (r)
		goto err_free_filename;

	if (file->f_objid)
		/* if the file is shared, there is no host node */
		file_node = HCC_NODE_ID_NONE;
	else
		file_node = hcc_node_id;

	nodelen = sizeof(file_node)*2;
	keylen = sizeof(key)*2;

	task = export->task;
	index = export->args.file_args.index;

	r = ghost_printf(ghost, "|%0*hX%0*lX|%s|%d:%d",
			 nodelen, file_node, keylen, key,
			 file_name, task_pid_knr(task), index);
	if (r)
		goto err_free_filename;

	list_for_each_entry(_export, &export->next, next) {
		task = _export->task;
		index = _export->args.file_args.index;

		r = ghost_printf(ghost, ",%d:%d",
				 task_pid_knr(task), index);
		if (r)
			goto err_free_filename;
	}

	r = ghost_printf(ghost, "\n");

err_free_filename:
	free_filename(tmp);
exit:
	return r;
}


static int prepare_restart_data_unsupported_file(void **returned_data,
						 size_t *data_size)
{
	struct cr_file_link *file_link;

	*data_size = sizeof(struct cr_file_link);
	file_link = kzalloc(*data_size, GFP_KERNEL);
	if (!file_link)
		return -ENOMEM;

	file_link->desc_type = CR_FILE_NONE;
	file_link->desc = NULL;
	file_link->from_substitution = false;

	*returned_data = file_link;

	return 0;
}

static int prepare_restart_data_local_file(struct file *f,
					   void **returned_data,
					   size_t *data_size)
{
	struct cr_file_link *file_link;

	*data_size = sizeof(struct cr_file_link);
	file_link = kzalloc(*data_size, GFP_KERNEL);
	if (!file_link)
		return -ENOMEM;

	file_link->desc_type = CR_FILE_POINTER;
	file_link->desc = f;
	file_link->from_substitution = false;

	*returned_data = file_link;

	return 0;
}

static int prepare_restart_data_dvfs_file(struct file *f,
					  void *desc,
					  int desc_size,
					  void **returned_data,
					  size_t *data_size)
{
	struct cr_file_link *file_link;

	*data_size = sizeof(struct cr_file_link) + desc_size;
	file_link = kzalloc(*data_size, GFP_KERNEL);
	if (!file_link)
		return -ENOMEM;

	file_link->desc = &file_link[1];
	file_link->desc_type = CR_FILE_REGULAR_DESC;
	file_link->dvfs_objid = f->f_objid;
	file_link->from_substitution = false;
	memcpy(file_link->desc, desc, desc_size);

	*returned_data = file_link;

	return 0;
}

#ifdef CONFIG_HCC_FAF
void fill_faf_file_hcc_desc(faf_client_data_t *data, struct file *file);

static int prepare_restart_data_faf_file(struct file *f,
					 void **returned_data,
					 size_t *data_size)
{
	struct cr_file_link *file_link;

	*data_size = sizeof(struct cr_file_link) + sizeof(faf_client_data_t);
	file_link = kmalloc(*data_size, GFP_KERNEL);
	if (!file_link)
		return -ENOMEM;

	file_link->desc = &file_link[1];
	file_link->desc_type = CR_FILE_FAF_DESC;
	file_link->dvfs_objid = f->f_objid;
	file_link->from_substitution = false;

	if (f->f_flags & O_FAF_SRV)
		fill_faf_file_hcc_desc(file_link->desc, f);
	else {
		BUG_ON(!(f->f_flags & O_FAF_CLT));
		*(faf_client_data_t*)file_link->desc =
			*(faf_client_data_t*)f->private_data;
	}

	*returned_data = file_link;

	return 0;
}
#endif

int prepare_restart_data_shared_file(struct file *f,
				     void *fdesc, int fdesc_size,
				     void **returned_data, size_t *data_size,
				     bool from_substitution)
{
	int r;
	struct cr_file_link *file_link;

#ifdef CONFIG_HCC_FAF
	if (f->f_flags & (O_FAF_CLT | O_FAF_SRV))
		r = prepare_restart_data_faf_file(f, returned_data,
						  data_size);
	else
#endif
		r = prepare_restart_data_dvfs_file(f, fdesc, fdesc_size,
						   returned_data,
						   data_size);

	if (r)
		goto error;

	file_link = (struct cr_file_link *)(*returned_data);
	file_link->from_substitution = from_substitution;
error:
	return r;
}


static int prepare_restart_data_supported_file(
	struct file *f, int local_only,
	void *fdesc, int fdesc_size,
	void **returned_data, size_t *data_size)
{
	int r;

	if (!local_only) {

		if (!f->f_objid) {
			/* get a new dvfs objid */
			r = create_gdm_file_object(f);
			if (r)
				goto error;
		}

#ifdef CONFIG_HCC_FAF
		r = setup_faf_file_if_needed(f);
		if (r)
			goto error;
#endif
		r = prepare_restart_data_shared_file(f, fdesc, fdesc_size,
						     returned_data, data_size,
						     false);
	} else
		r = prepare_restart_data_local_file(f, returned_data,
						    data_size);

error:
	return r;
}

/* if *returned_data is not NULL, the file checkpointed must be
 * replaced. Thus, we just read the ghost.
 */
static int cr_import_now_file(struct gpm_action *action,
			      ghost_t *ghost,
			      struct task_struct *fake,
			      int local_only,
			      void **returned_data,
			      size_t *data_size)
{
	int r, desc_size, supported;
	struct file *f;
	void *desc;

	r = ghost_read(ghost, &supported, sizeof(supported));
	if (r)
		goto error;

	if (!supported) {
		r = prepare_restart_data_unsupported_file(returned_data,
							  data_size);
		goto error;
	}

	/* We need to read the file description from the ghost
	 * even if we may not use it
	 */
	r = ghost_read_file_hcc_desc(ghost, &desc, &desc_size);
	if (r)
		goto error;

	/* File has been substituted at restart-time */
	if (*returned_data)
		goto error;

	r = __regular_file_import_from_desc(action, desc, fake, &f);
	if (r)
		goto err_free_desc;

	r = prepare_restart_data_supported_file(f, local_only, desc, desc_size,
						returned_data, data_size);

err_free_desc:
	kfree(desc);
error:
	if (r)
		ckpt_err(action, r,
			 "App %ld - Fail to restore a file",
			 action->restart.app->app_id);
	return r;
}

static int cr_import_complete_file(struct task_struct *fake, void *_file_link)
{
	struct cr_file_link *file_link = _file_link;
	struct file *file;

	if (file_link->desc_type == CR_FILE_NONE
	    || file_link->from_substitution)
		/* the file has not been imported */
		return 0;

	if (file_link->desc_type == CR_FILE_POINTER)
		file = file_link->desc;
	else {
		struct dvfs_file_struct *dvfs_file;

		BUG_ON(file_link->desc_type != CR_FILE_REGULAR_DESC
		       && file_link->desc_type != CR_FILE_FAF_DESC);

		dvfs_file = grab_dvfs_file_struct(file_link->dvfs_objid);
		file = dvfs_file->file;
	}

	BUG_ON(atomic_long_read(&file->f_count) <= 1);

	fput(file);

	if (file_link->desc_type != CR_FILE_POINTER)
		put_dvfs_file_struct(file_link->dvfs_objid);

	return 0;
}

static int cr_delete_file(struct task_struct *fake, void *_file_link)
{
	int r = 0;
	struct cr_file_link *file_link = _file_link;
	struct file *file;

	if (file_link->desc_type == CR_FILE_NONE
	    || file_link->from_substitution)
		/* the file has not been imported */
		return 0;

	if (file_link->desc_type == CR_FILE_POINTER)
		file = file_link->desc;
	else {
		struct dvfs_file_struct *dvfs_file;

		BUG_ON(file_link->desc_type != CR_FILE_REGULAR_DESC
		       && file_link->desc_type != CR_FILE_FAF_DESC);

		dvfs_file = grab_dvfs_file_struct(file_link->dvfs_objid);
		if (!dvfs_file) {
			r = -ENOENT;
			goto error;
		}

		file = dvfs_file->file;
	}

	if (file)
		fput(file);

error:
	if (file_link->desc_type != CR_FILE_POINTER)
		put_dvfs_file_struct(file_link->dvfs_objid);
	return 0;
}

struct shared_object_operations cr_shared_file_ops = {
	.export_now        = cr_export_now_file,
	.export_user_info  = cr_export_user_info_file,
	.import_now        = cr_import_now_file,
	.import_complete   = cr_import_complete_file,
	.delete            = cr_delete_file,
};