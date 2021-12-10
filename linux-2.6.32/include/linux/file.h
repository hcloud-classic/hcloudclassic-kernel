/*
 * Wrapper functions for accessing the file_struct fd array.
 */

#ifndef __LINUX_FILE_H
#define __LINUX_FILE_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/posix_types.h>

struct file;
#ifdef CONFIG_HCC_FAF
struct files_struct;
struct task_struct;
#endif
extern void __fput(struct file *);
extern void fput(struct file *);
extern void fput_pos_unlock(struct file *file);
extern void drop_file_write_access(struct file *file);

struct file_operations;
struct vfsmount;
struct dentry;
struct path;
extern struct file *alloc_file(struct path *, fmode_t mode,
	const struct file_operations *fop);

#define FDPUT_FPUT       1
#define FDPUT_POS_UNLOCK 2

static inline void fput_light(struct file *file, int fput_needed)
{
	if (unlikely(fput_needed & FDPUT_FPUT))
		fput(file);
}

static inline void fput_light_pos(struct file *file, int fput_needed)
{
	if (fput_needed & FDPUT_POS_UNLOCK)
		fput_pos_unlock(file);
	fput_light(file, fput_needed);
}

extern struct file *fget(unsigned int fd);
extern struct file *fget_light(unsigned int fd, int *fput_needed);
extern struct file *fget_light_pos(unsigned int fd, int *fput_needed);
extern void set_close_on_exec(unsigned int fd, int flag);
extern void put_filp(struct file *);
extern int alloc_fd(unsigned start, unsigned flags);
extern int get_unused_fd(void);
#ifdef CONFIG_HCC_FAF
int __get_unused_fd(struct task_struct *task);
#endif
extern int get_unused_fd_flags(unsigned flags);
#ifdef CONFIG_HCC_FAF
extern void __put_unused_fd(struct files_struct *files, unsigned int fd);
#endif
extern void put_unused_fd(unsigned int fd);
#ifdef CONFIG_HCC_FAF
extern void __fd_install(struct files_struct *files,
			 unsigned int fd, struct file *file);
#endif
extern void fd_install(unsigned int fd, struct file *file);
#ifdef CONFIG_HCC_FAF
extern void __put_unused_fd(struct files_struct *files, unsigned int fd);
#endif
#ifdef CONFIG_HCC_FAF
extern void __fd_install(struct files_struct *files,
			 unsigned int fd, struct file *file);
#endif
#ifdef CONFIG_HCC_DVFS
struct fdtable;
int count_open_files(struct fdtable *fdt);
struct fdtable * alloc_fdtable(unsigned int nr);
#endif

#endif /* __LINUX_FILE_H */
