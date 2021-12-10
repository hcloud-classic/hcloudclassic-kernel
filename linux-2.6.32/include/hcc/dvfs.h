#include <linux/fs.h>
#include <hcc/fcntl.h>

/** HCC Kernel Hooks **/
loff_t hcc_file_pos_read(struct file *file);
void hcc_file_pos_write(struct file *file, loff_t pos);
void hcc_put_file(struct file *file);

static inline loff_t file_pos_read(struct file *file)
{
	if (file->f_flags & O_HCC_SHARED)
		file->f_pos = hcc_file_pos_read(file);
	return file->f_pos;
}

static inline void file_pos_write(struct file *file, loff_t pos)
{
	if (file->f_flags & O_HCC_SHARED)
		hcc_file_pos_write(file, pos);
	file->f_pos = pos;
}
