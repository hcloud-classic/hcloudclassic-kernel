/** DVFS Level 3 - File struct sharing management.
 *  @file file.h
 *
 *  @author Innogrid HCC
 */

#ifndef __DVFS_FILE__
#define __DVFS_FILE__

#include <gdm/gdm.h>

struct gpm_action;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

struct dvfs_file_struct {
	loff_t f_pos;
	int count;
	struct file *file;
};

extern struct gdm_set *dvfs_file_struct_ctnr;

#ifdef CONFIG_HCC_GIPC
extern struct file_operations hcc_shm_file_operations;
extern const struct file_operations shm_file_operations_huge;
extern const struct file_operations shm_file_operations;
#endif

extern const struct file_operations shmem_file_operations;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                              EXTERN FUNCTIONS                            *
 *                                                                          *
 *--------------------------------------------------------------------------*/

int create_gdm_file_object(struct file *file);

#ifdef CONFIG_HCC_GPM
void check_file_struct_sharing (int index, struct file *file,
				struct gpm_action *action);
#endif

void get_dvfs_file(int index, unsigned long objid);
void put_dvfs_file(int index, struct file *file);

int dvfs_file_init(void);
void dvfs_file_finalize(void);

static inline struct dvfs_file_struct *grab_dvfs_file_struct(unsigned long file_id)
{
	struct dvfs_file_struct * dvfs_file;

	dvfs_file = _gdm_grab_object(dvfs_file_struct_ctnr, file_id);
	if (dvfs_file && dvfs_file->file) {
		if (atomic_long_read(&dvfs_file->file->f_count) == 0)
			dvfs_file->file = NULL;
	}
	return dvfs_file;
}

static inline struct dvfs_file_struct *get_dvfs_file_struct(unsigned long file_id)
{
	struct dvfs_file_struct * dvfs_file;

	dvfs_file = _gdm_get_object(dvfs_file_struct_ctnr, file_id);
	if (dvfs_file && dvfs_file->file) {
		if (atomic_long_read(&dvfs_file->file->f_count) == 0)
			dvfs_file->file = NULL;
	}
	return dvfs_file;
}

static inline void put_dvfs_file_struct(unsigned long file_id)
{
	_gdm_put_object (dvfs_file_struct_ctnr, file_id);
}

#endif // __KERFS_FILE__
