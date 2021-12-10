/** GDM SHM id Linker.
 *  @file shmid_io_linker.h
 *
 *  Link GDM and Linux SHM id mechanisms.
 *  @author Innogrid HCC
 */

#ifndef __SHMID_IO_LINKER__
#define __SHMID_IO_LINKER__

#include <gdm/gdm_types.h>

extern struct kmem_cache *shmid_object_cachep;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/


typedef struct shmid_object {
	struct shmid_kernel mobile_shp;
	gdm_set_id_t set_id;
	struct shmid_kernel *local_shp;
} shmid_object_t;


extern struct iolinker_struct shmid_linker;
extern struct iolinker_struct shmkey_linker;


#endif
