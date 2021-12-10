/** /proc manager
 *  @file procfs.c
 *
 *  Copyright (C) 2019-2021, Innogrid HCC.
 */

#include <linux/mmzone.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/hcc_hashtable.h>

#include <hcc/procfs.h>
#include <gdm/gdm.h>
#include "gdm_bench.h"

/*  /proc/hcc/gdm          */
static struct proc_dir_entry *procfs_gdm;

/*  /proc/hcc/gdm/meminfo  */
static struct proc_dir_entry *procfs_meminfo;

/*  /proc/hcc/gdm/gdmstat */
static struct proc_dir_entry *procfs_setstat;

/*  /proc/hcc/gdm/bench */
static struct proc_dir_entry *procfs_bench;



/****************************************************************************/
/*                                                                          */
/*                         /proc/gdminfo Management                        */
/*                                                                          */
/****************************************************************************/



static void *s_start(struct seq_file *m, loff_t *pos)
{
	struct gdm_set *set;
	unsigned long found;

	if (*pos == 0)
		seq_printf (m, "       Set ID           nr entries       nr objects     obj size      Set size     \n");

	/* Assumption: GDM set id 0 is never used. */

	down (&gdm_def_ns->table_sem);
	set = __hashtable_find_next (gdm_def_ns->gdm_set_table, *pos,
				     &found);
	up (&gdm_def_ns->table_sem);
	*pos = found;
	return set;
}

static void *s_next(struct seq_file *m, void *p, loff_t *pos)
{
	return s_start(m, pos);
}

static void s_stop(struct seq_file *m, void *p)
{
}

static int s_show(struct seq_file *m, void *p)
{
	struct gdm_set *set = p;

	seq_printf (m, "%20ld %16d %16d %10d %16d\n", set->id,
		    atomic_read(&set->nr_entries),
		    atomic_read(&set->nr_objects), set->obj_size,
		    atomic_read(&set->nr_objects) * set->obj_size);

        return 0;
}



const struct seq_operations gdminfo_op = {
        .start = s_start,
        .next = s_next,
        .stop = s_stop,
        .show = s_show,
};



static int gdminfo_open(struct inode *inode, struct file *file)
{
        return seq_open(file, &gdminfo_op);
}



static struct file_operations proc_gdminfo_operations = {
        .open           = gdminfo_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = seq_release,
};



/****************************************************************************/
/*                                                                          */
/*                     /proc/hcc/gdm  Management                     */
/*                                                                          */
/****************************************************************************/



/** Read function for /proc/hcc/gdm/meminfo entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
int read_meminfo (char *buffer,
                  char **start, off_t offset, int count, int *eof, void *data)
{
  static char mybuffer[80 * (5 + NB_OBJ_STATE)];
  static int len;
  int i;



  if (offset == 0)
    {
      len = sprintf (mybuffer,
                     "Free Pages:         %lu\n"
                     "Kddm objects:       %d\n"
                     "Master objetcs:     %d\n"
                     "Copy objects:       %d\n",
                     nr_free_pages (),
                     atomic_read(&nr_master_objects) +
		     atomic_read(&nr_copy_objects),
                     atomic_read(&nr_master_objects),
		     atomic_read(&nr_copy_objects));

      for (i = 0; i < NB_OBJ_STATE; i++)
        {
          len += sprintf (mybuffer + len,
                          "%s: \t %d\n", STATE_NAME (i),
			  atomic_read(&nr_OBJ_STATE[i]));
        }
      show_mem(0);
    }

  if (offset + count >= len)
    {
      count = len - offset;
      if (count < 0)
        count = 0;
      *eof = 1;
    }

  memcpy (buffer, &mybuffer[offset], count);

  return count;
}



/** Read function for /proc/hcc/gdm/setstat entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
int read_setstat (char *buffer,
                   char **start, off_t offset, int count, int *eof, void *data)
{
  static char mybuffer[80 * 5];
  static int len;

  if (offset == 0)
    {
      len = 0;

      len += sprintf (mybuffer + len, "Get Object:          %ld\n",
                      total_get_object_counter);

      len += sprintf (mybuffer + len, "Grab Object:         %ld\n",
                      total_grab_object_counter);

      len += sprintf (mybuffer + len, "Remove Object:       %ld\n",
                      total_remove_object_counter);

      len += sprintf (mybuffer + len, "Flush Object:        %ld\n",
                      total_flush_object_counter);
    }

  if (offset + count >= len)
    {
      count = len - offset;
      if (count < 0)
        count = 0;
      *eof = 1;
    }

  memcpy (buffer, &mybuffer[offset], count);

  return count;
}



/** Read function for /proc/hcc/gdm/bench entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
int read_bench (char *buffer,
		char **start, off_t offset, int count, int *eof, void *data)
{
	static char *mybuffer = NULL;
	static int len, size = 80*50;

	if (mybuffer == NULL)
		mybuffer = kmalloc (size, GFP_KERNEL);

	if (offset == 0)
		len = gdm_bench(mybuffer, size);

	if (offset + count >= len)
	{
		count = 1 + len - offset;
		if (count < 0)
			count = 0;
		*eof = 1;
	}

	snprintf (buffer, count, "%s", &mybuffer[offset]);

	*start = buffer;

	return count;
}



/** Create the /proc/hcc/gdm directory and sub-directories.
 *  @author Innogrid HCC
 */
void create_gdm_proc_dir (void)
{
  /* Create the /proc/hcc/gdm entry */

  BUG_ON (proc_hcc == NULL);

  procfs_gdm = create_proc_entry ("gdm", S_IFDIR | S_IRUGO | S_IWUGO |
                                   S_IXUGO, proc_hcc);

  if (procfs_gdm == NULL)
    {
      printk ("Cannot create /proc/hcc/gdm\n");
      return;
    }

  /* Create the /proc/hcc/gdm/meminfo entry */

  procfs_meminfo = create_proc_entry ("meminfo", S_IRUGO, procfs_gdm);

  if (procfs_meminfo == NULL)
    {
      printk ("Cannot create /proc/hcc/gdm/memfinfo\n");
      return;
    }

  procfs_meminfo->read_proc = read_meminfo;

  /* Create the /proc/hcc/gdm/setstat entry */

  procfs_setstat = create_proc_entry ("setstat", S_IRUGO, procfs_gdm);
  if (procfs_setstat == NULL)
    {
      printk ("Cannot create /proc/hcc/gdm/setstat\n");
      return;
    }

  procfs_setstat->read_proc = read_setstat;

  /* Create the /proc/hcc/gdm/bench entry */

  procfs_bench = create_proc_entry ("bench", S_IRUGO, procfs_gdm);
  if (procfs_bench == NULL) {
	  printk ("Cannot create /proc/hcc/gdm/bench\n");
	  return;
  }

  procfs_bench->read_proc = read_bench;

  /* Create the /proc/gdminfo entry */

  proc_create("gdminfo", S_IRUGO, NULL, &proc_gdminfo_operations);
}



/** Delete the /proc/hcc/gdm directory and sub-directories.
 *  @author Innogrid HCC
 */
void remove_gdm_proc_dir (void)
{
  procfs_deltree (procfs_gdm);
}



/****************************************************************************/
/*                                                                          */
/*               /proc/hcc/gdm/<set_id>  Management                */
/*                                                                          */
/****************************************************************************/




/** Read function for /proc/hcc/gdm/<set_id>/setstat entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
int read_set_id_setstat (char *buffer,
                          char **start,
                          off_t offset, int count, int *eof, void *data)
{
	struct gdm_set *set = NULL;
	static char mybuffer[80 * 5];
	static int len;

	if (offset == 0) {
		set = _find_get_gdm_set (gdm_def_ns, (gdm_set_id_t) data);
		BUG_ON (!set);

		len = 0;

		len += sprintf (mybuffer + len, "Get Object:          %ld\n",
				set->get_object_counter);

		len += sprintf (mybuffer + len, "Grab Object:         %ld\n",
				set->grab_object_counter);

		len += sprintf (mybuffer + len, "Remove Object:       %ld\n",
				set->remove_object_counter);

		len += sprintf (mybuffer + len, "Flush Object:        %ld\n",
				set->flush_object_counter);

		put_gdm_set(set);
	}

  if (offset + count >= len)
    {
      count = len - offset;
      if (count < 0)
        count = 0;
      *eof = 1;
    }

  memcpy (buffer, &mybuffer[offset], count);

  return count;
}



/** Read function for /proc/hcc/gdm/<set_id>/setinfo entry.
 *  @author Innogrid HCC
 *
 *  @param buffer           Buffer to write data to.
 *  @param buffer_location  Alternative buffer to return...
 *  @param offset           Offset of the first byte to write in the buffer.
 *  @param buffer_length    Length of given buffer
 *
 *  @return  Number of bytes written.
 */
int read_set_id_setinfo (char *buffer,
                          char **start,
                          off_t offset, int count, int *eof, void *data)
{
	struct gdm_set *set = NULL;
	static char mybuffer[80 * 20];

	static int len;

	if (offset == 0) {
		len = 0;

		set = _find_get_gdm_set (gdm_def_ns, (gdm_set_id_t) data);
		BUG_ON (!set);

		if (set->iolinker == NULL)
			len += sprintf (mybuffer + len,
					"Type:         No IO Linker\n");
		else
			len += sprintf (mybuffer + len, "Type:         %s\n",
					set->iolinker->linker_name);

		len += sprintf (mybuffer + len, "Manager            : %d\n",
				GDM_SET_MGR (set));

		len += sprintf (mybuffer + len, "Nr Objects         : %d\n",
				atomic_read(&set->nr_objects));

		len += sprintf (mybuffer + len, "Nr Entries         : %d\n",
				atomic_read(&set->nr_entries));

		len += sprintf (mybuffer + len, "Flags              : "
				"0x%08lx\n", set->flags);

		len += sprintf (mybuffer + len, "State              : %d\n",
				set->state);

		len += sprintf (mybuffer + len, "- Master entries   : %d\n",
				atomic_read(&set->nr_masters));

		len += sprintf (mybuffer + len, "- Copy entries     : %d\n",
				atomic_read(&set->nr_copies));

		len += sprintf (mybuffer + len, "Usage count  : %d\n",
				atomic_read(&set->count) - 1);

		switch (set->def_owner) {
		  case GDM_RR_DEF_OWNER:
			  len += sprintf (mybuffer + len,
					  "Default owner    : Round Robin\n");
			  break;

		  case GDM_CUSTOM_DEF_OWNER:
			  len += sprintf (mybuffer + len,
					  "Default owner    : Custom\n");
			  break;

		  default:
			  len += sprintf (mybuffer + len, "Default owner    : %d\n",
					  set->def_owner);
		}

		put_gdm_set(set);
	}

	if (offset + count >= len) {
		count = len - offset;
		if (count < 0)
			count = 0;
		*eof = 1;
	}

	memcpy (buffer, &mybuffer[offset], count);

	return count;
}



/** Read function for /proc/hcc/gdm/<set_id>/objectstates entry.
 *  @author Gael Utard
 */
int read_set_id_objectstates (char *buffer,
                              char **start,
                              off_t offset, int count, int *eof, void *data)
{
	int i, size = 0;
	struct gdm_set *set;

	if (offset >= size) {
		*eof = 1;
		return 0;
	}

	for (i = 0; offset + i < size && i < count; i++) {
		struct gdm_obj *obj_entry;

		obj_entry = _get_gdm_obj_entry(gdm_def_ns,
						(gdm_set_id_t) data,
						offset + i, &set);

		if (obj_entry != NULL) {
			switch (OBJ_STATE(obj_entry)) {
			case READ_COPY:
				buffer[i] = 'R';
				break;

			case WAIT_CHG_OWN_ACK:
			case WAIT_ACK_WRITE:
			case WAIT_ACK_INV:
			case READ_OWNER:
				buffer[i] = 'O';
				break;

			case WRITE_GHOST:
			case WRITE_OWNER:
				buffer[i] = 'W';
				break;

			case INV_COPY:
			case INV_OWNER:
			case INV_FILLING:
			case WAIT_OBJ_READ:
			case WAIT_OBJ_WRITE:
				buffer[i] = 'I';
				break;

			default:
				buffer[i] = '?';
			}
			put_gdm_obj_entry(set, obj_entry, offset + i);
		}
		else
			buffer[i] = 'I';
	}

	return i;
}



/* Create a /proc/hcc/gdm/<set_id> directory and sub-directories. */

struct proc_dir_entry *create_gdm_proc (gdm_set_id_t set_id)
{
	struct proc_dir_entry *entry, *objectstates, *stat, *info;
	char buffer[24];

	BUG_ON (procfs_gdm == NULL);

	/* Create the /proc/hcc/gdm/<set_id> entry */

	snprintf (buffer, 24, "%ld", set_id);
	entry = create_proc_entry (buffer, S_IFDIR|S_IRUGO|S_IWUGO|S_IXUGO,
				   procfs_gdm);

	if (entry == NULL)
		return NULL;

	/* Create the /proc/hcc/gdm/<set_id>/objectstates entry */

	objectstates = create_proc_entry ("objectstates", S_IRUGO, entry);

	if (objectstates == NULL)
		return NULL;

	objectstates->data = (void *) set_id;
	objectstates->read_proc = read_set_id_objectstates;

	/* Create the /proc/hcc/gdm/<set_id>/setstat entry */

	stat = create_proc_entry ("setstat", S_IRUGO, entry);
	if (stat == NULL) {
		printk ("Cannot create proc entry for %ld/setstat\n",
			set_id);
		return NULL;
	}

	stat->data = (void *) set_id;
	stat->read_proc = read_set_id_setstat;

	/* Create the /proc/hcc/gdm/<set_id>/setinfo entry */

	info = create_proc_entry ("setinfo", S_IRUGO, entry);
	if (info == NULL)
		return NULL;

	info->data = (void *) set_id;
	info->read_proc = read_set_id_setinfo;

	return entry;
}



/* Remove a /proc/hcc/gdm/<set_id> directory and sub-directories. */


void remove_gdm_proc (struct proc_dir_entry *proc_entry)
{
  if (proc_entry != NULL)
    procfs_deltree (proc_entry);
}



/***********************************************************************/
/*                                                                     */
/*         Define Kddm services in the /proc/hcc/services        */
/*                                                                     */
/***********************************************************************/



/** Init Kddm proc stuffs.
 *  @author Innogrid HCC
 */
int procfs_gdm_init (void)
{
	create_gdm_proc_dir ();

	return 0;
};



/** Finalize Kddm proc stuffs.
 *  @author Innogrid HCC
 */
int procfs_gdm_finalize (void)
{
	remove_gdm_proc_dir ();

	return 0;
};
