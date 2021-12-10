#ifndef _LINUX_NAMEI_H
#define _LINUX_NAMEI_H

#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/linkage.h>
#include <linux/path.h>

struct vfsmount;

struct open_intent {
	int	flags;
	int	create_mode;
	struct file *file;
};

enum { MAX_NESTED_LINKS = 8 };

struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	unsigned int	flags;
	int		last_type;
	unsigned	depth;
	char *saved_names[MAX_NESTED_LINKS + 1];

	/* Intent data */
	union {
		struct open_intent open;
	} intent;
};

/*
 * Type of the last component on LOOKUP_PARENT
 */
enum {LAST_NORM, LAST_ROOT, LAST_DOT, LAST_DOTDOT, LAST_BIND};

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path components" flag
 *  - locked when lookup done with dcache_lock held
 *  - dentry cache is untrusted; force a real lookup
 *  - suppress terminal automount
 */
#define LOOKUP_FOLLOW		 1
#define LOOKUP_DIRECTORY	 2
#define LOOKUP_CONTINUE		 4
#define LOOKUP_AUTOMOUNT	 8
#define LOOKUP_PARENT		16
#define LOOKUP_REVAL		64
/*
 * Intent data
 */
#define LOOKUP_OPEN		0x0100
#define LOOKUP_CREATE		0x0200
#define LOOKUP_EXCL		0x0400
#define LOOKUP_RENAME_TARGET	0x0800
#define LOOKUP_OPATH		0x80000000

#define LOOKUP_EMPTY		0x4000

extern int user_path_at(int, const char __user *, unsigned, struct path *);
extern int user_path_at_empty(int, const char __user *, unsigned, struct path *, int *empty);

#define user_path(name, path) user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, path)
#define user_lpath(name, path) user_path_at(AT_FDCWD, name, 0, path)
#define user_path_dir(name, path) \
	user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, path)

extern int kern_path(const char *, unsigned, struct path *);

extern int path_lookup(const char *, unsigned, struct nameidata *);
extern int vfs_path_lookup(struct dentry *, struct vfsmount *,
			   const char *, unsigned int, struct nameidata *);

extern struct file *lookup_instantiate_filp(struct nameidata *nd, struct dentry *dentry,
		int (*open)(struct inode *, struct file *));

extern int kern_path_mountpoint(int, const char *, struct path *, unsigned int);

extern struct dentry *lookup_one_len(const char *, struct dentry *, int);
extern struct dentry *lookup_one_noperm(const char *, struct dentry *);

extern int follow_down(struct path *);
extern int __follow_down(struct path *, bool);
extern int follow_up(struct path *);

extern struct dentry *lock_rename(struct dentry *, struct dentry *);
extern void unlock_rename(struct dentry *, struct dentry *);

static inline void nd_set_link(struct nameidata *nd, char *path)
{
	nd->saved_names[nd->depth] = path;
}

static inline char *nd_get_link(struct nameidata *nd)
{
	return nd->saved_names[nd->depth];
}

static inline void nd_terminate_link(void *name, size_t len, size_t maxlen)
{
	((char *) name)[min(len, maxlen)] = '\0';
}

/**
 * retry_estale - determine whether the caller should retry an operation
 * @error: the error that would currently be returned
 * @flags: flags being used for next lookup attempt
 *
 * Check to see if the error code was -ESTALE, and then determine whether
 * to retry the call based on whether "flags" already has LOOKUP_REVAL set.
 *
 * Returns true if the caller should try the operation again.
 */
static inline bool
retry_estale(const long error, const unsigned int flags)
{
	return error == -ESTALE && !(flags & LOOKUP_REVAL);
}

#endif /* _LINUX_NAMEI_H */
