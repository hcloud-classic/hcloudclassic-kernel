/** HCC Kernel Hooks **/

#ifndef __FAF_H__
#define __FAF_H__

#include <linux/types.h>
#include <linux/namei.h>

struct file;
struct iovec;
struct kstat;
struct statfs;

/*--------------------------------------------------------------------------*
 *                                                                          *
 *                                  TYPES                                   *
 *                                                                          *
 *--------------------------------------------------------------------------*/

typedef struct faf_client_data {
	hcc_node_t server_id;
	unsigned int server_fd;
	unsigned long f_flags;
	fmode_t f_mode;
	loff_t f_pos;
	wait_queue_head_t poll_wq;
	unsigned int poll_revents;
	umode_t i_mode;
	unsigned int is_named_pipe:1;
} faf_client_data_t;

off_t hcc_faf_lseek(struct file *file, off_t offset,
		    unsigned int origin);
long hcc_faf_llseek(struct file *file, unsigned long offset_high,
		    unsigned long offset_low, loff_t *result,
		    unsigned int origin);
ssize_t hcc_faf_read(struct file *file, char *buf, size_t count, loff_t *pos);
ssize_t hcc_faf_write(struct file *file, const char *buf,
		      size_t count, loff_t *pos);
ssize_t hcc_faf_readv(struct file *file, const struct iovec __user *vec,
		      unsigned long vlen, loff_t *pos);
ssize_t hcc_faf_writev(struct file *file, const struct iovec __user *vec,
		       unsigned long vlen, loff_t *pos);

enum getdents_filler {
	OLDREADDIR,
	GETDENTS,
	GETDENTS64
};

int hcc_faf_getdents(struct file *file, enum getdents_filler filler,
		     void *dirent, unsigned int count);
long hcc_faf_fcntl(struct file *file, unsigned int cmd,
		   unsigned long arg);
long hcc_faf_fcntl64(struct file *file, unsigned int cmd,
		     unsigned long arg);
long hcc_faf_ioctl(struct file *file, unsigned int cmd,
		   unsigned long arg);
long hcc_faf_fstat(struct file *file, struct kstat *stat);
long hcc_faf_fstatfs(struct file *file, struct statfs *statfs);
long hcc_faf_fsync(struct file *file);
long hcc_faf_flock(struct file *file, unsigned int cmd);
char *hcc_faf_d_path(const struct file *file, char *buffer, int size, bool *deleted);
char *hcc_faf_phys_d_path(const struct file *file, char *buff, int size, bool *deleted);
int hcc_faf_do_path_lookup(struct file *file, const char *name,
			   unsigned int flags, struct nameidata *nd);
void hcc_faf_srv_close(struct file *file);

struct sockaddr;
struct msghdr;

long hcc_faf_bind(struct file *file, struct sockaddr __user *umyaddr,
		  int addrlen);
long hcc_faf_connect(struct file *file,
		     struct sockaddr __user *uservaddr, int addrlen);
long hcc_faf_listen(struct file *file, int backlog);
long hcc_faf_accept(struct file *file,
		    struct sockaddr __user *upeer_sockaddr,
		    int __user *upeer_addrlen);
long hcc_faf_getsockname(struct file *file,
			 struct sockaddr __user *usockaddr,
			 int __user *usockaddr_len);
long hcc_faf_getpeername(struct file *file,
			 struct sockaddr __user *usockaddr,
			 int __user *usockaddr_len);
long hcc_faf_shutdown(struct file *file, int how);
long hcc_faf_setsockopt(struct file *file, int level, int optname,
			char __user *optval, int optlen);
long hcc_faf_getsockopt(struct file *file, int level, int optname,
			char __user *optval, int __user *optlen);
ssize_t hcc_faf_sendmsg(struct file *file, struct msghdr *msg,
			size_t total_len);
ssize_t hcc_faf_recvmsg(struct file *file, struct msghdr *msg,
			size_t total_len, unsigned int flags);
int hcc_faf_poll_wait(struct file *file, int wait);
void hcc_faf_poll_dequeue(struct file *file);

/* Remote user access */
unsigned long hcc_copy_user_generic(void *to, const void *from,
				    unsigned long n, int zerorest);
long hcc___strncpy_from_user(char *dst, const char __user *src,
			     unsigned long count);
unsigned long hcc___strnlen_user(const char __user *str,
					  unsigned long n);
unsigned long hcc___clear_user(void __user *mem, unsigned long len);

/* functions used by other subsystems */
int setup_faf_file_if_needed(struct file *file);

int setup_faf_file(struct file *file);

void faf_error(struct file *file, const char *function);

#endif // __FAF_H__
