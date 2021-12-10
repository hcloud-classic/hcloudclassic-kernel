#include <linux/fs.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/compile.h>

static int hcc_version_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", HCC_VERSION);
	return 0;
}

static int hcc_version_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hcc_version_proc_show, NULL);
}

static const struct file_operations hcc_version_proc_fops = {
	.open		= hcc_version_proc_open,
	.read		= seq_read,
	.llseek	= seq_lseek,
	.release	= single_release,
};

static int __init proc_hcc_version_init(void)
{
	proc_create("hcc_version", 0, NULL, &hcc_version_proc_fops);
	return 0;
}
module_init(proc_hcc_version_init);
