#
# Makefile for HCC's global ProcFs
#

obj-$(CONFIG_HCC_PROCFS) := hcc_procfs.o

hcc_procfs-y := procfs.o proc.o \
        static_node_info_linker.o static_cpu_info_linker.o \
        dynamic_node_info_linker.o dynamic_cpu_info_linker.o \
	procfs_ghotplug.o

hcc_procfs-$(CONFIG_HCC_PROC) += proc_pid.o \
	proc_pid_file.o proc_pid_link.o \
	proc_pid_fd.o

EXTRA_CFLAGS += -Wall -Werror
