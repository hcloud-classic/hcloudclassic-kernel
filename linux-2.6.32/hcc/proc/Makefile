#
# HCC's low-level Process monitoring and control
#

obj-$(CONFIG_HCC_PROC) := hcc_proc.o

hcc_proc-y := proc.o libproc.o \
	task.o hcc_exit.o \
	remote_cred.o remote_syscall.o

EXTRA_CFLAGS += -Wall -Werror
