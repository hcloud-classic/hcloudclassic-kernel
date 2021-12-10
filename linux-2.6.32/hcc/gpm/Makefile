#
# HCC Process Management (GPM)
#

obj-$(CONFIG_HCC_GPM) := hcc_gpm.o
obj-$(CONFIG_HCC_GPM) += application/

hcc_gpm-y := gpm.o \
	signal.o sighand.o children.o pid.o pidmap.o \
	action.o ghost.o network_ghost.o \
	remote_clone.o migration.o checkpoint.o restart.o \
	ghotplug.o \
	procfs.o

EXTRA_CFLAGS += -Wall -Werror
