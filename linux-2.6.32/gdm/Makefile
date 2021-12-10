#
# Makefile for the Kernel Distributed Data Management system
#

obj-$(CONFIG_HCC_GDM) := gdm.o object.o procfs.o \
	io_linker.o object_server.o protocol_action.o \
	gdm_tree.o \
	name_space.o gdm_set.o \
	gdm_find_object.o gdm_put_object.o gdm_get_object.o \
	gdm_grab_object.o gdm_set_object.o gdm_flush_object.o \
	gdm_remove_object.o gdm_sync_object.o gdm_bench.o gdm_ghotplug.o

obj-$(CONFIG_HCC_GPM) += mobility.o

EXTRA_CFLAGS += -Wall -Werror
