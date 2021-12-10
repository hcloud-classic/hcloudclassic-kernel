#
# Makefile for the HCC Remote Procedure Call layer
#

obj-y := hcc_init.o hcc_syms.o hcc_tools.o hcc_syscalls.o procfs.o node_discovering.o

obj-$(CONFIG_HCC_GHOTPLUG) += add.o cluster.o failure.o hooks.o ghotplug.o ghotplug_notifier.o membership.o namespace.o
obj-$(CONFIG_HCC_GHOTPLUG_DEL) += remove.o
obj-$(CONFIG_HCC_GHOTPLUG_XCH) += replace.o

EXTRA_CFLAGS += -I$(M) -Wall -Werror

# end of file
