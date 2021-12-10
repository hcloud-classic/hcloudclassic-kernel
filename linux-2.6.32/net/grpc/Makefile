#
# Makefile for the HCC Remote Procedure Call layer
#

obj-$(CONFIG_HCC_GRPC) := hcc_grpc.o

hcc_grpc-y := grpc.o comlayer.o thread_pool.o grpclayer.o monitor.o grpc_ghotplug.o synchro.o

EXTRA_CFLAGS += -I$(M) -Wall -Werror

# end of file
