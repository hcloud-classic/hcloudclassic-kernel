obj-$(CONFIG_HCC_GMM) := hcc_gmm.o

hcc_gmm-y := memory_int_linker.o mm.o vma_struct.o page_table_tree.o \
		   memory_io_linker.o mm_struct.o mm_struct_io_linker.o \
		   mm_server.o injection.o

hcc_gmm-$(CONFIG_HCC_GPM) += mobility.o

EXTRA_CFLAGS += -Wall -Werror
