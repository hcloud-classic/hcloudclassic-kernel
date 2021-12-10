obj-$(CONFIG_HCC_DVFS) := hcc_fs.o
obj-$(CONFIG_HCC_FAF) += faf/

hcc_fs-y := file_struct_io_linker.o physical_fs.o file.o fs.o file_stat.o
hcc_fs-$(CONFIG_HCC_GPM) += regular_file_mgr.o mobility.o

hcc_fs-$(CONFIG_HCC_STREAM) +=
#hcc_fs-$(CONFIG_HCC_DEBUG) += debug_fs.o

EXTRA_CFLAGS += -Wall -Werror
