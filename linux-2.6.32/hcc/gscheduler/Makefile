#
# HCC's configurable gscheduler framework (SCHED)
#

obj-$(CONFIG_HCC_GSCHED) := core.o info.o \
	global_lock.o string_list.o hashed_string_list.o global_config.o \
	policy.o gscheduler.o \
	pipe.o remote_pipe.o \
	probe.o port.o filter.o \
	process_set.o placement.o

obj-$(CONFIG_HCC_GSCHED) += probes/
obj-$(CONFIG_HCC_GSCHED) += filters/
obj-$(CONFIG_HCC_GSCHED) += policies/

EXTRA_CFLAGS += -Wall -Werror
