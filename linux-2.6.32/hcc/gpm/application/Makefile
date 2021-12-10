#
# HCC Process Management (GPM) - Application
#

obj-$(CONFIG_HCC_GPM) := hcc_gpm_application.o

hcc_gpm_application-y := app_shared.o \
	app_frontier.o application.o \
	app_checkpoint.o app_restart.o \
	application_cr_api.o

EXTRA_CFLAGS += -Wall -Werror
