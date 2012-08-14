

TOP := $(shell pwd)/../../

include $(TOP)/.config

ifeq ($(HAVE_L2SWITCH), y)

OBJECTS = l2switch.o
PROGRAM = mul-l2sw.bin

include $(TOP)/common/Makefile.app
else
all:
$(error l2sw is configured as module. Cant make...)
endif
