
TOP := $(shell pwd)


CTRL_LIB_ARGS := GLIB_SRC_PATH=$(TOP)/common-libs/3rd-party/glib-2.32.0 GLIB_PATH=$(TOP)/common-libs/3rd-party/glib-2.32.0/glib/.libs LIBEVENT_SRC_PATH=$(TOP)/common-libs/3rd-party/libevent-2.0.18-stable/ LIBEVENT_PATH=$(TOP)/common-libs/3rd-party/libevent-2.0.18-stable/.libs

all:
	@make -f Makefile.mul common-libs
	@make -f Makefile.mul $(CTRL_LIB_ARGS) 

clean:
	@make -f Makefile.mul clean
	@make -f Makefile.mul clean-common-libs

mul:
	@make -f Makefile.mul $(CTRL_LIB_ARGS) 

mul-clean:
	@make -f Makefile.mul clean
