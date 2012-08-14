

GLIB_SRC_PATH=$(TOP)/common-libs/3rd-party/glib-2.32.0/
GLIB_PATH=$(TOP)/common-libs/3rd-party/glib-2.32.0/glib/.libs/
LIBEVENT_SRC_PATH=$(TOP)/common-libs/3rd-party/libevent-2.0.18-stable/
LIBEVENT_PATH=$(TOP)/common-libs/3rd-party/libevent-2.0.18-stable/.libs/

ifeq ($(findstring mul_of_msg.c,$(wildcard *.c)), )
$(shell ln -s $(TOP)/common/mul_of_msg.c mul_of_msg.c)
endif

ifeq ($(findstring mul_app_main.c,$(wildcard *.c)), )
$(shell ln -s $(TOP)/common/mul_app_main.c mul_app_main.c)
endif

OBJECTS += mul_app_main.o \
         mul_of_msg.o

CC=gcc
AR=ar

DEFAULT_INCLUDES = -I./ 
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@

CFLAGS = -O2 -g -Wall -Wno-sign-compare -Wpointer-arith -Wdeclaration-after-statement -Wformat-security -Wswitch-enum -Wunused-parameter -Wstrict-aliasing -Wbad-function-cast -Wcast-align -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-field-initializers -Wno-override-init -Wl,-rpath=$(LIBEVENT_PATH) -Wl,-rpath=$(GLIB_PATH)

CPPFLAGS = 
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H -DSYSCONFDIR=\"$(sysconfdir)/\"
DEPDIR = .
GAWK = gawk
INCLUDES   = -I$(TOP)/common-libs/3rd-party/derived-lib/include/ \
			 -I$(TOP)/common-libs/3rd-party/quagga-lib/include/ \
             -I$(TOP)/common-libs/mul-lib/include/ \
			 -I$(TOP)/common/ \
			 -I$(LIBEVENT_SRC_PATH)/include/ \
			 -I$(GLIB_SRC_PATH)/glib/ \
			 -I$(GLIB_SRC_PATH) \
             -L$(GLIB_PATH) \
             -L$(LIBEVENT_PATH)
LDFLAGS = 
OBJEXT = o
SHELL = /bin/bash
exec_prefix = ${prefix}
mkdir_p = /bin/mkdir -p
prefix = /usr/local
#srcdir = ./lib
sysconfdir = ${prefix}/etc
lib_LTLIBRARIES  = $(TOP)/common-libs/3rd-party/derived-lib/bin/libutil.a  \
                   $(TOP)/common-libs/3rd-party/quagga-lib/bin/libzebra.a \
                   $(TOP)/common-libs/mul-lib/bin/libmulutil.a
libof_la_DEPENDENCIES = 
libof_la_LIBADD = 
LIBS = -lcrypt -lglib-2.0 -lpthread -levent

all: all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj

mostlyclean-compile:
	-rm -f ./*.$(OBJEXT)
	@-rm -f ./*.Po

common-libs:
	@pushd $(TOP)/common-libs/3rd-party/derived-lib; make; popd
	@pushd $(TOP)/common-libs/3rd-party/quagga-lib; make; popd
	@pushd $(TOP)/common-libs/mul-lib; make; popd

clean-common-libs:
	@pushd $(TOP)/common-libs/3rd-party/derived-lib; make clean; popd
	@pushd $(TOP)/common-libs/3rd-party/quagga-lib; make clean; popd
	@pushd $(TOP)/common-libs/mul-lib; make clean; popd

ifneq ($(MAKECMDGOALS),clean) 
-include $(OBJECTS:%.o=$(DEPDIR)/%.Po) 
endif 

.c.o:
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	@$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po

$(PROGRAM): $(OBJECTS)
	$(COMPILE) -o $@ $(OBJECTS) $(LIBADD) $(lib_LTLIBRARIES) $(LIBS)

all-am: $(PROGRAM)

mostlyclean-generic:

clean-generic:
	-rm -f ./$(PROGRAM)

clean: clean-am

clean-am: clean-generic \
	mostlyclean-am

html: html-am

html-am:

info: info-am

info-am:

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic 

.MAKE: all

.PHONY: CTAGS all all-am clean clean-generic clean-common-libs \
	html html-am info info-am \
	mostlyclean \
	mostlyclean-compile mostlyclean-generic common-libs \
	pdf pdf-am ps ps-am

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
