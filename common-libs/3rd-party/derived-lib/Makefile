LTLIBRARIES = $(lib_LTLIBRARIES)
BIN_DIR = bin
libutil_la_OBJECTS = ./src/random.o ./src/hash.o \
                     ./src/clog.o
CC = gcc
AR = ar
DEFAULT_INCLUDES = -I./include/
am__mv = mv -f
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
LTCOMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) \
	$(LDFLAGS) -o $@

CFLAGS = -Os -g -Wall -Wno-sign-compare -Wpointer-arith -Wdeclaration-after-statement -Wformat-security -Wswitch-enum -Wunused-parameter -Wstrict-aliasing -Wbad-function-cast -Wcast-align -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-field-initializers -Wno-override-init

CPPFLAGS = 
CYGPATH_W = echo
DEFS = -DHAVE_CONFIG_H -DSYSCONFDIR=\"$(sysconfdir)/\"
DEPDIR = .deps
GAWK = gawk
INCLUDES =  -I.. -I./src -I./include
LDFLAGS = 
OBJEXT = o
SHELL = /bin/bash
exec_prefix = ${prefix}
mkdir_p = /bin/mkdir -p
prefix = /usr/local
srcdir = ./quagga-lib/src
sysconfdir = ${prefix}/etc
lib_LTLIBRARIES = $(BIN_DIR)/libutil.a
BUILT_SOURCES =
libutil_la_DEPENDENCIES = 
libutil_la_LIBADD = 

EXTRA_DIST =
all: $(BUILT_SOURCES) all-am

.SUFFIXES:
.SUFFIXES: .c .lo .o .obj

$(BIN_DIR)/libutil.a: $(libutil_la_OBJECTS) $(libutil_la_DEPENDENCIES) 
	$(AR) -r $@ $(libutil_la_OBJECTS) $(libutil_la_LIBADD) $(LIBS)

mostlyclean-compile:
	-rm -f ./src/*.$(OBJEXT)

.c.o:
	$(COMPILE) -MT $@ -MD -MP -MF $(DEPDIR)/$*.Tpo -c -o $@ $<
	$(am__mv) $(DEPDIR)/$*.Tpo $(DEPDIR)/$*.Po

all-am: $(LTLIBRARIES)

mostlyclean-generic:

clean-generic:
	rm -f ./$(DEPDIR)/src/*.Po
	rm -f ./src/*.o
	rm -f $(BIN_DIR)/*

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

.PHONY: CTAGS all all-am clean clean-generic \
	html html-am info info-am \
	mostlyclean \
	mostlyclean-compile mostlyclean-generic \
	pdf pdf-am ps ps-am

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
