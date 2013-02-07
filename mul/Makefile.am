ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir=$(libdir)/pkgconfig

lib_LTLIBRARIES = libmul.la
bin_PROGRAMS = mul 

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir) -I$(top_srcdir)/common/ \
           -I$(top_srcdir)/services/loadable/topo_routing/ \
           -I$(top_srcdir)/common-libs/3rd-party/derived-lib/include/ \
           -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
           -I$(top_srcdir)/common-libs/mul-lib/include/

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

libmul_la_SOURCES = \
            mul_servlet.c

mul_SOURCES = mul_app_interface.c mul_fp.c mul_main.c mul_thread_core.c \
              mul_events.c mul_ipc.c mul_of.c mul_vty.c ../common/mul_of_msg.c

if HAVE_L2SW_MODULE 
mul_SOURCES += $(top_srcdir)/application/l2switch/l2switch.c 
endif

LD_FLAGS= @LDFLAGS@ 

if !HAVE_EXT_GLIB
LD_FLAGS += -Wl,-rpath=$(LIB_GLIB) -L$(LIB_GLIB)
INCLUDES += -I$(GLIB_INCLUDE) -I$(GLIB_INCLUDE)/../
endif

if !HAVE_EXT_LIBEVENT
LD_FLAGS += -Wl,-rpath=$(LIB_EVENT) -L$(LIB_EVENT)
INCLUDES += -I$(LIBEVENT_INCLUDE)
endif

mul_LDADD = $(top_srcdir)/common-libs/3rd-party/derived-lib/.libs/libutil.a  \
            $(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libzebra.a \
            $(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.a 

mul_LDFLAGS = $(LD_FLAGS) -lpthread -lglib-2.0 -levent -lcrypt 

noinst_HEADERS = mul_events.h mul.h mul_of.h mul_priv.h mul_thread.h
