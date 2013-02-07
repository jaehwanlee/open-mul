ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir=$(libdir)/pkgconfig

lib_LTLIBRARIES = libmultr.la
bin_PROGRAMS = multr 

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir)/mul -I$(top_srcdir)/common/ \
           -I$(top_srcdir)/common-libs/3rd-party/derived-lib/include/ \
           -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
           -I$(top_srcdir)/common-libs/mul-lib/include/

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

libmultr_la_SOURCES = \
        mul_route_servlet.c mul_tr_servlet.c
    

multr_SOURCES = mul_lldp.c mul_lldp_vty.c mul_lldp_hash.c \
                mul_lldp_common.c mul_lldp_debug.c \
                mul_route_apsp.c mul_route_vty.c \
                mul_tr.c \
               $(top_srcdir)/common/mul_app_main.c \
               $(top_srcdir)/common/mul_of_msg.c \
               $(top_srcdir)/common/mul_service.c

LD_FLAGS= @LDFLAGS@ 

if !HAVE_EXT_GLIB
LD_FLAGS += -Wl,-rpath=$(LIB_GLIB) -L$(LIB_GLIB)
INCLUDES += -I$(GLIB_INCLUDE) -I$(GLIB_INCLUDE)/../
endif

if !HAVE_EXT_LIBEVENT
LD_FLAGS += -Wl,-rpath=$(LIB_EVENT) -L$(LIB_EVENT)
INCLUDES += -I$(LIBEVENT_INCLUDE)
endif

multr_LDADD = $(top_srcdir)/common-libs/3rd-party/derived-lib/.libs/libutil.a  \
                $(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libzebra.a \
                $(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.a 

multr_LDFLAGS = $(LD_FLAGS) -lpthread -lglib-2.0 -levent -lcrypt -lmultr

noinst_HEADERS = mul_lldp_pkt.h mul_lldp_vty.h mul_lldp_hash.h mul_lldp_common.h mul_lldp_debug.h mul_tr.h mul_tr_common.h
