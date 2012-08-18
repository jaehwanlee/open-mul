ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

pkgconfigdir=$(libdir)/pkgconfig

bin_PROGRAMS = mull2sw 

LIB_GLIB = @LIB_GLIB@
LIB_EVENT = @LIB_EVENT@
GLIB_INCLUDE = @GLIB_INCLUDE@
LIBEVENT_INCLUDE = @LIBEVENT_INCLUDE@

INCLUDES = -I. -I$(top_srcdir) -I$(top_srcdir)/common/ \
           -I$(top_srcdir)/common-libs/3rd-party/derived-lib/include/ \
           -I$(top_srcdir)/common-libs/3rd-party/quagga-lib/include/ \
           -I$(top_srcdir)/common-libs/mul-lib/include/ \
           -I$(GLIB_INCLUDE) -I$(GLIB_INCLUDE)/../ -I$(LIBEVENT_INCLUDE)

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

if !HAVE_L2SW_MODULE 
mull2sw_SOURCES = l2switch.c $(top_srcdir)/common/mul_app_main.c \
               $(top_srcdir)/common/mul_of_msg.c
endif

LD_FLAGS= @LDFLAGS@ 

if !HAVE_EXT_GLIB
LD_FLAGS += -Wl,-rpath=$(LIB_GLIB)
endif

if !HAVE_EXT_LIBEVENT
LD_FLAGS += -Wl,-rpath=$(LIB_EVENT)
endif

mull2sw_LDADD = $(top_srcdir)/common-libs/3rd-party/derived-lib/.libs/libutil.a  \
                $(top_srcdir)/common-libs/3rd-party/quagga-lib/.libs/libzebra.a \
                $(top_srcdir)/common-libs/mul-lib/.libs/libmulutil.a 

mull2sw_LDFLAGS = -L$(LIB_GLIB) -L$(LIB_EVENT) $(LD_FLAGS) \
              -lpthread -lglib-2.0 -levent -lcrypt

noinst_HEADERS = l2switch.h
