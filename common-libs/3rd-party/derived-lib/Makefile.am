INCLUDES =  -I./include -I$(top_srcdir)/common
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libutil.la

libutil_la_SOURCES = \
  ./src/random.c ./src/hash.c ./src/clog.c 

pkginclude_HEADERS = \
    ./include/nicira-ext.h ./include/openflow-netlink.h ./include/random.h    \
    ./include/clog.h ./include/openflow-ext.h ./include/packets.h \
    ./include/hash.h ./include/openflow.h ./include/private-ext.h \
    ./include/xtoxll.h
