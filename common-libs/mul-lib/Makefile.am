INCLUDES =  -I./include -I$(top_srcdir)/common
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

lib_LTLIBRARIES = libmulutil.la

libmulutil_la_SOURCES = \
    ./src/cbuf.c ./src/c_util.c  ./src/idx_pool.c

pkginclude_HEADERS = \
    ./include/atomic.h  ./include/cbuf.h  ./include/compiler.h  ./include/c_util.h  ./include/idx_pool.h  ./include/lock.h
