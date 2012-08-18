## Configure template for mul
## Written for mul by Dipjyoti Saikia

AC_PREREQ(2.6)

AC_INIT(MuL, 1.1, [http://sourceforge.net/projects/mul/])
AC_CONFIG_SRCDIR(common/mul_of_msg.h)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(common/config.h)

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

AC_PROG_GCC_TRADITIONAL

dnl -----------------
dnl System extensions
dnl -----------------
AC_GNU_SOURCE

dnl -------
dnl libtool
dnl -------
AC_PROG_LIBTOOL

AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

AC_CHECK_HEADERS([stropts.h sys/ksym.h sys/times.h sys/select.h \
    sys/types.h linux/version.h netdb.h asm/types.h \
    sys/param.h limits.h signal.h \
    sys/socket.h netinet/in.h time.h sys/time.h])

AC_CHECK_HEADERS([stropts.h sys/ksym.h sys/times.h sys/select.h \
    sys/types.h linux/version.h netdb.h asm/types.h \
    sys/param.h limits.h signal.h \
    sys/socket.h netinet/in.h time.h sys/time.h])

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([inet_ntoa memset mkfifo strrchr strtoul strtoull])

dnl ---------------
dnl other functions
dnl ---------------
AC_CHECK_FUNCS([dup2 ftruncate getcwd gethostbyname getpagesize gettimeofday \
    inet_ntoa inet_aton strnlen \
    memchr memmove memset select socket \
    strcasecmp strchr strcspn strdup strerror \
    strncasecmp strndup strrchr strspn strstr \
    strtol strtoul strlcat strlcpy \
    daemon snprintf vsnprintf \
    if_nametoindex if_indextoname getifaddrs \
    uname fcntl])


AC_CHECK_PROG([GAWK],[gawk],[gawk],[not-in-PATH])
if test "x$GAWK" = "xnot-in-PATH" ; then
    AC_MSG_ERROR([GNU awk is required by mul]) 
fi

AC_ARG_VAR([GAWK],[GNU AWK])

if test "$GCC" = "yes" ; then
    CFLAGS="$CFLAGS -O2 -Wall -Wno-sign-compare -Wpointer-arith -Wdeclaration-after-statement -Wformat-security -Wswitch-enum -Wunused-parameter -Wstrict-aliasing -Wbad-function-cast -Wcast-align -Wstrict-prototypes -Wold-style-definition -Wmissing-prototypes -Wmissing-field-initializers -Wno-override-init"
    CFLAGS="$CFLAGS -fno-strict-aliasing"
else
  AC_MSG_ERROR([GCC/ICC is required by mul]) 
  exit 1;
fi

AC_ARG_WITH(l2sw,
[  --with-l2sw              Set l2sw as "m" for l2sw as a module])
AM_CONDITIONAL(HAVE_L2SW_MODULE, test "$with_l2sw" = m)

AC_SUBST([HAVE_L2SW_MODULE])

save_LIBS="$LIBS"
LIBS=""
AC_ARG_WITH(glib,
[  --with-glib              Set glib path])
if test "x$with_glib" != "x" ; then
  LIB_GLIB="$with_glib"/glib/.libs ;
  GLIB_INCLUDE="$with_glib"/glib  
  if ! test -f "$LIB_GLIB/libglib-2.0.so"; then
      AC_MSG_ERROR([glib not found])
  fi
  if ! test -f "$GLIB_INCLUDE/glib.h"; then
      AC_MSG_ERROR([glib header file not found])
  fi
  have_glib=no
else
  LIB_GLIB=
  GLIB_INCLUDE=
  AC_SEARCH_LIBS([g_get_monotonic_time], [glib-2.0],
                 [have_glib=yes], 
                 [AC_MSG_ERROR([glib is not installed])])
  AC_CHECK_HEADERS([glib.h], [],
                 [AC_MSG_ERROR([glib header file not found])])                  
fi
LIBS="$save_LIBS"

AM_CONDITIONAL(HAVE_EXT_GLIB, test "$have_glib" = yes)
AC_SUBST([LIB_GLIB])
AC_SUBST([GLIB_INCLUDE])

save_LIBS="$LIBS"
LIBS=""
AC_ARG_WITH(libevent,
[  --with-libevent         Set libevent path])
if test "x$with_libevent" != "x" ; then
  LIB_EVENT="$with_libevent"/.libs ;
  LIBEVENT_INCLUDE="$with_libevent"/include; 
  if ! test -f "$LIB_EVENT/libevent.so"; then
      AC_MSG_ERROR([libevent not found])
  fi
  if ! test -f "$LIBEVENT_INCLUDE/event2/event.h"; then
      AC_MSG_ERROR([libevent header file not found])
  fi
  have_libevent=no
else
  LIB_EVENT=
  LIBEVENT_INCLUDE=
  AC_SEARCH_LIBS([event_add], [event],
                 [have_libevent=yes], 
                 [AC_MSG_ERROR([libevent is not installed])])
  AC_CHECK_HEADERS([event2/event.h], [], 
                   [AC_MSG_ERROR([libevent header file not found])])                  
fi
LIBS="$save_LIBS"

AM_CONDITIONAL(HAVE_EXT_LIBEVENT, test "$have_libevent" = yes)
AC_SUBST([LIB_EVENT])
AC_SUBST([LIBEVENT_INCLUDE])

save_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS([pthread_create], [pthread],
                 [], 
                 [AC_MSG_ERROR([libpthread is not installed])])
AC_CHECK_HEADERS([pthread.h])     
LIBS="$save_LIBS"

AC_CHECK_LIB(c, inet_ntop, [AC_DEFINE(HAVE_INET_NTOP,,inet_ntop)])
AC_CHECK_LIB(c, inet_pton, [AC_DEFINE(HAVE_INET_PTON,,inet_pton)])
AC_CHECK_LIB(crypt, crypt)

AC_CONFIG_FILES([Makefile mul-core/Makefile application/l2switch/Makefile common-libs/3rd-party/derived-lib/Makefile common-libs/3rd-party/quagga-lib/Makefile common-libs/mul-lib/Makefile])
AC_OUTPUT
