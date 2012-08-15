/*
 * Logging of zebra
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "clog.h"

static inline void ignore_result_helper(int __attribute__((unused)) dummy, ...) 
{ 
} 
 
#define IGNORE_RESULT(X) ignore_result_helper(0, (X)) 


static int logfile_fd = -1;	/* Used in signal handler. */

struct clog *clog_default = NULL;

const char *clog_proto_names[] = 
{
  "NONE",
  "DEFAULT",
  "MUL-CONTROLLER", 
  NULL
};

const char *clog_priority[] =
{
  "emergencies",
  "alerts",
  "critical",
  "errors",
  "warnings",
  "notifications",
  "informational",
  "debugging",
  NULL,
};
  

const char *c_safe_strerror(int errnum);
void       *Xcalloc(size_t sz);
void        Xfree(void *ptr);
size_t      log_timestamp(int timestamp_precision, 
                          char *buf, size_t buflen);
void        _clog_assert_failed (const char *assertion,
                            const char *file,
                            unsigned int line, const char *function);
const char  *c_lookup(const struct message *mes, int key);
const char  *mes_c_lookup (const struct message *meslist, int max, int index,
                           const char *none, const char *mesname);

void *
Xcalloc(size_t sz)
{
    void *b;
    b = calloc(1, sz);
    assert(b);
    
    return b;
}

void
Xfree(void *ptr)
{
    free(ptr);
}

#define XCALLOC(type, sz)  Xcalloc(sz)
#define XFREE(type, ptr) Xfree(ptr)

/* For time string format. */

size_t
log_timestamp(int timestamp_precision, char *buf, size_t buflen)
{
  static struct {
    time_t last;
    size_t len;
    char buf[28];
  } cache;
  struct timeval clock;

  /* would it be sufficient to use global 'recent_time' here?  I fear not... */
  gettimeofday(&clock, NULL);

  /* first, we update the cache if the time has changed */
  if (cache.last != clock.tv_sec)
    {
      struct tm *tm;
      cache.last = clock.tv_sec;
      tm = localtime(&cache.last);
      cache.len = strftime(cache.buf, sizeof(cache.buf),
      			   "%Y/%m/%d %H:%M:%S", tm);
    }
  /* note: it's not worth caching the subsecond part, because
     chances are that back-to-back calls are not sufficiently close together
     for the clock not to have ticked forward */

  if (buflen > cache.len)
    {
      memcpy(buf, cache.buf, cache.len);
      if ((timestamp_precision > 0) &&
	  (buflen > cache.len+1+timestamp_precision))
	{
	  /* should we worry about locale issues? */
	  static const int divisor[] = {0, 100000, 10000, 1000, 100, 10, 1};
	  int prec;
	  char *p = buf+cache.len+1+(prec = timestamp_precision);
	  *p-- = '\0';
	  while (prec > 6)
	    /* this is unlikely to happen, but protect anyway */
	    {
	      *p-- = '0';
	      prec--;
	    }
	  clock.tv_usec /= divisor[prec];
	  do
	    {
	      *p-- = '0'+(clock.tv_usec % 10);
	      clock.tv_usec /= 10;
	    }
	  while (--prec > 0);
	  *p = '.';
	  return cache.len+1+timestamp_precision;
	}
      buf[cache.len] = '\0';
      return cache.len;
    }
  if (buflen > 0)
    buf[0] = '\0';
  return 0;
}

/* Utility routine for current time printing. */
static void
time_print(FILE *fp, struct timestamp_control *ctl)
{
  if (!ctl->already_rendered)
    {
      ctl->len = log_timestamp(ctl->precision, ctl->buf, sizeof(ctl->buf));
      ctl->already_rendered = 1;
    }
  fprintf(fp, "%s ", ctl->buf);
}
  

/* va_list version of clog. */
static void
vclog (struct clog *zl, int priority, const char *format, va_list args)
{
  struct timestamp_control tsctl;
  tsctl.already_rendered = 0;

  /* If clog is not specified, use default one. */
  if (zl == NULL)
    zl = clog_default;

  /* When clog_default is also NULL, use stderr for logging. */
  if (zl == NULL)
    {
      tsctl.precision = 0;
      time_print(stderr, &tsctl);
      fprintf (stderr, "%s: ", "unknown");
      vfprintf (stderr, format, args);
      fprintf (stderr, "\n");
      fflush (stderr);

      /* In this case we return at here. */
      return;
    }
  tsctl.precision = zl->timestamp_precision;

  /* Syslog output */
  if (priority <= zl->maxlvl[CLOG_DEST_SYSLOG])
    {
      va_list ac;
      va_copy(ac, args);
      vsyslog (priority|clog_default->facility, format, ac);
      va_end(ac);
    }

  /* File output. */
  if ((priority <= zl->maxlvl[CLOG_DEST_FILE]) && zl->fp)
    {
      va_list ac;
      time_print (zl->fp, &tsctl);
      if (zl->record_priority)
	fprintf (zl->fp, "%s: ", clog_priority[priority]);
      fprintf (zl->fp, "%s: ", clog_proto_names[zl->protocol]);
      va_copy(ac, args);
      vfprintf (zl->fp, format, ac);
      va_end(ac);
      fprintf (zl->fp, "\n");
      fflush (zl->fp);
    }

  /* stdout output. */
  if (priority <= zl->maxlvl[CLOG_DEST_STDOUT])
    {
      va_list ac;
      time_print (stdout, &tsctl);
      if (zl->record_priority)
	fprintf (stdout, "%s: ", clog_priority[priority]);
      fprintf (stdout, "%s: ", clog_proto_names[zl->protocol]);
      va_copy(ac, args);
      vfprintf (stdout, format, ac);
      va_end(ac);
      fprintf (stdout, "\n");
      fflush (stdout);
    }

  /* Terminal monitor. */
//  if (priority <= zl->maxlvl[CLOG_DEST_MONITOR])
//    vty_log ((zl->record_priority ? clog_priority[priority] : NULL),
//	     clog_proto_names[zl->protocol], format, &tsctl, args);
}

static char *
str_append(char *dst, int len, const char *src)
{
  while ((len-- > 0) && *src)
    *dst++ = *src++;
  return dst;
}

static char *
num_append(char *s, int len, u_long x)
{
  char buf[30];
  char *t;

  if (!x)
    return str_append(s,len,"0");
  *(t = &buf[sizeof(buf)-1]) = '\0';
  while (x && (t > buf))
    {
      *--t = '0'+(x % 10);
      x /= 10;
    }
  return str_append(s,len,t);
}

#if defined(SA_SIGINFO) || defined(HAVE_STACK_TRACE)
static char *
hex_append(char *s, int len, u_long x)
{
  char buf[30];
  char *t;

  if (!x)
    return str_append(s,len,"0");
  *(t = &buf[sizeof(buf)-1]) = '\0';
  while (x && (t > buf))
    {
      u_int cc = (x % 16);
      *--t = ((cc < 10) ? ('0'+cc) : ('a'+cc-10));
      x /= 16;
    }
  return str_append(s,len,t);
}
#endif

/* Needs to be enhanced to support Solaris. */
static int
syslog_connect(void)
{
#ifdef SUNOS_5
  return -1;
#else
  int fd;
  char *s;
  struct sockaddr_un addr;

  if ((fd = socket(AF_UNIX,SOCK_DGRAM,0)) < 0)
    return -1;
  addr.sun_family = AF_UNIX;
#ifdef _PATH_LOG
#define SYSLOG_SOCKET_PATH _PATH_LOG
#else
#define SYSLOG_SOCKET_PATH "/dev/log"
#endif
  s = str_append(addr.sun_path,sizeof(addr.sun_path),SYSLOG_SOCKET_PATH);
#undef SYSLOG_SOCKET_PATH
  *s = '\0';
  if (connect(fd,(struct sockaddr *)&addr,sizeof(addr)) < 0)
    {
      close(fd);
      return -1;
    }
  return fd;
#endif
}

static void
syslog_sigsafe(int priority, const char *msg, size_t msglen)
{
  static int syslog_fd = -1;
  char buf[sizeof("<1234567890>ripngd[1234567890]: ")+msglen+50];
  char *s;

  if ((syslog_fd < 0) && ((syslog_fd = syslog_connect()) < 0))
    return;

#define LOC s,buf+sizeof(buf)-s
  s = buf;
  s = str_append(LOC,"<");
  s = num_append(LOC,priority);
  s = str_append(LOC,">");
  /* forget about the timestamp, too difficult in a signal handler */
  s = str_append(LOC,clog_default->ident);
  if (clog_default->syslog_options & LOG_PID)
    {
      s = str_append(LOC,"[");
      s = num_append(LOC,getpid());
      s = str_append(LOC,"]");
    }
  s = str_append(LOC,": ");
  s = str_append(LOC,msg);
  IGNORE_RESULT(write(syslog_fd,buf,s-buf));
#undef LOC
}

static int
open_crashlog(void)
{
#define CRASHLOG_PREFIX "/var/tmp/quagga."
#define CRASHLOG_SUFFIX "crashlog"
  if (clog_default && clog_default->ident)
    {
      /* Avoid strlen since it is not async-signal-safe. */
      const char *p;
      size_t ilen;

      for (p = clog_default->ident, ilen = 0; *p; p++)
	ilen++;
      {
	char buf[sizeof(CRASHLOG_PREFIX)+ilen+sizeof(CRASHLOG_SUFFIX)+3];
	char *s = buf;
#define LOC s,buf+sizeof(buf)-s
	s = str_append(LOC, CRASHLOG_PREFIX);
	s = str_append(LOC, clog_default->ident);
	s = str_append(LOC, ".");
	s = str_append(LOC, CRASHLOG_SUFFIX);
#undef LOC
	*s = '\0';
	return open(buf, O_WRONLY|O_CREAT|O_EXCL, LOGFILE_MASK);
      }
    }
  return open(CRASHLOG_PREFIX CRASHLOG_SUFFIX, O_WRONLY|O_CREAT|O_EXCL,
	      LOGFILE_MASK);
#undef CRASHLOG_SUFFIX
#undef CRASHLOG_PREFIX
}

/* Note: the goal here is to use only async-signal-safe functions. */
void
clog_signal(int signo, const char *action
#ifdef SA_SIGINFO
	    , siginfo_t *siginfo, void *program_counter
#endif
	   )
{
  time_t now;
  char buf[sizeof("DEFAULT: Received signal S at T (si_addr 0xP, PC 0xP); aborting...")+100];
  char *s = buf;
  char *msgstart = buf;
#define LOC s,buf+sizeof(buf)-s

  time(&now);
  if (clog_default)
    {
      s = str_append(LOC,clog_proto_names[clog_default->protocol]);
      *s++ = ':';
      *s++ = ' ';
      msgstart = s;
    }
  s = str_append(LOC,"Received signal ");
  s = num_append(LOC,signo);
  s = str_append(LOC," at ");
  s = num_append(LOC,now);
#ifdef SA_SIGINFO
  s = str_append(LOC," (si_addr 0x");
  s = hex_append(LOC,(u_long)(siginfo->si_addr));
  if (program_counter)
    {
      s = str_append(LOC,", PC 0x");
      s = hex_append(LOC,(u_long)program_counter);
    }
  s = str_append(LOC,"); ");
#else /* SA_SIGINFO */
  s = str_append(LOC,"; ");
#endif /* SA_SIGINFO */
  s = str_append(LOC,action);
  if (s < buf+sizeof(buf))
    *s++ = '\n';

  /* N.B. implicit priority is most severe */
#define PRI LOG_CRIT

#define DUMP(FD) write(FD, buf, s-buf)
  /* If no file logging configured, try to write to fallback log file. */
  if ((logfile_fd >= 0) || ((logfile_fd = open_crashlog()) >= 0))
    IGNORE_RESULT(DUMP(logfile_fd));
  if (!clog_default)
    IGNORE_RESULT(DUMP(STDERR_FILENO));
  else
    {
      if (PRI <= clog_default->maxlvl[CLOG_DEST_STDOUT])
        IGNORE_RESULT(DUMP(STDOUT_FILENO));
      /* Remove trailing '\n' for monitor and syslog */
      *--s = '\0';
      //if (PRI <= clog_default->maxlvl[CLOG_DEST_MONITOR])
      //   vty_log_fixed(buf,s-buf);
      if (PRI <= clog_default->maxlvl[CLOG_DEST_SYSLOG])
	syslog_sigsafe(PRI|clog_default->facility,msgstart,s-msgstart);
    }
#undef DUMP

  clog_backtrace_sigsafe(PRI,
#ifdef SA_SIGINFO
  			 program_counter
#else
			 NULL
#endif
			);
#undef PRI
#undef LOC
}

/* Log a backtrace using only async-signal-safe functions.
   Needs to be enhanced to support syslog logging. */
void
clog_backtrace_sigsafe(int priority __attribute__((unused)), 
                       void *program_counter __attribute__((unused)))
{
#ifdef HAVE_STACK_TRACE
  static const char pclabel[] = "Program counter: ";
  void *array[64];
  int size;
  char buf[100];
  char *s, **bt = NULL;
#define LOC s,buf+sizeof(buf)-s

#ifdef HAVE_GLIBC_BACKTRACE
  if (((size = backtrace(array,sizeof(array)/sizeof(array[0]))) <= 0) ||
      ((size_t)size > sizeof(array)/sizeof(array[0])))
    return;

#define DUMP(FD) { \
  if (program_counter) \
    { \
      write(FD, pclabel, sizeof(pclabel)-1); \
      backtrace_symbols_fd(&program_counter, 1, FD); \
    } \
  write(FD, buf, s-buf);	\
  backtrace_symbols_fd(array, size, FD); \
}
#elif defined(HAVE_PRINTSTACK)
#define DUMP(FD) { \
  if (program_counter) \
    write((FD), pclabel, sizeof(pclabel)-1); \
  write((FD), buf, s-buf); \
  printstack((FD)); \
}
#endif /* HAVE_GLIBC_BACKTRACE, HAVE_PRINTSTACK */

  s = buf;
  s = str_append(LOC,"Backtrace for ");
  s = num_append(LOC,size);
  s = str_append(LOC," stack frames:\n");

  if ((logfile_fd >= 0) || ((logfile_fd = open_crashlog()) >= 0))
    DUMP(logfile_fd)
  if (!clog_default)
    DUMP(STDERR_FILENO)
  else
    {
      if (priority <= clog_default->maxlvl[CLOG_DEST_STDOUT])
	DUMP(STDOUT_FILENO)
      /* Remove trailing '\n' for monitor and syslog */
      *--s = '\0';
      if (priority <= clog_default->maxlvl[CLOG_DEST_MONITOR])
	vty_log_fixed(buf,s-buf);
      if (priority <= clog_default->maxlvl[CLOG_DEST_SYSLOG])
	syslog_sigsafe(priority|clog_default->facility,buf,s-buf);
      {
	int i;
#ifdef HAVE_GLIBC_BACKTRACE
        bt = backtrace_symbols(array, size);
#endif
	/* Just print the function addresses. */
	for (i = 0; i < size; i++)
	  {
	    s = buf;
	    if (bt) 
	      s = str_append(LOC, bt[i]);
	    else {
	      s = str_append(LOC,"[bt ");
	      s = num_append(LOC,i);
	      s = str_append(LOC,"] 0x");
	      s = hex_append(LOC,(u_long)(array[i]));
	    }
	    *s = '\0';
	    //if (priority <= clog_default->maxlvl[CLOG_DEST_MONITOR])
	    //  vty_log_fixed(buf,s-buf);
	    if (priority <= clog_default->maxlvl[CLOG_DEST_SYSLOG])
	      syslog_sigsafe(priority|clog_default->facility,buf,s-buf);
	  }
	  if (bt)
	    free(bt);
      }
    }
#undef DUMP
#undef LOC
#endif /* HAVE_STRACK_TRACE */
}

void
clog_backtrace(int priority)
{
#ifndef HAVE_GLIBC_BACKTRACE
  c_log(NULL, priority, "No backtrace available on this platform.");
#else
  void *array[20];
  int size, i;
  char **strings;

  if (((size = backtrace(array,sizeof(array)/sizeof(array[0]))) <= 0) ||
      ((size_t)size > sizeof(array)/sizeof(array[0])))
    {
      c_log_err("Cannot get backtrace, returned invalid # of frames %d "
	       "(valid range is between 1 and %lu)",
	       size, (unsigned long)(sizeof(array)/sizeof(array[0])));
      return;
    }
  c_log(NULL, priority, "Backtrace for %d stack frames:", size);
  if (!(strings = backtrace_symbols(array, size)))
    {
      c_log_err("Cannot get backtrace symbols (out of memory?)");
      for (i = 0; i < size; i++)
	c_log(NULL, priority, "[bt %d] %p",i,array[i]);
    }
  else
    {
      for (i = 0; i < size; i++)
	c_log(NULL, priority, "[bt %d] %s",i,strings[i]);
      free(strings);
    }
#endif /* HAVE_GLIBC_BACKTRACE */
}

void
c_log (struct clog *zl, int priority, const char *format, ...)
{
  va_list args;

  va_start(args, format);
  vclog (zl, priority, format, args);
  va_end (args);
}

#define CLOG_FUNC(FUNCNAME,PRIORITY) \
void \
FUNCNAME(const char *format, ...) \
{ \
  va_list args; \
  va_start(args, format); \
  vclog (NULL, PRIORITY, format, args); \
  va_end(args); \
}

CLOG_FUNC(c_log_err, LOG_ERR)

CLOG_FUNC(c_log_warn, LOG_WARNING)

CLOG_FUNC(c_log_info, LOG_INFO)

CLOG_FUNC(c_log_notice, LOG_NOTICE)

CLOG_FUNC(c_log_debug, LOG_DEBUG)

#undef CLOG_FUNC

void
_clog_assert_failed (const char *assertion, const char *file,
		     unsigned int line, const char *function)
{
  /* Force fallback file logging? */
  if (clog_default && !clog_default->fp &&
      ((logfile_fd = open_crashlog()) >= 0) &&
      ((clog_default->fp = fdopen(logfile_fd, "w")) != NULL))
    clog_default->maxlvl[CLOG_DEST_FILE] = LOG_ERR;
  c_log(NULL, LOG_CRIT, "Assertion `%s' failed in file %s, line %u, function %s",
       assertion,file,line,(function ? function : "?"));
  clog_backtrace(LOG_CRIT);
  abort();
}


/* Open log stream */
struct clog *
openclog (const char *progname, clog_proto_t protocol,
	  int syslog_flags, int syslog_facility)
{
  struct clog *zl;
  u_int i;

  zl = XCALLOC(MTYPE_CLOG, sizeof (struct clog));

  zl->ident = progname;
  zl->protocol = protocol;
  zl->facility = syslog_facility;
  zl->syslog_options = syslog_flags;

  /* Set default logging levels. */
  for (i = 0; i < sizeof(zl->maxlvl)/sizeof(zl->maxlvl[0]); i++)
    zl->maxlvl[i] = CLOG_DISABLED;
  zl->maxlvl[CLOG_DEST_MONITOR] = LOG_DEBUG;
  zl->default_lvl = LOG_DEBUG;

  openlog (progname, syslog_flags, zl->facility);
  
  return zl;
}

void
closeclog (struct clog *zl)
{
  closelog();

  if (zl->fp != NULL)
    fclose (zl->fp);

  if (zl->filename != NULL)
    free (zl->filename);

  XFREE (MTYPE_CLOG, zl);
}

/* Called from command.c. */
void
clog_set_level (struct clog *zl, clog_dest_t dest, int log_level)
{
  if (zl == NULL)
    zl = clog_default;

  zl->maxlvl[dest] = log_level;
}

int
clog_set_file (struct clog *zl, const char *filename, int log_level)
{
  FILE *fp;
  mode_t oldumask;

  /* There is opend file.  */
  clog_reset_file (zl);

  /* Set default zl. */
  if (zl == NULL)
    zl = clog_default;

  /* Open file. */
  oldumask = umask (0777 & ~LOGFILE_MASK);
  fp = fopen (filename, "a");
  umask(oldumask);
  if (fp == NULL)
    return 0;

  /* Set flags. */
  zl->filename = strdup (filename);
  zl->maxlvl[CLOG_DEST_FILE] = log_level;
  zl->fp = fp;
  logfile_fd = fileno(fp);

  return 1;
}

/* Reset opend file. */
int
clog_reset_file (struct clog *zl)
{
  if (zl == NULL)
    zl = clog_default;

  if (zl->fp)
    fclose (zl->fp);
  zl->fp = NULL;
  logfile_fd = -1;
  zl->maxlvl[CLOG_DEST_FILE] = CLOG_DISABLED;

  if (zl->filename)
    free (zl->filename);
  zl->filename = NULL;

  return 1;
}

/* Reopen log file. */
int
clog_rotate (struct clog *zl)
{
  int level;

  if (zl == NULL)
    zl = clog_default;

  if (zl->fp)
    fclose (zl->fp);
  zl->fp = NULL;
  logfile_fd = -1;
  level = zl->maxlvl[CLOG_DEST_FILE];
  zl->maxlvl[CLOG_DEST_FILE] = CLOG_DISABLED;

  if (zl->filename)
    {
      mode_t oldumask;
      int save_errno;

      oldumask = umask (0777 & ~LOGFILE_MASK);
      zl->fp = fopen (zl->filename, "a");
      save_errno = errno;
      umask(oldumask);
      if (zl->fp == NULL)
        {
	  c_log_err("Log rotate failed: cannot open file %s for append: %s",
	  	   zl->filename, c_safe_strerror(save_errno));
	  return -1;
        }	
      logfile_fd = fileno(zl->fp);
      zl->maxlvl[CLOG_DEST_FILE] = level;
    }

  return 1;
}

/* Message c_lookup function. */
const char *
c_lookup (const struct message *mes, int key)
{
  const struct message *pnt;

  for (pnt = mes; pnt->key != 0; pnt++) 
    if (pnt->key == key) 
      return pnt->str;

  return "";
}

/* Older/faster version of message c_lookup function, but requires caller to pass
 * in the array size (instead of relying on a 0 key to terminate the search). 
 *
 * The return value is the message string if found, or the 'none' pointer
 * provided otherwise.
 */
const char *
mes_c_lookup (const struct message *meslist, int max, int index,
  const char *none, const char *mesname)
{
  int pos = index - meslist[0].key;
  
  /* first check for best case: index is in range and matches the key
   * value in that slot.
   * NB: key numbering might be offset from 0. E.g. protocol constants
   * often start at 1.
   */
  if ((pos >= 0) && (pos < max)
      && (meslist[pos].key == index))
    return meslist[pos].str;

  /* fall back to linear search */
  {
    int i;

    for (i = 0; i < max; i++, meslist++)
      {
	if (meslist->key == index)
	  {
	    const char *str = (meslist->str ? meslist->str : none);
	    
	    c_log_debug ("message index %d [%s] found in %s at position %d (max is %d)",
		      index, str, mesname, i, max);
	    return str;
	  }
      }
  }
  c_log_err("message index %d not found in %s (max is %d)", index, mesname, max);
  assert (none);
  return none;
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char *
c_safe_strerror(int errnum)
{
  const char *s = strerror(errnum);
  return (s != NULL) ? s : "Unknown error";
}

