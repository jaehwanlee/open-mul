/*
 *  mul_main.c: MUL controller main()
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include "mul.h"

/* of-controller options. */
static struct option longopts[] = 
{
    { "daemon",                 no_argument,       NULL, 'd'},
    { "help",                   no_argument,       NULL, 'h'},
    { "switch-threads",         required_argument, NULL, 'S'},
    { "app-threads",            required_argument, NULL, 'A'},
};

/* Process ID saved for use by init system */
const char *pid_file = C_PID_PATH;

/* handle to controller to pass around */
ctrl_hdl_t ctrl_hdl;

/* Help information display. */
static void
usage(char *progname, int status)
{
    printf("%s Options:\n", progname);
    printf("-d : Daemon Mode\n");
    printf("-S <num> : Number of switch handler threads\n");
    printf("-A <num> : Number of app handler threads\n");
    printf("-h : Help\n");

    exit(status);
}

int
main(int argc, char **argv)
{
    char    *p;
    int     daemon_mode = 0;
    char    *progname;
    int     sthreads = 4, athreads = 2;

    /* Set umask before anything for security */
    umask (0027);

    /* Get program name. */
    progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

    /* Command line option parse. */
    while (1) {
        int opt;

        opt = getopt_long (argc, argv, "dhS:A:", longopts, 0);
        if (opt == EOF)
            break;

        switch (opt) {
        case 0:
            break;
        case 'd':
            daemon_mode = 1;
            break;
        case 'S': 
            sthreads = atoi(optarg);
            if (sthreads < 0 || sthreads > 16) {
                printf ("Illegal:Too many switch threads\n");    
                exit(0);
            }
            break;
        case 'A':
            athreads = atoi(optarg);
            if (athreads < 0 || athreads > 8) {
                printf ("Illegal:Too many app threads\n");    
                exit(0);
            }
            break;
        case 'h':
            usage(progname, 0);
            break;
        default:
            usage(progname, 1);
            break;
        }
    }

    if (daemon_mode) {
        c_daemon(0, 0);
    }

    c_pid_output(C_PID_PATH);

    signal(SIGPIPE, SIG_IGN);

    /* initialize controller handler */
    of_ctrl_init(&ctrl_hdl, sthreads);

    clog_default = openclog (progname, CLOG_MUL,
                             LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
    clog_set_level(NULL, CLOG_DEST_SYSLOG, LOG_WARNING);
    clog_set_level(NULL, CLOG_DEST_STDOUT, LOG_DEBUG);

    c_thread_start(&ctrl_hdl, sthreads, athreads);
    while (1) {
        sleep(1);
    }

    pthread_exit(NULL);

    /* Not reached. */
    return (0);
}
