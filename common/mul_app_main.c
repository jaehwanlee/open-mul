/*
 *  mul_app_main.c: MUL application main
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
#include "mul_common.h"
#include "mul_vty.h"
#include "mul_app_main.h"

static int c_app_sock_init(c_app_hdl_t *hdl, char *server);

/* MUL app main handle */ 
c_app_hdl_t c_app_main_hdl;
char *server = "127.0.0.1";

static struct option longopts[] = 
{
    { "daemon",                 no_argument,       NULL, 'd'},
    { "help",                   no_argument,       NULL, 'h'},
    { "server-ip",              required_argument, NULL, 's'},
    { "vty-shell",              required_argument, NULL, 'V'},
};

/* Help information display. */
static void
usage(char *progname, int status)
{
    printf("%s Options:\n", progname);
    printf("-d : Daemon Mode\n");
    printf("-s <server-ip> : Server ip address to connect\n");
    printf("-V <vty-port> : vty port address. (enables vty shell)\n");
    printf("-h : Help\n");

    exit(status);
}

void
mul_app_free_buf(void *b UNUSED)
{
    return;
}

static void
c_app_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

static void
c_app_write_event(evutil_socket_t fd UNUSED, short events UNUSED, void *arg)
{
    c_conn_t *conn = arg;

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_loop(conn, c_app_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

static void
c_app_tx(void *conn_arg, struct cbuf *b)
{
    c_conn_t *conn = conn_arg;

    c_wr_lock(&conn->conn_lock);

    if (cbuf_list_queue_len(&conn->tx_q) > 1024) {
        c_wr_unlock(&conn->conn_lock);
        free_cbuf(b);
        return;
    }

    cbuf_list_queue_tail(&conn->tx_q, b);

    c_socket_write_nonblock_loop(conn, c_app_write_event_sched);

    c_wr_unlock(&conn->conn_lock);
}

static void
c_app_notify_reconnect(c_app_hdl_t *hdl)
{
    struct cbuf *b;

    if (!hdl->ev_cb) {
        return;
    }

    b = of_prep_msg(sizeof(struct ofp_header), C_OFPT_RECONN_APP, 0);

    hdl->ev_cb(hdl, b);

    free_cbuf(b);
}

static void
c_app_notify_disconnect(c_app_hdl_t *hdl)
{
    struct cbuf *b;

    if (!hdl->ev_cb) {
        return;
    }

    b = of_prep_msg(sizeof(struct ofp_header), C_OFPT_NOCONN_APP, 0);

    hdl->ev_cb(hdl, b);

    free_cbuf(b);
}

static void
c_app_reconn_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                         void *arg)
{ 
    c_app_hdl_t *hdl = arg;
    struct timeval tv = { 2, 0 };

    if(!c_app_sock_init(hdl, server)) {
        c_log_debug("Connection to controller restored");
        event_del((struct event *)(hdl->reconn_timer_event));
        event_free((struct event *)(hdl->reconn_timer_event));
        c_app_notify_reconnect(hdl);
        return;
    }

    evtimer_add(hdl->reconn_timer_event, &tv);
}

static void
c_app_reconnect(c_app_hdl_t *hdl)
{
    struct timeval tv = { 1, 0 };

    event_del((struct event *)(hdl->conn.rd_event));
    event_del((struct event *)(hdl->conn.wr_event));
    event_free((struct event *)(hdl->conn.rd_event));
    event_free((struct event *)(hdl->conn.wr_event));
    close(hdl->conn.fd);

    c_app_notify_disconnect(hdl);

    hdl->reconn_timer_event = evtimer_new(hdl->base,
                                          c_app_reconn_timer,
                                          (void *)hdl);
    evtimer_add(hdl->reconn_timer_event, &tv);
    return;
}

static int
c_app_recv_msg(void *hdl_arg, struct cbuf *b)
{
    c_app_hdl_t         *hdl = hdl_arg;

    if (hdl->ev_cb) {
        hdl->ev_cb(hdl_arg, b);
    }

    return 0;
}

static void
c_app_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    c_app_hdl_t         *hdl = arg;
    int                 ret;

    ret = c_socket_read_nonblock_loop(fd, hdl, &hdl->conn, C_APP_RCV_BUF_SZ,
                                      (conn_proc_t)c_app_recv_msg,
                                       of_get_data_len, c_app_of_hdr_valid,
                                      sizeof(struct ofp_header));

    if (c_recvd_sock_dead(ret)) {
        c_log_debug("Controller connection Lost..\n");
        c_app_reconnect(hdl);
    }

    return;
}

int
mul_app_command_handler(void *app_name UNUSED, void *b)
{
    c_app_tx(&c_app_main_hdl.conn, (struct cbuf *)(b));
    return 0;
}

int
mul_register_app(void *app_arg UNUSED, char *app_name, uint32_t app_flags,
                 uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                 void  (*ev_cb)(void *app_arg, void *pkt_arg))
{
    uint64_t *p_dpid = NULL;
    struct cbuf *b;
    c_ofp_register_app_t *reg_app;
    int idx = 0;

    b = of_prep_msg(sizeof(struct c_ofp_register_app) + 
                    (n_dpid * sizeof(uint64_t)), C_OFPT_REG_APP, 0);

    reg_app = (void *)(b->data);
    strncpy(reg_app->app_name, app_name, C_MAX_APP_STRLEN-1);
    reg_app->app_flags = htonl(app_flags);
    reg_app->ev_mask = htonl(ev_mask);
    reg_app->dpid = htonl(n_dpid);

    p_dpid = (void *)(reg_app+1);
    for (; idx < n_dpid; idx++) {
        *p_dpid++ = *dpid_list++;
    }

    c_app_main_hdl.ev_cb = ev_cb;

    c_app_tx(&c_app_main_hdl.conn, b);

    return 0;
}

int
mul_unregister_app(char *app_name)
{
    struct cbuf *b;
    c_ofp_unregister_app_t *unreg_app;

    b = of_prep_msg(sizeof(*unreg_app), C_OFPT_UNREG_APP, 0);
    unreg_app = (void *)(b->data);
    strncpy(unreg_app->app_name, app_name, C_MAX_APP_STRLEN-1);

    c_app_tx(&c_app_main_hdl.conn, b);

    return 0;
}

static int 
c_app_init(c_app_hdl_t *hdl)
{
    c_rw_lock_init(&hdl->conn.conn_lock);
    hdl->base = event_base_new();
    assert(hdl->base);

    return 0;
}

static int
c_app_sock_init(c_app_hdl_t *hdl, char *server)
{
    hdl->conn.fd = c_client_socket_create(server, C_APP_PORT);
    if (hdl->conn.fd <= 0) { 
        return -1;
    }

    hdl->conn.rd_event = event_new(hdl->base,
                                   hdl->conn.fd,
                                   EV_READ|EV_PERSIST,
                                   c_app_read, hdl);

    hdl->conn.wr_event = event_new(hdl->base,
                                   hdl->conn.fd,
                                   EV_WRITE, //|EV_PERSIST,
                                   c_app_write_event, &hdl->conn);

    event_add((struct event *)(hdl->conn.rd_event), NULL);

    return 0;
}

static void
mod_initcalls(c_app_hdl_t *hdl)
{
    initcall_t *mod_init;

    mod_init = &__start_modinit_sec;
    do {
        (*mod_init)(hdl->base);
        mod_init++;
    } while (mod_init < &__stop_modinit_sec);
}

static void
modvty__initcalls(void *arg)
{       
    initcall_t *mod_init;                
                                         
    mod_init = &__start_modvtyinit_sec;  
    do {
        (*mod_init)(arg);
        mod_init++;
    } while (mod_init < &__stop_modvtyinit_sec);
}   

DEFUN (show_app_version,
       show_app_version_cmd,
       "show app-host-version",
       SHOW_STR
       "Application Hosting Version")
{
    vty_out(vty, " Version 0.99\r\n");
    return CMD_SUCCESS;
}

static void *
c_app_vty_main(void *arg)
{   
    struct thread thread;
    c_app_hdl_t *hdl = arg;
    char app_vtysh_path[64];

    strncpy(app_vtysh_path, C_APP_VTY_COMMON_PATH, 63 ); 
    strncat(app_vtysh_path, hdl->progname, 63);

    hdl->vty_master = thread_master_create();

    cmd_init(1);
    vty_init(hdl->vty_master);
    modvty__initcalls(hdl);
    install_element(ENABLE_NODE, &show_app_version_cmd);
    sort_node();

    vty_serv_sock(NULL, hdl->vty_port, app_vtysh_path);

    c_log_debug(" App vty thread running \n");
    
     /* Execute each thread. */       
    while (thread_fetch(hdl->vty_master, &thread))
        thread_call(&thread);

    /* Not reached. */
    return (0);
} 

int
main(int argc, char **argv)
{
    char    *p;
    int     daemon_mode = 0;
    int     vty_shell = 0;
    uint16_t vty_port = 0;

    /* Set umask before anything for security */
    umask (0027);

    /* Get program name. */
    c_app_main_hdl.progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

    /* Command line option parse. */
    while (1) {
        int opt;

        opt = getopt_long (argc, argv, "dhS:V:", longopts, 0);
        if (opt == EOF)
            break;

        switch (opt) {
        case 0:
            break;
        case 'd':
            daemon_mode = 1;
            break;
        case 's': 
            server = optarg;
            break;
        case 'V':
            vty_shell = 1;
            vty_port = atoi(optarg);
            break;
        case 'h':
            usage(c_app_main_hdl.progname, 0);
            break;
        default:
            usage(c_app_main_hdl.progname, 1);
            break;
        }
    }

    if (daemon_mode) {
        c_daemon(0, 0);
    }

    clog_default = openclog (c_app_main_hdl.progname, CLOG_MUL,
                             LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
    clog_set_level(NULL, CLOG_DEST_SYSLOG, LOG_WARNING);
    clog_set_level(NULL, CLOG_DEST_STDOUT, LOG_DEBUG);

    c_app_init(&c_app_main_hdl);
    while (c_app_sock_init(&c_app_main_hdl, server) < 0) { 
        c_log_debug("Trying to connect..\n");
        sleep(1);
    }

    mod_initcalls(&c_app_main_hdl);

    if (vty_shell && vty_port > 0) {
        c_app_main_hdl.vty_port = vty_port;
        pthread_create(&c_app_main_hdl.vty_thread, NULL, c_app_vty_main, &c_app_main_hdl);
    }

    while(1) { 
        return event_base_dispatch(c_app_main_hdl.base);
    }

    /* Not reached. */
    return (0);
}
