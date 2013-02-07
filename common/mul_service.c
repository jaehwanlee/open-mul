/*
 *  mul_service.c: MUL service layer 
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

char *__server = "127.0.0.1";

static int c_service_client_sock_init(mul_service_t *serv, char *__server);

static void
c_service_write_event_sched(void *conn_arg)
{
    c_conn_t *conn = conn_arg;
    event_add((struct event *)(conn->wr_event), NULL);
}

static void
c_service_write_event(evutil_socket_t fd UNUSED, short events UNUSED, void *arg)
{
    c_conn_t *conn = arg;

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_loop(conn, c_service_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

static int 
c_service_clr_rcv_buf(mul_service_t *service)
{
    char buf[1024];
    int ret = 0;
    int retries = 0;

    if (service->conn.dead) {
        return -1;
    }

    if (c_make_socket_nonblocking(service->conn.fd))
        c_log_err("%s: Failed to set non-blocking", FN);
    while(1) {
        ret = recv(service->conn.fd, buf, 1024, MSG_DONTWAIT);
        if (ret < 0) {
            break;
        }

        if (retries++ >= 100) {
            c_log_err("%s: noise on service(%s) conn",
                      FN, service->service_name);
            ret = -1;
            break;
        }
    }

    if (c_make_socket_blocking(service->conn.fd)) 
        c_log_err("%s: Failed to set blocking", FN);

    return ret;
}

int 
c_service_timed_throw_resp(mul_service_t *service)
{
    char buf[1024];
    int ret = 0;

    if (service->conn.dead) {
        return -1;
    }

    usleep(50000); /* 50 ms for any response */
    c_make_socket_nonblocking(service->conn.fd);
    ret = recv(service->conn.fd, buf, 1024, MSG_DONTWAIT);
    if (c_recvd_sock_dead(ret)) {
        c_log_debug("Service(%s) connection Broken..\n", service->service_name);
        perror("c_service_timed_throw_resp");
        c_service_reconnect(service);
        ret = -1;
    } else {
        c_make_socket_blocking(service->conn.fd);
    }

    /* return > 0 if we got a response else < 0 */
    return ret;
}

void
c_service_send(mul_service_t *service, struct cbuf *b)
{
    if (service->is_client) {
        c_service_clr_rcv_buf(service);
        c_socket_write_block_loop(&service->conn, b);
    } else {

        c_wr_lock(&service->conn.conn_lock);

        if (cbuf_list_queue_len(&service->conn.tx_q) > 1024) {
            c_wr_unlock(&service->conn.conn_lock);
            free_cbuf(b);
            return;
        }

        cbuf_list_queue_tail(&service->conn.tx_q, b);

        c_socket_write_nonblock_loop(&service->conn, 
                                     c_service_write_event_sched);

        c_wr_unlock(&service->conn.conn_lock);
    }
}

static void
c_service_fetch_response(mul_service_t *service, struct cbuf *b)
{
    service->conn.cbuf = b;
}

/* 
 * c_service_wait_response -
 * 
 * This is not yet smp proof 
 */
struct cbuf *
c_service_wait_response(mul_service_t *service)
{
    int ret = 0;

    if (service->conn.dead) return NULL;
    service->conn.cbuf = NULL;

    ret = c_socket_read_block_loop(service->conn.fd, service, 
                                   &service->conn,
                                   C_SERV_RCV_BUF_SZ,
                                   (conn_proc_t)(c_service_fetch_response),
                                   of_get_data_len, c_app_of_hdr_valid,
                                   sizeof(struct ofp_header));
    if (c_recvd_sock_dead(ret)) {
        c_log_debug("Service(%s) connection Broken..\n", service->service_name);
        perror("c_service_wait_repsonse");
        if (service->conn.cbuf) {
            free_cbuf(service->conn.cbuf);
        }
        c_service_reconnect(service);
        return NULL;
    } else {
        return service->conn.cbuf;
    }
}

static void
c_service_read(evutil_socket_t fd, short events UNUSED, void *arg)
{
    mul_service_t *hdl = arg;
    int           ret;

    ret = c_socket_read_nonblock_loop(fd, hdl, &hdl->conn, C_SERV_RCV_BUF_SZ,
                                      (conn_proc_t)(hdl->ev_cb),
                                       of_get_data_len, c_app_of_hdr_valid,
                                       sizeof(struct ofp_header));

    if (c_recvd_sock_dead(ret)) {
        hdl->conn.dead = 1;
        event_del((hdl->conn.rd_event));
        event_del(hdl->conn.wr_event);
        event_free(hdl->conn.rd_event);
        event_free(hdl->conn.wr_event);
        hdl->conn.rd_event = NULL;
        hdl->conn.wr_event = NULL;
        close(hdl->conn.fd);
        c_log_debug("Service(%s) connection Broken..\n", hdl->service_name);
        free(hdl);
        perror("c_service_read");
    }

    return;
}

static void
c_service_validity_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                         void *arg)
{ 
    mul_service_t *service = arg;
    struct timeval tv = { 5, 0 };

    if (service->conn.dead) return;

    if (!mul_service_alive(service)) {
        c_log_err("%s: service died", service->service_name);
        return c_service_reconnect(service);
    }

    evtimer_add(service->valid_timer_event, &tv);
}

static void
c_service_reconn_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                       void *arg)
{ 
    mul_service_t *service = arg;
    struct timeval tv = { 5, 0 };


   c_log_debug("Retry Conn to service %s", service->service_name);

    if(!c_service_client_sock_init(service, __server)) {
        c_log_debug("Connection to service %s restored", service->service_name);
        event_del((struct event *)(service->reconn_timer_event));
        event_free((struct event *)(service->reconn_timer_event));
        service->reconn_timer_event = NULL;
        service->conn.dead = 0;
        if (service->conn_update) {
            service->conn_update(service, MUL_SERVICE_UP);
        }

        service->valid_timer_event = evtimer_new(service->ev_base,
                                              c_service_validity_timer,
                                              (void *)service);
        evtimer_add(service->valid_timer_event, &tv);
        return;
    }

    evtimer_add(service->reconn_timer_event, &tv);
}


void
c_service_reconnect(mul_service_t *service)
{
    struct timeval tv = { 1, 0 };

    service->conn.dead = 1;

    close(service->conn.fd);

    if (service->reconn_timer_event) {
        event_del((struct event *)(service->reconn_timer_event));
        event_free((struct event *)(service->reconn_timer_event));
        service->reconn_timer_event = NULL;
    }

    if (service->valid_timer_event) {
        event_del((struct event *)(service->valid_timer_event));
        event_free((struct event *)(service->valid_timer_event));
        service->valid_timer_event = NULL;
    }

    if (service->conn_update) {
        service->conn_update(service, MUL_SERVICE_DOWN);
    }
     
    service->reconn_timer_event = evtimer_new(service->ev_base,
                                              c_service_reconn_timer,
                                              (void *)service);
    evtimer_add(service->reconn_timer_event, &tv);

    return;
}

static void
c_service_accept(evutil_socket_t listener, short event UNUSED, void *arg)
{
    mul_service_t *service = arg;
    struct sockaddr_storage ss;
    socklen_t               slen = sizeof(ss);
    int fd                  = accept(listener, (struct sockaddr*)&ss, &slen);
    mul_service_t *serv_inst = NULL;

    c_log_debug("%s:", FN);

    if (fd < 0) {
        perror("accept");
    } else if (fd > FD_SETSIZE) {
        close(fd);
    } else {
        serv_inst = calloc(1, sizeof(mul_service_t));
        assert(serv_inst);
        memcpy(serv_inst, service, sizeof(*serv_inst));
        memset(&serv_inst->conn, 0, sizeof(c_conn_t));

        c_make_socket_nonblocking(fd);
        serv_inst->conn.fd = fd;
        serv_inst->conn.rd_event = event_new(serv_inst->ev_base,
                                             serv_inst->conn.fd,
                                             EV_READ|EV_PERSIST,
                                             c_service_read, serv_inst);

        serv_inst->conn.wr_event = event_new(serv_inst->ev_base,
                                               serv_inst->conn.fd,
                                               EV_WRITE, //|EV_PERSIST,
                                               c_service_write_event, 
                                               &serv_inst->conn);
        event_add((struct event *)(serv_inst->conn.rd_event), NULL);
    }
}


static inline int
c_service_server_sock_init(mul_service_t *serv, char *server UNUSED)
{
    c_log_err("Service Create %s:%d", serv->service_name, serv->serv_port);

    serv->conn.fd = c_server_socket_create(INADDR_ANY, serv->serv_port);
    if (serv->conn.fd <= 0) { 
        return -1;
    }

    serv->conn.rd_event = event_new(serv->ev_base, serv->conn.fd,
                                    EV_READ|EV_PERSIST,
                                    c_service_accept, (void*)serv);

    event_add(serv->conn.rd_event, NULL);

    return 0;
}

static int
c_service_client_sock_init(mul_service_t *serv, char *__server)
{
    serv->conn.fd = c_client_socket_create_blocking(__server, 
                                                    serv->serv_port);
    if (serv->conn.fd <= 0) { 
        return -1;
    }

    return 0;
}

static void
c_service_init(mul_service_t *new_service, void *base, 
               const char *name, uint16_t service_port,
               void (*service_handler)(void *service, struct cbuf *msg))
{
    strncpy(new_service->service_name, name, MAX_SERV_NAME_LEN - 1);
    new_service->ev_base = base;
    new_service->ev_cb = service_handler;
    new_service->serv_port = service_port;
    c_rw_lock_init(&new_service->conn.conn_lock); 
}

mul_service_t *
mul_service_start(void *base, const char *name, uint16_t service_port, 
                  void (*service_handler)(void *service, struct cbuf *msg))
{
    mul_service_t *new_service = NULL;

    if (!(new_service = calloc(1, sizeof(mul_service_t)))) {
        c_log_err("%s: Cant alloc service", FN);
        return NULL;
    }

    c_service_init(new_service, base, name, service_port, service_handler);
    
    while (c_service_server_sock_init(new_service, __server) < 0) {
        c_log_debug("Cannot start service %s..\n", new_service->service_name);
        sleep(1);
    }

    return new_service;
}

mul_service_t *
mul_service_instantiate(void *base, const char *name, uint16_t service_port,
                        void (*conn_update)(void *service,
                                            unsigned char conn_event),
                        bool retry_conn)
{
    mul_service_t *new_service = NULL;
    struct timeval tv = { 2, 0 };

    if (!(new_service = calloc(1, sizeof(mul_service_t)))) {
        c_log_err("%s: Cant alloc service", FN);
        return NULL;
    }

    c_service_init(new_service, base, name, service_port, NULL);
    new_service->is_client = true;
    new_service->conn_update = conn_update;

    while (c_service_client_sock_init(new_service, __server) < 0) {
        c_log_debug("Cannot start service %s..\n", new_service->service_name);
        if (!retry_conn) {
            return NULL;
        } 
        sleep(1);
    }

    new_service->valid_timer_event = evtimer_new(new_service->ev_base,
                                              c_service_validity_timer,
                                              (void *)new_service);
    evtimer_add(new_service->valid_timer_event, &tv);

    c_log_debug("%s: Service (%s) instatiated", FN, name);

    return new_service;
}

void
mul_service_destroy(mul_service_t *service)
{
   if (service->reconn_timer_event) {
        event_del((struct event *)(service->reconn_timer_event));
        event_free((struct event *)(service->reconn_timer_event));
   }

   if (!service->conn.dead) close(service->conn.fd);

   free(service);
}

bool
mul_service_alive(mul_service_t *service)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;

    b = of_prep_msg(sizeof(*cofp_auc), C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_ECHO);

    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        free_cbuf(b);
        return true;
    }

    return false;
}
