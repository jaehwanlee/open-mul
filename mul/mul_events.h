/*
 *  mul_events.h: MUL event handling 
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

#ifndef __MUL_EVENTS_H__
#define __MUL_EVENTS_H__

/* Cast to struct event */
#define C_EVENT(x) ((struct event *)(x))

typedef enum 
{
    C_EVENT_NEW_SW_CONN,
    C_EVENT_NEW_APP_CONN,
    C_EVENT_NEW_HA_CONN,
}c_event_conn_t;

void    c_write_event_sched(void *conn_arg);
int     c_worker_event_new_conn(void *ctx_arg, void *msg_arg);
void    c_switch_thread_read(evutil_socket_t fd, short events, void *arg);
void    c_accept(evutil_socket_t listener, short event, void *arg);
void    c_app_accept(evutil_socket_t listener, short event, void *arg);
void    c_aux_app_accept(evutil_socket_t listener, short event, void *arg);
void    c_worker_ipc_read(evutil_socket_t listener, short event, void *arg);
void    c_per_worker_timer_event(evutil_socket_t fd, short event, void *arg);
void    c_switch_thread_write_event(evutil_socket_t fd, short events, void *arg);
void    c_thread_write_event(evutil_socket_t fd, short events, void *arg);

static inline void
c_conn_events_del(c_conn_t *conn)
{
    if (conn->rd_event) {
        event_del(C_EVENT(conn->rd_event));
        event_free(C_EVENT(conn->rd_event));
        conn->rd_event = NULL;
    }
    if (conn->wr_event) {
        event_del(C_EVENT(conn->wr_event));
        event_free(C_EVENT(conn->wr_event));
        conn->wr_event = NULL;
    }
}

static inline void
c_conn_close(c_conn_t *conn)
{
    if (conn->fd > 0) 
        close(conn->fd);
    conn->fd = 0;
    conn->dead = 1;
}

static inline void
c_conn_destroy(c_conn_t *conn)
{
    c_conn_events_del(conn);
    c_conn_close(conn);

    if (conn->cbuf) {
        free_cbuf(conn->cbuf);
        conn->cbuf = NULL;
    }

    c_wr_lock(&conn->conn_lock);
    cbuf_list_purge(&conn->tx_q);
    c_wr_unlock(&conn->conn_lock);
}

static inline void
c_conn_assign_fd(c_conn_t *conn, int fd)
{
    struct sockaddr_in peer_addr;
    socklen_t          peer_sz = sizeof(peer_addr);

    if (fd <= 0) return;

    conn->fd = fd;
    conn->dead = 0;
    if (conn->cbuf) {
        free_cbuf(conn->cbuf);
        conn->cbuf = NULL;
    }

    cbuf_list_purge(&conn->tx_q);
    
    memset(conn->conn_str, 0, sizeof(conn->conn_str));
    if (getpeername(fd, (void *)&peer_addr, &peer_sz) < 0) {
        c_log_err("get peer failed");
        return;
    }

    snprintf(conn->conn_str, C_CONN_DESC_SZ -1, "%s:%d",
             inet_ntoa(peer_addr.sin_addr), ntohs(peer_addr.sin_port));
}

#ifdef HAVE_SG_TX
static inline void
c_thread_sg_tx_sync(void *conn_arg)
{
    c_conn_t *conn = conn_arg;

    c_wr_lock(&conn->conn_lock);
    c_socket_write_nonblock_sg_loop(conn, c_write_event_sched);
    c_wr_unlock(&conn->conn_lock);
}

static inline void
c_thread_tx(void *conn_arg, struct cbuf *b, bool only_q)
{
    c_conn_t *conn = conn_arg;

    c_wr_lock(&conn->conn_lock);
    if (cbuf_list_queue_len(&conn->tx_q)  > C_TX_BUF_SZ) {
        c_wr_unlock(&conn->conn_lock);
        free_cbuf(b);
        return;
    }

    cbuf_list_queue_tail(&conn->tx_q, b);

    if (!only_q) {
        c_socket_write_nonblock_loop(conn, c_write_event_sched);
    }

    c_wr_unlock(&conn->conn_lock);
}
#else
static inline void
c_thread_sg_tx_sync(void *conn_arg UNUSED)
{
    return;
}

static inline void
c_thread_tx(void *conn_arg, struct cbuf *b, bool only_q UNUSED)
{
    c_conn_t *conn = conn_arg;

    c_wr_lock(&conn->conn_lock);
    if (cbuf_list_queue_len(&conn->tx_q)  > C_TX_BUF_SZ) {
        c_wr_unlock(&conn->conn_lock);
        free_cbuf(b);
        return;
    }

    cbuf_list_queue_tail(&conn->tx_q, b);

    c_socket_write_nonblock_loop(conn, c_write_event_sched);

    c_wr_unlock(&conn->conn_lock);
}

#endif

static inline void
c_thread_chain_tx(void *conn_arg, struct cbuf **b, size_t nbufs)
{
    c_conn_t *conn = conn_arg;
    int n;

    c_wr_lock(&conn->conn_lock);
    if (cbuf_list_queue_len(&conn->tx_q) + nbufs  > C_TX_BUF_SZ) {
        c_wr_unlock(&conn->conn_lock);
        goto free_all;
    }

    for (n = 0; n < nbufs; n++) {
        cbuf_list_queue_tail(&conn->tx_q, b[n]);
    }

    c_socket_write_nonblock_sg_loop(conn, c_write_event_sched);
    c_wr_unlock(&conn->conn_lock);

    return;

free_all:
    for (n = 0; n < nbufs; n++) {
        free_cbuf(b[n]);
    }
}



#endif
