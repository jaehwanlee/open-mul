/*
 *  c_util.h: Common utility functions 
 *  Copyright (C) 2012, Dipjyoti Saikia
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

#ifndef __C_UTIL_H__
#define __C_UTIL_H__

#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>

#include "compiler.h"
#include "lock.h"
#include "cbuf.h"

#define C_RBUF_STATE_BEGIN 0
#define C_RBUF_STATE_CONT  1
#define C_RBUF_STATE_END   2
#define C_RBUF_PART_DATA   (1 << 7)

#define C_TX_BUF_SZ        (1024)

typedef struct c_conn_
{
    void                    *rd_event;
    void                    *wr_event;
    int                     fd;
    int                     rd_fd;      /* Only used for unidir connections */
    struct cbuf             *cbuf;
    struct cbuf_head        tx_q;
#define C_CONN_TYPE_SOCK    0
#define C_CONN_TYPE_FILE    1
    uint16_t                conn_type;
    uint16_t                dead;
    uint32_t                rx_pkts;
    uint32_t                tx_pkts;
    uint32_t                tx_err;
#define C_CONN_DESC_SZ 32
    char                    conn_str[C_CONN_DESC_SZ];       /* connection str */
    c_rw_lock_t             conn_lock __aligned; 
}c_conn_t;

typedef void (*conn_proc_t)(void *, struct cbuf *);


int     c_daemon (int nochdir, int noclose);
pid_t   c_pid_output(const char *path);
int     c_server_socket_create(uint32_t server_ip, uint16_t port);
int     c_client_socket_create(char *server_ip, uint16_t port);
int     c_server_socket_close(int fd);
int     c_client_socket_close(int fd);
int     c_make_socket_nonblocking(int fd);
int     c_tcpsock_set_nodelay(int fd);
int     c_sock_set_recvbuf(int fd, size_t len);
void    c_hex_dump(void *ptr, int len);
int     c_socket_read_nonblock_loop(int fd, void *arg, c_conn_t *conn, 
                            const size_t rcv_buf_sz,
                            conn_proc_t proc_msg,
                            int (*get_data_len)(void *), 
                            bool (*validate_hdr)(void *), 
                            size_t hdr_sz);
int     c_socket_write_nonblock_loop(c_conn_t *conn, 
                                     void (*sched_tx)(void *));
int     c_socket_write_nonblock_sg_loop(c_conn_t *conn, 
                                     void (*sched_tx)(void *));


static inline int
c_recvd_sock_dead(int recv_res) 
{
    if ((recv_res == 0) ||
        ((recv_res < 0) && (errno != EAGAIN))) {
        return 1;    
    }

    return 0;
}

static inline void 
c_timeval_diff(struct timeval *res,
               struct timeval *t2,
               struct timeval *t1)
{
    if (t2->tv_usec >= t1->tv_usec) {
        res->tv_usec = t2->tv_usec - t1->tv_usec;
        res->tv_sec = t2->tv_sec - t1->tv_sec;
    } else {
        res->tv_usec = 1000000 - t1->tv_usec + t2->tv_usec;
        res->tv_sec = t2->tv_sec - t1->tv_sec - 1;
    }

    return;
}


static inline uint32_t
make_inet_mask(uint8_t len)
{
    return (~((1 << (32 - (len))) - 1));
}



#define TIME_uS_SCALE (1000000)
#define TIME_uS(x) (x*TIME_uS_SCALE)

#include <stddef.h>
#define container_of(ptr, str, memb)                           \
        ((str *) ((char *) (ptr) - offsetof(str, memb)))

#define FN  __FUNCTION__

#endif
