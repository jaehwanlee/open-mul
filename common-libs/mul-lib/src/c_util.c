/*
 *  c_util.c: Common utility functions 
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "cbuf.h"
#include "c_util.h"

int
c_daemon (int nochdir, int noclose)
{
    pid_t pid;

    pid = fork ();

    if (pid < 0) {
        return -1;
    }

    if (pid != 0) {
        exit (0);
    }

    pid = setsid();

    if (pid == -1) {
        return -1;
    }

    if (!nochdir) {
        if (chdir("/")) {
            printf("Failed to chdir /\n");
            return -1;
        }
    }

    if (!noclose) {
        int fd;

        fd = open ("/dev/null", O_RDWR, 0);
        if (fd != -1) {
	        dup2 (fd, STDIN_FILENO);
	        dup2 (fd, STDOUT_FILENO);
	        dup2 (fd, STDERR_FILENO);
	        if (fd > 2)
	            close (fd);
	    }
    }

    umask (0027);

    return 0;
}


pid_t
c_pid_output(const char *path)
{
    int tmp;
    int fd;
    pid_t pid;
    char buf[16];
    struct flock lock;
    mode_t oldumask;

    pid = getpid ();
#define PIDFILE_MASK 0644
    oldumask = umask(0777 & ~PIDFILE_MASK);
    fd = open(path, O_RDWR | O_CREAT, PIDFILE_MASK);
    if (fd < 0) {
        perror("open");
        umask(oldumask);
        exit(1);
    } else {
        unsigned int pidsize;

        umask(oldumask);
        memset (&lock, 0, sizeof(lock));

        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;

        if (fcntl(fd, F_SETLK, &lock) < 0) {
            printf("Duplicate instance running\n");
            exit(1);
        }

        sprintf (buf, "%d\n", (int) pid);
        pidsize = strlen(buf);
        if ((tmp = write (fd, buf, pidsize)) != (int)pidsize)
            printf("Could not write pid %d to pid_file %s\n",
                   (int)pid, path);
        else if (ftruncate(fd, pidsize) < 0)
            printf("Could not truncate pid_file %s to %u bytes\n",
                   path, (u_int)pidsize);
    }
    return pid;
}



int
c_make_socket_nonblocking(int fd)
{
    int flags;
    if ((flags = fcntl(fd, F_GETFL, NULL)) < 0) {
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return -1;
    }

    return 0;
}

int
c_server_socket_create(uint32_t server_ip, uint16_t port)
{
    struct sockaddr_in sin;
    int                fd;
    int                one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("");
        return fd;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(server_ip);
    sin.sin_port = htons(port);

    c_make_socket_nonblocking(fd);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        return -1;
    }

    return fd;
}

int
c_client_socket_create(char *server_ip, uint16_t port)
{
    struct sockaddr_in sin;
    int                fd;
    int                one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return fd;
    }

    sin.sin_family = AF_INET; 
    sin.sin_port = htons(port);
    if (!inet_aton(server_ip, &sin.sin_addr)) {
        return -1;
    }

    memset(sin.sin_zero, 0, sizeof sin.sin_zero);
    if (connect(fd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1) {
        perror("connect");
        return -1;
    }

    c_make_socket_nonblocking(fd);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));    

    return fd;
}


int
c_server_socket_close(int fd)
{
    close(fd);
    return 0;
}

int
c_client_socket_close(int fd)
{
    close(fd);
    return 0;
}

int
c_sock_set_recvbuf (int fd, size_t size)
{
  return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size));
}

int c_tcpsock_set_nodelay(int fd)
{
    int zero = 0;

    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));

}

void
c_hex_dump(void *ptr, int len)
{
    int i= 0, idx = 0;
    unsigned char tmp_buf[64] = { 0 };

    for (i = 0; i < len; i++) {
        idx += snprintf((void *)(tmp_buf + idx), 3, "%02x",
                        *((unsigned char *)ptr + i));

        if (idx >= 32) {
            printf("0x%s\r\n", tmp_buf);
            memset(tmp_buf, 0, 32);
            idx = 0;
        }
    }

    if (idx) {
        printf("0x%s\r\n", tmp_buf);
    }

    return;
}

int 
c_socket_read_nonblock_loop(int fd, void *arg, c_conn_t *conn,
                            const size_t rcv_buf_sz, 
                            conn_proc_t proc_msg, int (*get_data_len)(void *),
                            bool (*validate_hdr)(void *), size_t hdr_sz )
{
    ssize_t             rd_sz = -1;
    struct cbuf         curr_b, *b = NULL;
    int                 loop_cnt = 0;

    if (!conn->cbuf) {
        b = alloc_cbuf(rcv_buf_sz);
    } else {
        b = conn->cbuf; 
    }


    while (1) {
        if (!cbuf_tailroom(b)) {
            struct cbuf *new;

            new = alloc_cbuf(b->len + rcv_buf_sz);
            if (b->len) {
                memcpy(new->data, b->data, b->len);
                cbuf_put(new, b->len);
            }
            free_cbuf(b);
            b = new;
        }

        if (conn->conn_type == C_CONN_TYPE_SOCK) {
            if (++loop_cnt < 100) {
                rd_sz = recv(fd, b->tail, cbuf_tailroom(b), 0);
            } else rd_sz = -1;
        } else {
            rd_sz = read(fd, b->tail, cbuf_tailroom(b));
        }

        if (rd_sz <= 0) {
            conn->cbuf = b;
            break;
        }

        cbuf_put(b, rd_sz);

        while (b->len >= hdr_sz && 
               b->len >= get_data_len(b->data))  {

            if (!validate_hdr(b->data)) {
                printf("%s: Corrupted header", FN);
                return 0; /* Close the socket */
            }

            curr_b.data = b->data;
            curr_b.len = get_data_len(b->data);
            curr_b.tail = b->data + curr_b.len;

            proc_msg(arg, &curr_b);
            cbuf_pull(b, curr_b.len);
        }
    }

    return rd_sz;
}

int
c_socket_write_nonblock_loop(c_conn_t *conn, 
                             void (*sched_tx)(void *))
{
    struct cbuf *buf;
    int         sent_sz;
    int         err = 0;

    while ((buf = cbuf_list_dequeue(&conn->tx_q))) {

        sent_sz = send(conn->fd, buf->data, buf->len, MSG_NOSIGNAL);
        if (sent_sz <= 0) {
            cbuf_list_queue(&conn->tx_q, buf);
            if (sent_sz == 0 || errno == EAGAIN) {
                conn->tx_err++;
                goto sched_tx_event;
            }
            err = -1;
            goto out;
        }

        if (sent_sz < buf->len) {
            cbuf_pull(buf, sent_sz);
            cbuf_list_queue(&conn->tx_q, buf);
            goto sched_tx_event;
        }

        conn->tx_pkts++;

        free_cbuf(buf);
    }

out:
    return err;

sched_tx_event:
    sched_tx(conn);
    return err;

}


int 
c_socket_write_nonblock_sg_loop(c_conn_t *conn,
                                void (*sched_tx)(void *))
{
    struct cbuf     *buf;
    struct cbuf     *curr = conn->tx_q.next;
    int             sent_sz;
    int             err = 0, qlen = 0;
    struct iovec    iov[C_TX_BUF_SZ];

    if (unlikely(!cbuf_list_queue_len(&conn->tx_q))) {
        return 0;
    }

    if (unlikely(conn->dead)) {
        cbuf_list_purge(&conn->tx_q);
        err = -1;
        goto out;
    }

    /* TODO : Optimize this */
    while (curr && qlen < C_TX_BUF_SZ) {
        iov[qlen].iov_base = curr->data;
        iov[qlen++].iov_len = curr->len;
        curr = curr->next;
    }

    sent_sz = writev(conn->fd, iov, qlen);

    if (sent_sz <= 0) {
        if (sent_sz == 0 || errno == EAGAIN) {
            conn->tx_err++;
            goto sched_tx_event;
        }
        conn->dead = 1;
        err = -1;
        goto out;
    }

    while (sent_sz && (buf = cbuf_list_dequeue(&conn->tx_q))) {
        if (sent_sz >= buf->len) {
            sent_sz -= buf->len;
            free_cbuf(buf);
            conn->tx_pkts++;
        } else {
            cbuf_pull(buf, sent_sz);
            cbuf_list_queue(&conn->tx_q, buf);
            goto sched_tx_event;
        }
    }

out:
    return err;

sched_tx_event:
    sched_tx(conn);
    return err;
}

