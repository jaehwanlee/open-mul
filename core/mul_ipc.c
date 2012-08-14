/*
 *  mul_ipc.c: MUL IPC handling 
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

void  *
alloc_ipc_msg(uint8_t ipc_type, uint16_t ipc_msg_type)
{
    struct c_ipc_hdr *ipc_hdr = NULL;

    switch (ipc_type) {
    case C_IPC_THREAD:
        ipc_hdr = (void *)malloc(sizeof(struct c_ipc_hdr) +
                                 sizeof(struct c_ipc_thread_msg));
        if (!ipc_hdr) {
            return NULL;
        }
        ipc_hdr->ipc_type = C_IPC_THREAD;
        ipc_hdr->ipc_msg_len = sizeof(struct c_ipc_hdr) +
                               sizeof(struct c_ipc_thread_msg);
        ipc_hdr->ipc_msg_type = ipc_msg_type;

        break;
    case C_IPC_EXT_APP:
        break;
    }

    return ipc_hdr;
}

int
c_send_unicast_ipc_msg(int fd, void *msg)
{
    struct c_ipc_hdr   *ipc_hdr = msg;
    int                ret;


    ret = write(fd, msg, ipc_hdr->ipc_msg_len);
    if (ret < 0) {
        c_log_warn("ipc_write failed");
        return ret;
    }

    /* TODO : ret < len : reschedule write */

    return 0;
}

static void 
c_ipc_worker_msg_rcv(struct c_worker_ctx *c_wrk_ctx,
                     struct c_ipc_hdr *hdr)
{
    size_t len = hdr->ipc_msg_len;
    struct c_ipc_thread_msg *msg;

    if (hdr->ipc_type != C_IPC_THREAD) {
        c_log_err("unexpected ipc type");
        return;
    }

    if (len < MIN_IPC_THREAD_MSG_SZ ||
        len > MAX_IPC_THREAD_MSG_SZ) {
        c_log_err("unexpected ipc len");
        return;
    }

    msg = (void *)(hdr + 1);
    switch (hdr->ipc_msg_type) {
    case C_IPC_THREAD_NEW_CONN_FD:
        c_worker_event_new_conn(c_wrk_ctx, msg);
        break;
    default:
        c_log_err("unknown ipc msg type");
        break;
    }

    return;
}

void
c_ipc_msg_rcv(void *ctx_arg, struct cbuf *buf)
{
    struct c_cmn_ctx *cmn_ctx = ctx_arg;

    switch(cmn_ctx->thread_type) {
    case THREAD_MAIN:
        /* Nothing to do now */
        break;
    case THREAD_WORKER:
    case THREAD_APP:
        return c_ipc_worker_msg_rcv((void *)cmn_ctx, (void *)buf->data);
    }

    return;
}
