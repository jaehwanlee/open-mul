/*
 *  mul_thread.h: MUL threading infrastructure 
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
#ifndef __MUL_THREAD_H__
#define __MUL_THREAD_H__

#if 0
#define c_print printf
#define c_err_log c_print
#define c_dbg_log c_print
#define c_warn_log c_print
#define c_log_err
#endif


struct c_main_ctx;

typedef enum thread_state
{
    THREAD_STATE_PRE_INIT,
    THREAD_STATE_FINAL_INIT,
    THREAD_STATE_RUNNING,
    //THREAD_STATE_DESTROY,
}thread_state_t;

typedef struct c_per_thread_dat_
{
    union {
        GSList              *sw_list;	
        GSList              *app_list;	
    };
}c_per_thread_dat_t;

struct c_cmn_ctx
{
    pthread_t           thread;
    struct event_base   *base;
    thread_state_t      run_state;
    void                *c_hdl;
#define THREAD_MAIN 0
#define THREAD_WORKER 1
#define THREAD_APP  2
#define THREAD_VTY  3
    int                 thread_type;
};

struct c_vty_ctx
{
    struct c_cmn_ctx    cmn_ctx;
};

struct c_app_ctx
{
    struct c_cmn_ctx    cmn_ctx;
    int                 thread_idx;
    c_conn_t            main_wrk_conn;
    struct event        *app_main_timer_event;
    c_per_thread_dat_t  thread_data;
};

struct c_worker_ctx
{
    struct c_cmn_ctx    cmn_ctx;
    int                 thread_idx;

    c_conn_t            main_wrk_conn;
    struct event        *worker_timer_event;
	
    c_per_thread_dat_t	thread_data;
};

struct c_main_ctx
{
    struct c_cmn_ctx    cmn_ctx;
#define C_MAX_THREADS  16
    int                 nthreads;
#define C_MAX_APP_THREADS 4 
    int                 n_appthreads;
    int                 switch_lb_hint; 
    int                 app_lb_hint; 
    int                 msg_lb_hint;
    struct c_worker_ctx **worker_pool;
    struct c_app_ctx    **app_pool;

    struct event        *c_accept_event;
    struct event        *c_app_accept_event;
    struct event        *c_app_aux_accept_event;
};


#define c_tid_to_ctx_slot(m, tid)  (&m->worker_pool[tid])
#define c_tid_to_app_ctx_slot(m, tid)  (&m->app_pool[tid])
#define C_THREAD_RUN(ctx)  do { while(1) { c_thread_run(ctx); } } while(0)

struct thread_alloc_args
{
    int     nthreads;
    int     n_appthreads;
    int     thread_type;
    int     thread_idx;
    void    *c_hdl;
};


typedef enum
{
    C_IPC_THREAD_BASE  = 0,  
    C_IPC_EXT_APP_BASE = 100 
}c_ipc_msg_base_t;


typedef enum
{
    C_IPC_THREAD_NEW_CONN_FD = C_IPC_THREAD_BASE,
    C_IPC_THREAD_MAX,
}c_ipc_msg_thread_base_t;


struct c_ipc_hdr
{
#define C_IPC_THREAD   0
#define C_IPC_EXT_APP  1 
    uint8_t     ipc_type;
    uint8_t     ipc_msg_len;    /* Including hdr */
    uint16_t    ipc_msg_type;
};

#define DEF_VALID_VAR(x) x##_valid;
#define DEF_STRUCT_VALID_PAIR(type, var)           \
    uint8_t  DEF_VALID_VAR(var);                   \
    type     var;                                  \

struct c_ipc_thread_msg
{
    DEF_STRUCT_VALID_PAIR(int, new_conn_fd);
    DEF_STRUCT_VALID_PAIR(int, aux_conn);
};

#define MIN_IPC_THREAD_MSG_SZ (sizeof(struct c_ipc_hdr) + \
							   sizeof(struct c_ipc_thread_msg))

#define MAX_IPC_THREAD_MSG_SZ MIN_IPC_THREAD_MSG_SZ

static inline int
c_ipc_get_data_len(void *h_arg)
{
    struct c_ipc_hdr *h = h_arg;

    return h->ipc_msg_len;
}

static inline bool
c_ipc_hdr_valid(void *h_arg)
{
    struct c_ipc_hdr *h = h_arg;

    if (h->ipc_type > C_IPC_EXT_APP ||
        h->ipc_msg_len > MAX_IPC_THREAD_MSG_SZ ||
        h->ipc_msg_type >= C_IPC_THREAD_MAX) {
        return false;
    }

    return true;
}

int     c_thread_start(void *c_hdl, int nthreads, int n_appthreads);
int     c_get_new_switch_worker(struct c_main_ctx *m_ctx);
int     c_get_new_app_worker(struct c_main_ctx *m_ctx);
int     c_set_thread_dfl_affinity(void);

static inline int
c_tid_to_ipc_wr_fd(struct c_main_ctx *m_ctx, int t_idx)
{
    struct c_worker_ctx *w_ctx;

    w_ctx = m_ctx->worker_pool[t_idx];
    return w_ctx->main_wrk_conn.fd;
}

static inline int
c_tid_to_app_ipc_wr_fd(struct c_main_ctx *m_ctx, int t_idx)
{
    struct c_app_ctx *app_ctx;

    app_ctx = m_ctx->app_pool[t_idx];
    return app_ctx->main_wrk_conn.fd;
}

#endif
