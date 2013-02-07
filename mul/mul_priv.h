/*
 *  mul_priv.h: MUL private defines 
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
#ifndef __MUL_PRIV_H__
#define __MUL_PRIV_H__

/* Generic defines */
#define C_VTY_NAME                "mul-vty"

#define C_LISTEN_PORT               6633 
#define C_APP_LISTEN_PORT           7744 
#define C_APP_AUX_LISTEN_PORT       7745 
#define C_IPC_PATH                  "/var/run/cipc_x"
#define C_IPC_APP_PATH              "/var/run/cipc_app_x"
#define C_PER_WORKER_TIMEO          1

#define C_VTY_PORT                  7000
#define C_PID_PATH                  "/var/run/mul.pid"
#define C_VTYSH_PATH 	            "/var/run/mul.vty"

#define OFSW_MAX_PORTS              65536	
#define OFC_SUCCESS                 0
#define OFC_FAIL                    -1
#define OFC_SW_TIME                 20
#define true                        1
#define false                       0
#define OFC_SW_PORT_VALID           true
#define OFC_SW_PORT_INVALID         false
#define OFC_SW_PORT_INFO_DIRTY      0x80000000
#define OFC_RCV_BUF_SZ              4096 
#define CIPC_RCV_BUF_SZ             512

struct c_iter_args
{
    void *u_arg;
    void *u_fn;
};

typedef enum port_state {
	P_DISABLED = 1 << 0,
	P_LISTENING = 1 << 1,
	P_LEARNING = 1 << 2,
	P_FORWARDING = 1 << 3,
	P_BLOCKING = 1 << 4
} port_state_t;

struct c_switch;

/* Controller handle structure */
typedef struct ctrl_hdl_ {

    c_rw_lock_t              lock;

    GHashTable               *sw_hash_tbl; 
    ipool_hdl_t              *sw_ipool;
    GSList                   *app_list;

    struct c_cmn_ctx         *main_ctx;
    struct c_cmn_ctx         **worker_ctx_list;

    void                     *vty_master;

    int                      n_threads;
    int                      n_appthreads;

} ctrl_hdl_t;


#define c_sw_hier_rdlock(sw)     \
do {                             \
    c_rd_lock(&ctrl_hdl.lock); \
    c_rd_lock(&sw->lock);      \
} while(0) 

#define c_sw_hier_unlock(sw)     \
do {                             \
    c_rd_unlock(&sw->lock);      \
    c_rd_unlock(&ctrl_hdl.lock); \
} while(0) 


typedef struct c_app_info_
{
    void                    *ctx;
    c_atomic_t              ref;
    struct sockaddr_in      peer_addr;
    c_conn_t                app_conn;
    uint32_t                ev_mask;
    uint32_t                app_flags;    
    uint32_t                n_dpid;
    GHashTable              *dpid_hlist;
    void                    (*ev_cb)(void *app_arg, void *pkt_arg);
    char                    app_name[C_MAX_APP_STRLEN];
} c_app_info_t;

struct c_sw_event_q_ent
{
    c_app_info_t *app;
    struct cbuf *b;
};

#define C_PROCESS_ALL_APP_EVENT_LOOP(sw, b, event, op) \
do {                                                   \
    c_app_info_t *__app;                               \
    for (iterator = sw->app_list; iterator; iterator = iterator->next) { \
        __app = iterator->data;                                          \
        if (!((1 << event) & __app->ev_mask)) {                          \
            continue;                                                    \
        }                                                                \
        app_op->app_handler(sw, b, __app, priv);                         \
    }                                                                    \
} while(0)

#define C_PROCESS_APP_EVENT_LOOP(sw, b, event, op, __app) \
do {                                                      \
    if ((1 << event) & __app->ev_mask) {                  \
        app_op->app_handler(sw, b, __app, priv);          \
    }                                                     \
} while(0)

struct c_switch_fp_ops
{
    int (*fp_fwd)(struct c_switch *sw, struct cbuf *b, void *in_data, size_t len, 
                  struct flow *in_flow, uint16_t iport);
    int (*fp_port_status)(struct c_switch *sw, uint32_t cfg, uint32_t state);

    int (*fp_db_ctor)(struct c_switch *sw);
    void (*fp_db_dtor)(struct c_switch *sw);
};

typedef struct c_sw_ports {
	struct ofp_phy_port      p_info;
	uint32_t				 valid;
} c_sw_ports_t;

typedef struct c_fl_entry_hdr_
{
    c_rw_lock_t             lock;
    uint8_t                 c_fl_ent_type;
    uint8_t                 flags;
    uint16_t                prio;
    uint8_t                 hw_tbl_idx;
    uint8_t                 pad;
    uint32_t                wildcards;
    c_atomic_t              ref;
#define C_FL_IDLE_DFL_TIMEO  (120)
    uint16_t                 i_timeo;
#define C_FL_HARD_DFL_TIMEO  (900)
    uint16_t                 h_timeo;
}c_fl_entry_hdr_t;

#define FL_LOCK fl_hdr.lock
#define FL_ENT_TYPE fl_hdr.c_fl_ent_type
#define FL_REF      fl_hdr.ref
#define FL_FLAGS    fl_hdr.flags
#define FL_PRIO     fl_hdr.prio
#define FL_WILDCARDS fl_hdr.wildcards
#define FL_HWTBL_IDX fl_hdr.hw_tbl_idx
#define FL_ITIMEO    fl_hdr.i_timeo
#define FL_HTIMEO    fl_hdr.h_timeo

typedef struct c_fl_entry_stats_
{
    uint64_t                byte_count;
    uint64_t                pkt_count;                

    long double             pps;
    long double             bps;

    uint64_t                last_refresh;
}c_fl_entry_stats_t;

typedef struct c_fl_entry_
{
    c_fl_entry_hdr_t         fl_hdr;
    struct c_switch          *sw;

    union {
        struct flow          fl;
        /* XXX - TODO for range match */
    };

    union {
        GSList               *cloned_list;
        void                 *parent;    
    };

    c_atomic_t               app_ref;
    GSList                   *app_owner_list;

    size_t                   action_len;
    struct ofp_action_header *actions;

    c_fl_entry_stats_t       fl_stats;
}c_fl_entry_t;

typedef struct c_flow_tbl_
{
#define C_TBL_EXM    (0)
#define C_TBL_RULE   (1)
#define C_TBL_UNK    (2)
    uint8_t           c_fl_tbl_type;
#define C_TBL_HW_IDX_DFL (1)
    uint8_t           hw_tbl_idx;

    union {
        GHashTable   *exm_fl_hash_tbl;
        GSList       *rule_fl_tbl; /* Would change */ 
    };
    void (*dtor)(void *sw, void *tbl);
} c_flow_tbl_t;

/* controller's switch abstraction */
struct c_switch 
{
    void                    *ctx __aligned;   
    struct c_switch_fp_ops  fp_ops; 
    ctrl_hdl_t              *c_hdl;         /* Controller handle */ 
#define DPID datapath_id
    unsigned long long int  datapath_id;	/* DP id */
    void                    *app_flow_tbl;   
    c_flow_tbl_t            exm_flow_tbl;
#define C_RULE_FLOW_TBL_DFL   0
#define C_MAX_RULE_FLOW_TBLS  1
    c_flow_tbl_t            rule_flow_tbls[C_MAX_RULE_FLOW_TBLS];
    GSList                  *app_list;      /* App list intereseted in switch */
    GSList                  *app_eventq;    /* App event queue */

    c_conn_t                conn;

    c_atomic_t              ref;
    c_rw_lock_t             lock;
    uint64_t                last_refresh_time;
    uint64_t                last_sample_time;

    c_sw_ports_t            ports[OFSW_MAX_PORTS];

    uint32_t                switch_state;  /* Switch connection state */

    uint32_t                n_buffers;     /* Max packets buffered at once. */
    int                     alias_id;      /* Canonical switch id */
    uint8_t                 version;       /* OFP version */
    uint8_t                 n_tables;      /* Number of tables supported by
                                              datapath. */
    uint32_t                actions;       /* Bitmap of supported
                                              "ofp_action_type"s. */
    uint32_t                capabilities;
    uint32_t                n_ports;
};

typedef struct c_switch c_switch_t;

struct c_sw_replay_q_ent
{
    c_switch_t              *sw;
    struct cbuf             *b;
};

struct c_buf_iter_arg
{
    uint8_t                 *wr_ptr;
    void                    *data;
};

struct c_port_cfg_state_mask
{
    uint32_t                config_mask;
    uint32_t                state_mask;
};

int     c_l2_lrn_fwd(c_switch_t *sw, struct cbuf *b, void *opi, size_t pkt_len, 
                     struct flow *in_flow, uint16_t in_port); 
int     c_l2_port_status(c_switch_t *sw, uint32_t cfg, uint32_t state);
int     c_l2fdb_init(c_switch_t *sw);
void    c_l2fdb_destroy(c_switch_t *sw);
void    c_ipc_msg_rcv(void *ctx_arg, struct cbuf *buf);
int     c_send_unicast_ipc_msg(int fd, void *msg);
void    *alloc_ipc_msg(uint8_t ipc_type, uint16_t ipc_msg_type);

c_app_info_t *c_app_alloc(void *ctx);
c_app_info_t *c_app_get(ctrl_hdl_t *c_hdl, char *app_name);
void    c_app_put(c_app_info_t *app);
bool    c_app_hdr_valid(void *h_arg);
int     c_builtin_app_start(void *arg);
void    c_signal_app_event(c_switch_t *sw, void *b, c_app_event_t event,
                           void *app_arg, void *priv);
int     __mul_app_command_handler(void *app_arg, struct cbuf *b);
void    c_aux_app_init(void *app_arg);

static inline void 
c_app_ref(void *app_arg)
{
    c_app_info_t *app = app_arg;
    atomic_inc(&app->ref, 1);
}

static inline void 
c_app_unref(void *app_arg)
{
    c_app_info_t *app = app_arg;
    atomic_dec(&app->ref, 1);
}

//#define C_PROF_SUPPORT 1 

#ifdef C_PROF_SUPPORT
uint64_t curr_time;

#define start_prof(X) \
do { \
    if (((struct c_worker_ctx *)(X))->thread_idx == 1) \
        curr_time = g_get_monotonic_time(); \
} while(0)

#define get_prof(X, str)  \
do { \
    if (((struct c_worker_ctx *)(X))->thread_idx == 1) { \
        printf ("%s: time %lluus\n", str, g_get_monotonic_time() - \
                curr_time); \
        curr_time = g_get_monotonic_time(); \
    } \
}while (0)
#else
#define start_prof(X)
#define get_prof(X, str)
#endif

#endif
