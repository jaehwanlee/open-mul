/*
 *  mul_app_interface.c: MUL application interface 
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

#define RETURN_APP_ERR(A, B, R, T, C)  \
do {                                                \
     c_app_info_t *_app = (void *)A;                \
     if (_app && (_app->app_flags & C_APP_REMOTE || \
         _app->app_flags & C_APP_AUX_REMOTE)) {     \
        if (!R) return 0;                           \
        return c_remote_app_error(A, B, T, C);      \
     } else {                                       \
        return R;                                   \
     }                                              \
}while(0)

static void c_switch_app_list_exp(c_switch_t *sw);
static void c_switch_app_list_de_exp(c_switch_t *sw);
static void c_app_dpreg_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_dpunreg_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_packet_in_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_port_change_event(c_switch_t *sw, void *buf, 
                              c_app_info_t *app, void *priv);
static void c_app_flow_removed_event(c_switch_t *sw, void *buf, 
                              c_app_info_t *app, void *priv);
static void c_app_flow_mod_failed_event(c_switch_t *sw, void *buf,
                              c_app_info_t *app, void *priv);
static void c_app_event_blackhole(void *app_arg, void *pkt_arg);

extern ctrl_hdl_t ctrl_hdl;

struct c_app_handler_op
{
    void (*pre_proc)(c_switch_t *sw);
    void (*app_handler)(c_switch_t *sw, void *buf, 
                        c_app_info_t *app, void *priv);
    void (*post_proc)(c_switch_t *sw);
} c_app_handler_ops[] = {
    { c_switch_app_list_exp, c_app_dpreg_event, NULL }, 
    { NULL, c_app_dpunreg_event, c_switch_app_list_de_exp },
    { NULL, c_app_packet_in_event, NULL },
    { NULL, c_app_port_change_event, NULL },
    { NULL, c_app_flow_removed_event, NULL },
    { NULL, c_app_flow_mod_failed_event, NULL }
};

#define C_APP_OPS_SZ (sizeof(c_app_handler_ops)/sizeof(struct c_app_handler_op))

void
mul_app_free_buf(void *b)
{
    free_cbuf((struct cbuf *)b);
}

static void
c_app_dpid_key_free(void *arg)
{
    free(arg);
}

static inline c_app_info_t *
__c_app_lookup(ctrl_hdl_t *c_hdl, char *app_name)
{
    c_app_info_t *app;  
    GSList       *iterator = NULL;

    for (iterator = c_hdl->app_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        if (!strncmp(app->app_name, app_name, C_MAX_APP_STRLEN)) { 
            return app;
        }
    }

    return NULL;
}

c_app_info_t *
c_app_get(ctrl_hdl_t *c_hdl, char *app_name)
{
    c_app_info_t *app = NULL;  

    c_rd_lock(&c_hdl->lock);

    if ((app = __c_app_lookup(c_hdl, app_name))) {
        atomic_inc(&app->ref, 1);
    }

    c_rd_unlock(&c_hdl->lock);

    return app;
}

static inline c_app_info_t *
__c_app_get(ctrl_hdl_t *c_hdl, char *app_name)
{
    c_app_info_t *app = NULL;  

    if ((app = __c_app_lookup(c_hdl, app_name))) {
        atomic_inc(&app->ref, 1);
    }

    return app;
}

void
c_app_put(c_app_info_t *app)
{
    if (atomic_read(&app->ref) == 0){
        free(app);
    } else {
        atomic_dec(&app->ref, 1);
    }

}

c_app_info_t *
c_app_alloc(void *ctx)
{
    c_app_info_t *app = NULL;
    
    app = calloc(1, sizeof(c_app_info_t));
    if (!app) {
        c_log_err("%s: App alloc failed", FN);
        return NULL;
    }

    app->ctx = ctx;

    return app;
}

static void
c_per_switch_app_register(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    c_wr_lock(&sw->lock);

    if (g_slist_find(sw->app_list, app)) {
        c_wr_unlock(&sw->lock);
        return;
    }

    atomic_inc(&app->ref, 1);
    sw->app_list = g_slist_append(sw->app_list, app);    
    c_wr_unlock(&sw->lock);
    
}

static void
__c_per_switch_app_register(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    if (g_slist_find(sw->app_list, app)) {
        return;
    }

    atomic_inc(&app->ref, 1);
    sw->app_list = g_slist_append(sw->app_list, app);    
}

static void
c_per_switch_app_unregister(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    c_wr_lock(&sw->lock);
    sw->app_list = g_slist_remove(sw->app_list, app);    
    __of_per_switch_del_app_flow_ownership(sw, app);
    c_wr_unlock(&sw->lock);
    atomic_dec(&app->ref, 1);
}

static void UNUSED
__c_per_switch_app_unregister(void *k, void *v UNUSED, void *arg)
{
    c_switch_t   *sw = k;
    c_app_info_t *app = arg;

    sw->app_list = g_slist_remove(sw->app_list, app);    
    atomic_dec(&app->ref, 1);
}

static void
c_per_app_switch_register(void *arg, void *sw_arg)
{
    c_app_info_t *app = arg;
    c_switch_t   *sw = sw_arg;

    if (app->app_flags & C_APP_ALL_SW ||  
        g_hash_table_lookup(app->dpid_hlist, &sw->DPID))  {

       /* TODO - Double check locking */
        __c_per_switch_app_register(sw, NULL, app);
    }
}

static void
c_per_app_switch_unregister(void *arg, void *sw_arg)
{
    c_app_info_t *app = arg;
    c_switch_t   *sw = sw_arg;

    if(app->app_flags & C_APP_ALL_SW || 
       g_hash_table_lookup(app->dpid_hlist, &sw->DPID))  {
        __c_per_switch_app_unregister(sw, NULL, app);
    }
}

static void
c_app_event_q_ent_free(void *ent)
{
    free(ent);
}

static void
c_per_switch_app_replay(void *k, void *v UNUSED, void *arg)
{

    struct c_sw_replay_q_ent *q_ent;
    GSList **app_replay_q =(GSList **)arg;
    struct cbuf *b;
    struct ofp_switch_features *osf; 
    c_switch_t *sw = k;

    c_rd_lock(&sw->lock);
    b = of_prep_msg(sizeof(*osf) + (sw->n_ports * sizeof(struct ofp_phy_port)), 
                    OFPT_FEATURES_REPLY, 0);

    osf = (void *)(b->data);
    of_switch_detail_info(sw, osf);
    c_rd_unlock(&sw->lock);

    if (!(q_ent = calloc(1, sizeof(struct c_sw_replay_q_ent)))) {
        c_log_err("%s: q_ent alloc failed", FN);
        return;
    } 
    
    atomic_inc(&sw->ref, 1);
    q_ent->sw = sw;
    q_ent->b = b;
        
    *app_replay_q = g_slist_append(*app_replay_q, q_ent);
}


static void
c_switch_replay_all(ctrl_hdl_t *hdl, void *app_arg)
{                                  
    GSList *iterator;            
    struct c_sw_replay_q_ent *q_ent;
    GSList *app_replay_q = NULL;
    c_rd_lock(&hdl->lock);
    
    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)c_per_switch_app_replay, 
                             (void *)&app_replay_q);
    }       
                                
    c_rd_unlock(&hdl->lock);
                          
    for (iterator = app_replay_q; iterator; iterator = iterator->next) {
        q_ent = iterator->data;
        c_signal_app_event(q_ent->sw, q_ent->b, C_DP_REG, app_arg, NULL);
        of_switch_put(q_ent->sw);
    }

    if (app_replay_q) {
        g_slist_free_full(app_replay_q, c_app_event_q_ent_free);
    }
} 

int
mul_register_app(void *app_arg, char *app_name, uint32_t app_flags, 
                 uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list, 
                 void  (*ev_cb)(void *app_arg, void *pkt_arg))
{
    c_app_info_t *app = app_arg;
    bool         is_remote = app? true:false;
    uint64_t     *dpid;
    c_switch_t   *sw;
    uint32_t     n;
    bool         app_alloc = false;

    if (!app_name) {
        c_log_err("%s: App registration failed", FN);
        return -1;
    }

    if (!app) {
        app = calloc(1, sizeof(c_app_info_t));
        if (!app) {
            c_log_err("%s: App alloc failed", app_name);
            return -1;
        }
        app_alloc = true;
    }

    c_wr_lock(&ctrl_hdl.lock);
 
    if (__c_app_get(&ctrl_hdl, app_name)) {
        c_wr_unlock(&ctrl_hdl.lock);
        c_log_err("%s: App exists", app_name);
        if (app_alloc) free(app);
        return -1;
    }

    strncpy(app->app_name, app_name, C_MAX_APP_STRLEN);
    app->app_name[C_MAX_APP_STRLEN-1] = '\0';
    app->app_flags = app_flags;
    if (is_remote) app->app_flags |= C_APP_REMOTE;
    app->ev_mask = ev_mask;
    app->ev_cb = ev_cb?:c_app_event_blackhole;
    atomic_inc(&app->ref, 1);
        
    if (!(app->app_flags & C_APP_ALL_SW)) {

        if (!n_dpid) {
            c_wr_unlock(&ctrl_hdl.lock);
            c_log_err("%s:%s No dpids given", FN, app->app_name);
            if (app_alloc) free(app);
            return -1;
        }

        /* Registered switch list can be expanded on-demand */
        app->dpid_hlist = g_hash_table_new_full(g_int64_hash,
                                                g_int64_equal, 
                                                c_app_dpid_key_free, 
                                                NULL);
        app->n_dpid = n_dpid; 
        for (n = 0; n < n_dpid; n++) {
            dpid = calloc(1, sizeof(uint64_t)); // Optimize ??   
            assert(dpid);

            *dpid = dpid_list[n]; 
            g_hash_table_insert(app->dpid_hlist, dpid, dpid);

            if ((sw = __of_switch_get(&ctrl_hdl, *dpid))) {
                c_per_switch_app_register(sw, NULL, app);
                of_switch_put(sw);
            }
        }
    } else {
        __of_switch_traverse_all(&ctrl_hdl, c_per_switch_app_register,
                                 app);
    }

    ctrl_hdl.app_list = g_slist_append(ctrl_hdl.app_list, app);
    c_wr_unlock(&ctrl_hdl.lock);

    c_log_debug("%s app registered", app_name);

    return 0;
}

int
mul_unregister_app(char *app_name) 
{
    c_app_info_t *app;

    c_wr_lock(&ctrl_hdl.lock);
 
    if (!(app = __c_app_get(&ctrl_hdl, app_name))) {
        c_wr_unlock(&ctrl_hdl.lock);
        c_log_err("%s: Unknown App", app_name);
        return -1;
    }

    ctrl_hdl.app_list = g_slist_remove(ctrl_hdl.app_list, app);

    __of_switch_traverse_all(&ctrl_hdl, c_per_switch_app_unregister,
                             app);

    if (app->dpid_hlist) {
        g_hash_table_destroy(app->dpid_hlist);
    }
    app->ev_cb = c_app_event_blackhole;

    c_wr_unlock(&ctrl_hdl.lock);

    c_log_debug("%s app unregistered", app_name);
    c_app_put(app);

    return 0;
}

static void
c_switch_app_list_exp(c_switch_t *sw)
{
    g_slist_foreach(ctrl_hdl.app_list, 
                    (GFunc)c_per_app_switch_register, sw);
}

static void
c_switch_app_list_de_exp(c_switch_t *sw)
{
    if (sw->app_list) {
        g_slist_foreach(ctrl_hdl.app_list, 
                        (GFunc)c_per_app_switch_unregister, sw);
        g_slist_free(sw->app_list);
    }
}

static void
c_remote_app_event(void *app_arg, void *pkt_arg)
{
    c_app_info_t *app = app_arg;
    return c_thread_tx(&app->app_conn, pkt_arg, false);
}

static int 
c_remote_app_error(void *app_arg, struct cbuf *b,
                   uint16_t type, uint16_t code) 
{
    struct cbuf       *new_b;
    c_ofp_error_msg_t *cofp_em;
    void              *data;
    size_t            data_len;

    data_len = b->len > C_OFP_MAX_ERR_LEN? 
                    C_OFP_MAX_ERR_LEN : b->len;

    new_b = of_prep_msg(sizeof(*cofp_em) + data_len, C_OFPT_ERR_MSG, 0); 

    cofp_em = (void *)(new_b->data);
    cofp_em->type = htons(type);
    cofp_em->code = htonl(code);

    data = (void *)(cofp_em + 1);
    memcpy(data, b->data, data_len);

    c_remote_app_event(app_arg, new_b);

    return 0;
}

static void
c_remote_app_notify_success(void *app_arg)
{
    struct cbuf             *new_b;
    struct c_ofp_auxapp_cmd *cofp_aac;

    new_b = of_prep_msg(sizeof(*cofp_aac), C_OFPT_AUX_CMD, 0);

    cofp_aac = (void *)(new_b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_SUCCESS);

    c_remote_app_event(app_arg, new_b);
    return;
}


static void
c_app_event_blackhole(void *app_arg UNUSED, void *pkt_arg)
{
   free_cbuf(pkt_arg);
}

static inline void
c_app_event_finish(c_switch_t *sw, c_app_info_t *app, void *pkt_arg)
{
    struct c_sw_event_q_ent *ev_q_ent;

    if (app->app_flags & C_APP_REMOTE)  {
        app->ev_cb(app, pkt_arg);
    } else {
        ev_q_ent = malloc(sizeof(*ev_q_ent));
        if (unlikely(!ev_q_ent)) return;
        atomic_inc(&app->ref, 1);
        ev_q_ent->app = app;
        ev_q_ent->b = pkt_arg; 
        sw->app_eventq = g_slist_append(sw->app_eventq, ev_q_ent);       
    }
}

static void
c_app_event_send(void *arg, void *u_arg)
{
    struct c_sw_event_q_ent *ev_q_ent = arg;

    if (ev_q_ent->app->app_flags & C_APP_REMOTE) {
        c_log_err("%s: Unknown remote app event queued", FN);
        c_app_put(ev_q_ent->app);
        return;
    }

    ev_q_ent->app->ev_cb(u_arg, ev_q_ent->b);
    c_app_put(ev_q_ent->app);
    free_cbuf(ev_q_ent->b);
}

static inline void
c_switch_app_eventq_send(c_switch_t *sw)
{
    /* Strategically dont care about locking */
    if (sw->app_eventq) {
        g_slist_foreach(sw->app_eventq,
                        (GFunc)c_app_event_send, sw);
        g_slist_free_full(sw->app_eventq, c_app_event_q_ent_free);
        sw->app_eventq = NULL;
    }
}

static void
c_app_dpreg_event(c_switch_t *sw, void *b,
                  c_app_info_t *app, void *priv UNUSED)
{
    struct cbuf *new_b;
    c_ofp_switch_add_t *sw_add;

    new_b = cbuf_realloc_headroom(b, 0, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    sw_add = (void *)(new_b->data); 
    C_ADD_ALIAS_IN_SWADD(sw_add, sw->alias_id);

    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_dpunreg_event(c_switch_t *sw, void *buf, 
                    c_app_info_t *app, void *priv UNUSED)
{
    struct cbuf                 *b;
    struct c_ofp_switch_delete  *ofp_sd;  
    assert(!buf);

    b = of_prep_msg(sizeof(struct c_ofp_switch_delete), 
                    C_OFPT_SWITCH_DELETE, 0);

    ofp_sd = (void *)(b->data);
    ofp_sd->datapath_id = htonll(sw->DPID);
    ofp_sd->sw_alias = htonl(sw->alias_id);

    return c_app_event_finish(sw, app, b);
}

static void __fastpath
c_app_packet_in_event(c_switch_t *sw, void *buf,
                      c_app_info_t *app, void *priv)
{
    struct flow             *fl = priv;
    struct cbuf             *b = buf, *new_b;
    size_t                  room = sizeof(struct c_ofp_packet_in) - 
                                        sizeof(struct ofp_packet_in);
    struct c_ofp_packet_in  *cofp_pin; 
    struct ofp_header       *orig_ofp = (void *)(b->data);
    uint16_t                orig_len;

    assert(b);

    orig_len = ntohs(orig_ofp->length);

    new_b = cbuf_realloc_headroom(b, room, 0);

    cofp_pin = cbuf_push(new_b, room); 
    cofp_pin->header.xid  = orig_ofp->xid;
    cofp_pin->header.version = OFP_VERSION;
    cofp_pin->header.type = C_OFPT_PACKET_IN;
    cofp_pin->header.length = htons(room + orig_len);
    cofp_pin->datapath_id = htonll(sw->DPID); 
    cofp_pin->sw_alias = htonl(sw->alias_id);
    memcpy(&cofp_pin->fl, fl, sizeof(*fl));
    
    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_port_change_event(c_switch_t *sw, void *buf, 
                        c_app_info_t *app, void *priv)
{
    struct cbuf                   *b = buf, *new_b;
    size_t                        room = sizeof(struct c_ofp_port_status) - 
                                          sizeof(struct ofp_port_status);
    struct c_ofp_port_status      *cofp_psts; 
    struct ofp_header             *orig_ofp = (void *)(b->data);
    uint16_t                      orig_len;
    uint32_t                      orig_xid;
    struct c_port_cfg_state_mask  *chg_mask = priv;
    uint32_t                      config_mask = chg_mask ? 
                                                chg_mask->config_mask : 0;
    uint32_t                      state_mask = chg_mask ? 
                                                chg_mask->state_mask : 0;

    assert(b);

    orig_len = ntohs(orig_ofp->length);
    orig_xid = ntohl(orig_ofp->xid);

    new_b = cbuf_realloc_headroom(b, room, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofp_psts = cbuf_push(new_b, room); 
    cofp_psts->header.xid  = orig_xid;
    cofp_psts->header.version = OFP_VERSION;
    cofp_psts->header.type = C_OFPT_PORT_STATUS;
    cofp_psts->header.length = htons(room + orig_len);
    cofp_psts->datapath_id = htonll(sw->DPID);
    cofp_psts->sw_alias = htonl(sw->alias_id);
    cofp_psts->config_mask = htonl(config_mask); 
    cofp_psts->state_mask = htonl(state_mask); 
    
    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_flow_removed_event(c_switch_t *sw, void *buf, 
                         c_app_info_t *app, void *priv)
{
    struct cbuf                   *b = buf, *new_b;
    struct of_flow_mod_params     *fl_parms = priv;
    struct ofp_flow_removed       *ofm;
    struct c_ofp_flow_removed     *cofm;
    size_t cp_len = sizeof(*ofm) - offsetof(struct ofp_flow_removed, reason); 

    assert(b && priv);

    ofm = (void *)(b->data);

    new_b = of_prep_msg(sizeof(*cofm), C_OFPT_FLOW_REMOVED, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofm = (void *)(new_b->data);
    cofm->datapath_id = htonll(sw->DPID); 
    memcpy(&cofm->flow, &fl_parms->flow, sizeof(struct flow));
    cofm->wildcards = fl_parms->wildcards;
    cofm->cookie = ofm->cookie;
    cofm->priority = ofm->priority;
    memcpy(&cofm->reason, &ofm->reason, cp_len); 
    
    return c_app_event_finish(sw, app, new_b);
}

static void
c_app_flow_mod_failed_event(c_switch_t *sw, void *buf,
                            c_app_info_t *app, void *priv)
{
    struct cbuf                   *b = buf, *new_b;
    struct of_flow_mod_params     *fl_parms = priv;
    struct ofp_error_msg          *ofp_err;
    struct ofp_flow_mod            *ofp_fm;
    c_ofp_error_msg_t             *cofp_em;
    c_ofp_flow_mod_t              *cofp_fm;

    assert(b && priv);

    ofp_err = (void *)(b->data);
    ofp_fm = (void *)(ofp_err->data);

    new_b = of_prep_msg(sizeof(*cofp_em) + sizeof(struct c_ofp_flow_mod),
                        C_OFPT_ERR_MSG, 0);
    if (!new_b) {
        c_log_err("%s: Failed to alloc buf", FN);
        return;
    }

    cofp_em = (void *)(new_b->data);
    cofp_em->type = ofp_err->type;
    cofp_em->code = ofp_err->code;

    cofp_fm = (void *)(cofp_em->data);
    cofp_fm->header.version = OFP_VERSION;
    cofp_fm->header.type = C_OFPT_FLOW_MOD;
    cofp_fm->header.length = htons(sizeof(*cofp_fm));

    cofp_fm->datapath_id = htonll(sw->DPID);
    cofp_fm->sw_alias = htonl(sw->alias_id);
    memcpy(&cofp_fm->flow, &fl_parms->flow, sizeof(struct flow));
    cofp_fm->wildcards = fl_parms->wildcards;
    cofp_fm->priority = htons(fl_parms->prio);
    cofp_fm->command = ofp_fm->command;

    return c_app_event_finish(sw, app, new_b);
}

void __fastpath
c_signal_app_event(c_switch_t *sw, void *b, c_app_event_t event, 
                   void *app_arg, void *priv)
{
    c_app_info_t *app = app_arg;
    GSList *iterator = NULL;
    struct c_app_handler_op *app_op;

    app_op = &event[c_app_handler_ops];
    prefetch(app_op);

    if (unlikely(event >= C_APP_OPS_SZ)) {
        c_log_err("%s: unhandled event", FN);
        return;
    }
    
    c_sw_hier_rdlock(sw);

    if (app_op->pre_proc) app_op->pre_proc(sw);
    if (app) {
        C_PROCESS_APP_EVENT_LOOP(sw, b, event, app_op, app); 
    } else {    
        C_PROCESS_ALL_APP_EVENT_LOOP(sw, b, event, app_op); 
    }
    if (app_op->post_proc) app_op->post_proc(sw);

    c_sw_hier_unlock(sw);

    c_switch_app_eventq_send(sw); 

    return;
}

static int  __fastpath
c_app_flow_mod_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t *sw;
    c_app_info_t *app = app_arg;
    struct c_ofp_flow_mod *cofp_fm = data;
    size_t action_len = ntohs(cofp_fm->header.length) - sizeof(*cofp_fm);
    struct of_flow_mod_params fl_parms;
    int ret = -1;

    assert(app);

    if (ntohs(cofp_fm->header.length) < sizeof(c_ofp_flow_mod_t)) {
        c_log_err("%s:Cmd(%u) Size err %u of %lu", FN, C_OFPT_FLOW_MOD,
                   ntohs(cofp_fm->header.length),
                   (unsigned long)sizeof(c_ofp_flow_mod_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);  
    }

    memset(&fl_parms, 0, sizeof(fl_parms));

    if (cofp_fm->flags & C_FL_ENT_SWALIAS) {
        sw = of_switch_alias_get(&ctrl_hdl, (int)(ntohl(cofp_fm->sw_alias)));
    } else {
        sw = of_switch_get(&ctrl_hdl, ntohll(cofp_fm->DPID));
    }

    if (!sw) {
        c_log_err("%s: Invalid switch-dpid(0x%llx)", FN,
                  (unsigned long long)ntohll(cofp_fm->DPID));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    if (app->app_flags & C_APP_AUX_REMOTE) {
        app = c_app_get(&ctrl_hdl, C_VTY_NAME);
        if (!app) {
            /* This condition should never occur */
            c_log_err("%s: %s app not found", FN, C_VTY_NAME);
            app = app_arg;
        }
    }

    of_flow_correction(&cofp_fm->flow, &cofp_fm->wildcards);

    if (of_validate_actions(cofp_fm->actions, action_len)) {
        c_log_err("%s: Invalid action list", FN);
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_ACTION, OFPBAC_BAD_GENERIC); 
    }

    if (cofp_fm->flags & C_FL_ENT_NOCACHE && 
        cofp_fm->flags & (C_FL_ENT_LOCAL | C_FL_ENT_CLONE)) {
        c_log_err("%s: Invalid flags", FN);
        RETURN_APP_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, 
                       OFPFMFC_BAD_FLAG); 
    }

    fl_parms.app_owner = app;
    fl_parms.flow = &cofp_fm->flow;
    fl_parms.action_len = action_len;
    fl_parms.wildcards = cofp_fm->wildcards;
    fl_parms.buffer_id = ntohl(cofp_fm->buffer_id);
    fl_parms.flags = cofp_fm->flags;
    fl_parms.prio = ntohs(cofp_fm->priority);
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;
    fl_parms.itimeo = ntohs(cofp_fm->itimeo); 
    fl_parms.htimeo = ntohs(cofp_fm->htimeo); 
    if (action_len) {
        fl_parms.actions = malloc(action_len);
        assert(fl_parms.actions);
    }

    memcpy(fl_parms.actions, cofp_fm->actions, action_len);

    if (cofp_fm->command == C_OFPC_ADD) {
        ret = cofp_fm->flags & C_FL_ENT_NOCACHE ? 
            of_send_flow_add_nocache(sw, fl_parms.flow, fl_parms.buffer_id,
                                     fl_parms.actions, fl_parms.action_len,
                                     fl_parms.itimeo, fl_parms.htimeo, 
                                     fl_parms.wildcards, fl_parms.prio) : 
            of_flow_add(sw, &fl_parms);
    } else /* if (cofp_fm->command == C_OFPC_DEL)*/ { 
        ret = cofp_fm->flags & C_FL_ENT_NOCACHE ? 
            of_send_flow_del_nocache(sw, fl_parms.flow, fl_parms.wildcards,
                                     ntohs(cofp_fm->oport), false) :  
            of_flow_del(sw, &fl_parms);
    } 

    c_thread_sg_tx_sync(&sw->conn);

    of_switch_put(sw);
    if (app != app_arg) {
        c_app_put(app);
    } 

    RETURN_APP_ERR(app_arg, b, ret, OFPET_FLOW_MOD_FAILED, OFPFMFC_GENERIC); 
}


int __fastpath
mul_app_send_flow_add(void *app_name, void *sw_arg, uint64_t dpid, struct flow *fl,
                      uint32_t buffer_id, void *actions,  size_t action_len,
                      uint16_t itimeo, uint16_t htimeo, uint32_t wildcards,
                      uint16_t prio, uint8_t flags)  
{
    c_switch_t *sw = sw_arg;
    struct of_flow_mod_params fl_parms;
    c_app_info_t *app;
    int ret = 0;

    if (sw == NULL) {
        if (!( sw = of_switch_get(&ctrl_hdl, dpid))) {
            return -EINVAL;
        }
    } else {
        atomic_inc(&sw->ref, 1);
    }

    /* All internal fns expected network byte order */
    wildcards = htonl(wildcards);

    if (flags & C_FL_ENT_NOCACHE) {
        ret = of_send_flow_add_nocache(sw, fl, buffer_id, actions, action_len,
                                       itimeo, htimeo, wildcards, prio);
        of_switch_put(sw);
        return ret;
    }

    app = c_app_get(&ctrl_hdl, (char *)app_name);
    if (!app) {
        of_switch_put(sw);
        return -EINVAL;
    }

    memset(&fl_parms, 0, sizeof(fl_parms));
    fl_parms.app_owner = app;
    fl_parms.flow = fl;
    fl_parms.wildcards = wildcards;
    fl_parms.buffer_id = buffer_id;
    fl_parms.flags = flags;
    fl_parms.prio = prio;
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;
    fl_parms.itimeo = itimeo;
    fl_parms.htimeo = htimeo;
    fl_parms.actions = actions;
    fl_parms.action_len = action_len;

    ret = of_flow_add(sw, &fl_parms);

    c_app_put(app);
    of_switch_put(sw);

    return ret;
}

int __fastpath
mul_app_send_flow_del(void *app_name, void *sw_arg, uint64_t dpid, struct flow *fl,
                      uint32_t wildcards, uint16_t oport, uint16_t prio, uint8_t flags)
{
    c_switch_t *sw = sw_arg;
    struct of_flow_mod_params fl_parms;
    c_app_info_t *app;
    int ret = 0;

    if (sw == NULL) {
        if (!( sw = of_switch_get(&ctrl_hdl, dpid))) {
            return -EINVAL;
        }
    } else {
        atomic_inc(&sw->ref, 1);
    }

    if (flags & C_FL_ENT_NOCACHE) {
        ret = of_send_flow_del_nocache(sw, fl, wildcards, oport, false);
        of_switch_put(sw);
        return ret;    
    }

    app = c_app_get(&ctrl_hdl, (char *)app_name);
    if (!app) {
        of_switch_put(sw);
        return -EINVAL;
    }

    memset(&fl_parms, 0, sizeof(fl_parms));
    fl_parms.app_owner = app;
    fl_parms.flow = fl;
    fl_parms.wildcards = htonl(wildcards);
    fl_parms.flags = flags;
    fl_parms.prio = htons(prio);;
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;

    ret = of_flow_del(sw, &fl_parms);

    c_app_put(app);
    of_switch_put(sw);

    return ret;
}

static int  __fastpath
c_app_packet_out_command(void *app_arg, struct cbuf *b, void *data)
{
    c_switch_t  *sw;
    struct of_pkt_out_params parms;
    struct c_ofp_packet_out *cofp_po = data;
    uint16_t pkt_len = ntohs(cofp_po->header.length);
    int ret = -1;

    if (unlikely(pkt_len < sizeof(c_ofp_packet_out_t))) {
        c_log_err("%s:Cmd(%u) Size err %hu of %lu", FN, C_OFPT_PACKET_OUT,
                  pkt_len, (unsigned long)sizeof(c_ofp_packet_out_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);  
    }

    sw = of_switch_get(&ctrl_hdl, ntohll(cofp_po->DPID));
    if (unlikely(!sw)) {
        //c_log_err("%s: Invalid switch-dpid(0x%llx)", FN,
        //          (unsigned long long)ntohll(cofp_po->DPID));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);  
    }

    parms.action_len = ntohs(cofp_po->actions_len);
    if (unlikely(pkt_len < (sizeof(*cofp_po)+parms.action_len))) {
        c_log_err("%s:Cmd(%u) Data sz err (%hu:%lu)", FN,
                  C_OFPT_PACKET_OUT, pkt_len,
                  (unsigned long)sizeof(*cofp_po) + parms.action_len);
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_ACTION, OFPBAC_BAD_LEN);  
    }

    parms.buffer_id = ntohl(cofp_po->buffer_id);
    parms.in_port = ntohs(cofp_po->in_port);
    parms.action_list = cofp_po->actions;

    parms.data_len = pkt_len - (sizeof(*cofp_po)+parms.action_len);
    parms.data = (void *)((uint8_t *)(cofp_po + 1) +
                                      parms.action_len);

    of_send_pkt_out(sw, &parms);
    c_thread_sg_tx_sync(&sw->conn);

    of_switch_put(sw);

    return 0;
}

void __fastpath
mul_app_send_pkt_out(void *sw_arg, uint64_t dpid, void *parms_arg)
{
    c_switch_t *sw = sw_arg;
    struct of_pkt_out_params *parms = parms_arg;
    
    if (sw == NULL) {
        if (!(sw = of_switch_get(&ctrl_hdl, dpid))) {
            return;
        }
    } else {
        atomic_inc(&sw->ref, 1);
    }

    of_send_pkt_out(sw, parms);

    of_switch_put(sw);

    return;

}

static int 
c_app_register_app_command(void *app_arg, struct cbuf *b, void *data)
{
    int  i;
    struct c_ofp_register_app *cofp_ra = data;
    c_app_info_t *app = app_arg;
    int ret = -1;

    if (ntohs(cofp_ra->header.length) < sizeof(c_ofp_register_app_t)) {
        c_log_err("%s:Cmd(%u) Size err %u of %lu", FN, C_OFPT_REG_APP,
                   ntohs(cofp_ra->header.length),
                   (unsigned long)sizeof(c_ofp_register_app_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    } 

    cofp_ra->app_flags = ntohl(cofp_ra->app_flags);
    cofp_ra->ev_mask = ntohl(cofp_ra->ev_mask);
    cofp_ra->dpid = ntohl(cofp_ra->dpid);
    for (i = 0; i < cofp_ra->dpid; i++) {
        cofp_ra->dpid_list[i] = ntohll(cofp_ra->dpid_list[i]);
    } 

    ret = mul_register_app(app, cofp_ra->app_name, cofp_ra->app_flags,
                           cofp_ra->ev_mask, cofp_ra->dpid,
                           cofp_ra->dpid_list, c_remote_app_event);
    if (ret) {
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, 
                       OFPBRC_BAD_APP_REG);
    }

    c_switch_replay_all(&ctrl_hdl, app);
    return 0;
}

static int 
c_app_unregister_app_command(void *app_arg, struct cbuf *b, void *data)
{
    struct c_ofp_unregister_app *cofp_ura = data;
    int ret = -1;

    if (ntohs(cofp_ura->header.length) < sizeof(c_ofp_unregister_app_t)) { 
        c_log_err("%s:Cmd(%u) Size err %u of %lu", 
                  FN, C_OFPT_UNREG_APP, ntohs(cofp_ura->header.length),
                  (unsigned long)sizeof(c_ofp_unregister_app_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }   

    ret = mul_unregister_app(cofp_ura->app_name);
    RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, 
                   OFPBRC_BAD_APP_UREG);
}

static int
c_app_set_fpops_command(void *app_arg, struct cbuf *b, void *data)
{
    struct c_ofp_set_fp_ops *cofp_sfp = data;
    int ret = -1;
    c_switch_t *sw;

    if (ntohs(cofp_sfp->header.length) < sizeof(c_ofp_set_fp_ops_t)) {
        c_log_err("%s:Cmd(%u) Size err %u of %lu",
                  FN, C_OFPT_SET_FPOPS, ntohs(cofp_sfp->header.length),
                  (unsigned long)sizeof(c_ofp_set_fp_ops_t));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sw = of_switch_get(&ctrl_hdl, ntohll(cofp_sfp->DPID));
    if (unlikely(!sw)) {
        c_log_err("%s: Invalid switch-dpid(0x%llx)", FN,
                  (unsigned long long)ntohll(cofp_sfp->DPID));
        RETURN_APP_ERR(app_arg, b, ret, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
    }

    switch (ntohl(cofp_sfp->fp_type)) {
    case C_FP_TYPE_DFL:
        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw);
        }
        sw->fp_ops.fp_db_dtor = NULL;
        sw->fp_ops.fp_db_ctor = NULL;

        sw->fp_ops.fp_fwd = of_dfl_fwd;
        sw->fp_ops.fp_port_status = of_dfl_port_status;

        c_log_err("Switch <%llx> fp set to default", sw->DPID);
        break;
    case C_FP_TYPE_L2:
        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw);
        }

        sw->fp_ops.fp_db_dtor = c_l2fdb_destroy;
        sw->fp_ops.fp_db_ctor = c_l2fdb_init;

        sw->fp_ops.fp_db_ctor(sw);

        sw->fp_ops.fp_fwd = c_l2_lrn_fwd;
        sw->fp_ops.fp_port_status = c_l2_port_status;

        c_log_err("Switch <%llx> fp set to L2", sw->DPID);
        break;
    default:
        break;
    }

    of_switch_put(sw);

    return 0;
}

static void
c_app_send_per_flow_info(void *arg, c_fl_entry_t *ent)
{
    struct c_buf_iter_arg *iter_arg = arg;
    c_ofp_flow_mod_t            *cofp_fm;
    void                        *act;
    struct cbuf                 *b;
    size_t                      tot_len = 0;

    c_rd_lock(&ent->FL_LOCK);
    if (iter_arg->wr_ptr &&  /* wr_ptr field is overridden */
        !(ent->FL_FLAGS & C_FL_ENT_STATIC)) {
        c_rd_unlock(&ent->FL_LOCK);
        return;
    }

    tot_len = sizeof(*cofp_fm) + ent->action_len;

    b = of_prep_msg(tot_len, C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->sw_alias = htonl((uint32_t)ent->sw->alias_id);
    cofp_fm->datapath_id = htonll(ent->sw->DPID);
    cofp_fm->command = C_OFPC_ADD;
    cofp_fm->flags = ent->FL_FLAGS;
    memcpy(&cofp_fm->flow, &ent->fl, sizeof(struct flow));
    cofp_fm->wildcards = ent->FL_WILDCARDS;
    cofp_fm->priority = htons(ent->FL_PRIO);
    cofp_fm->itimeo = htons(ent->FL_ITIMEO);
    cofp_fm->htimeo = htons(ent->FL_HTIMEO);
    cofp_fm->buffer_id = 0xffffffff;
    cofp_fm->oport = OFPP_NONE;

    act = (void *)(cofp_fm+1);
    memcpy(act, ent->actions, ent->action_len);

    c_rd_unlock(&ent->FL_LOCK);

    c_remote_app_event(iter_arg->data, b);
}


static void
c_app_per_switch_flow_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;

    of_flow_traverse_tbl_all(sw, iter_arg, c_app_send_per_flow_info);
}

static void 
c_app_send_flow_info(void *app_arg, struct cbuf *b, bool dump_all)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL };
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    c_switch_t *sw = NULL;

    if (ntohs(cofp_aac->header.length) <
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%u) of (%u)", FN,
                  ntohs(cofp_aac->header.length),
                  sizeof(*cofp_aac) + sizeof(*cofp_rda));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        return;
    }

    iter_arg.data = app_arg;
    if (!dump_all) {
        iter_arg.wr_ptr = app_arg;
    }

    cofp_rda = (void *)(cofp_aac->data);
    sw = of_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, ntohll(cofp_rda->datapath_id));
        if (!cofp_rda->datapath_id) {
            of_switch_traverse_all(&ctrl_hdl, c_app_per_switch_flow_info,
                                   &iter_arg);
            goto done;
        }
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
        return;
    }

    of_flow_traverse_tbl_all(sw, &iter_arg, c_app_send_per_flow_info);

    of_switch_put(sw);

done:
    c_remote_app_notify_success(app_arg);

    return;
}

static void
c_app_per_switch_brief_info(void *k, void *v UNUSED, void *arg)
{   
    c_switch_t   *sw = k;
    struct c_buf_iter_arg *iter_arg = arg;
    struct c_ofp_switch_brief *cofp_sb = (void *)(iter_arg->wr_ptr);

    c_rd_lock(&sw->lock);
    of_switch_brief_info(sw, cofp_sb);

    c_rd_unlock(&sw->lock);
    iter_arg->wr_ptr += sizeof(*cofp_sb);
}
   
static void 
c_app_send_brief_switch_info(void *app_arg, struct cbuf *b)
{
    struct c_buf_iter_arg iter_arg = { NULL, NULL };
    size_t n_switches = 0;
    struct c_ofp_auxapp_cmd *cofp_aac;

    c_rd_lock(&ctrl_hdl.lock);

    if (!ctrl_hdl.sw_hash_tbl ||
        !(n_switches = g_hash_table_size(ctrl_hdl.sw_hash_tbl))) {
        c_rd_unlock(&ctrl_hdl.lock);
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_NO_INFO);
        return;
    }

    b = of_prep_msg(sizeof(c_ofp_auxapp_cmd_t) +
                    (n_switches * sizeof(c_ofp_switch_brief_t)),
                    C_OFPT_AUX_CMD, 0); 
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = ntohl(C_AUX_CMD_MUL_GET_SWITCHES_REPLY);
    iter_arg.wr_ptr = cofp_aac->data;
    iter_arg.data = (void *)(b->data);

    __of_switch_traverse_all(&ctrl_hdl, c_app_per_switch_brief_info,
                             &iter_arg);

    c_rd_unlock(&ctrl_hdl.lock);

    c_remote_app_event(app_arg, b);
}

static void
c_app_send_detail_switch_info(void *app_arg, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);
    struct c_ofp_req_dpid_attr *cofp_rda;
    struct ofp_switch_features *osf;
    c_switch_t *sw;

    if (ntohs(cofp_aac->header.length) < 
        sizeof(*cofp_aac) + sizeof(*cofp_rda)) {
        c_log_err("%s: Size err (%u) of (%u)", FN, ntohs(cofp_aac->header.length), 
                  sizeof(*cofp_aac) + sizeof(*cofp_rda));
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    cofp_rda = (void *)(cofp_aac->data);
    sw = of_switch_get(&ctrl_hdl, ntohll(cofp_rda->datapath_id));
    if (!sw) {
        c_remote_app_error(app_arg, b, OFPET_BAD_REQUEST, OFPBRC_BAD_NO_INFO);
        return;
    }

    c_rd_lock(&sw->lock);
    b = of_prep_msg(sizeof(*osf) + (sw->n_ports * sizeof(struct ofp_phy_port)),
                    OFPT_FEATURES_REPLY, 0);

    osf = (void *)(b->data);
    of_switch_detail_info(sw, osf);
    c_rd_unlock(&sw->lock);
    of_switch_put(sw);

    c_remote_app_event(app_arg, b);
}

static int
c_app_aux_request_handler(void *app_arg, struct cbuf *b, void *data)
{
    struct c_ofp_auxapp_cmd *cofp_aac = data;

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%u) of (%u)", FN, ntohs(cofp_aac->header.length), 
                   sizeof(struct c_ofp_auxapp_cmd));
        RETURN_APP_ERR(app_arg, b, -1, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_MUL_GET_SWITCHES:
        c_app_send_brief_switch_info(app_arg, b);
        break;
    case C_AUX_CMD_MUL_GET_SWITCH_DETAIL:
        c_app_send_detail_switch_info(app_arg, b);
        break;
    case C_AUX_CMD_MUL_GET_APP_FLOW:
        c_app_send_flow_info(app_arg, b, false); 
        break;
    case C_AUX_CMD_MUL_GET_ALL_FLOWS:
        c_app_send_flow_info(app_arg, b, true); 
    default:
        RETURN_APP_ERR(app_arg, b, -1, OFPET_BAD_REQUEST, OFPBRC_BAD_GENERIC);
        break;
    }

    return 0;
} 

void
c_aux_app_init(void *app_arg)
{
    c_app_info_t *app = app_arg;

    app->app_flags = C_APP_AUX_REMOTE;
    app->ev_cb = c_remote_app_event;
}

int  __fastpath
__mul_app_command_handler(void *app_arg, struct cbuf *b)
{
    struct ofp_header *hdr = (void *)(b->data);

    switch (hdr->type) {
    case C_OFPT_FLOW_MOD:
        return c_app_flow_mod_command(app_arg, b, hdr);
    case C_OFPT_PACKET_OUT:
        return c_app_packet_out_command(app_arg, b, hdr);
    case C_OFPT_REG_APP:
        return c_app_register_app_command(app_arg, b, hdr);
    case C_OFPT_UNREG_APP:
        return c_app_unregister_app_command(app_arg, b, hdr);
    case C_OFPT_SET_FPOPS:
        return c_app_set_fpops_command(app_arg, b, hdr);
    case C_OFPT_AUX_CMD:
        return c_app_aux_request_handler(app_arg, b, hdr);
    }

    return -1;
}

int __fastpath
mul_app_command_handler(void *app_name, void *buf)
{
    c_app_info_t *app = NULL;
    struct cbuf *b = buf;
    struct ofp_header *hdr = (void *)(b->data);
    int ret;

    assert(b && app_name);

    c_rd_lock(&ctrl_hdl.lock);

    if (hdr->type != C_OFPT_REG_APP &&
        !(app = __c_app_get(&ctrl_hdl, (char *)app_name))) {
        c_rd_unlock(&ctrl_hdl.lock);
        c_log_err("%s: Unknown App", (char *)app_name);
        return -1;
    }

    c_rd_unlock(&ctrl_hdl.lock);

    ret = __mul_app_command_handler(app, b);

    c_app_put(app);

    free_cbuf(b);
    return ret;
}

static void
mod_initcalls(struct c_app_ctx *app_ctx)
{
    initcall_t *mod_init;

    mod_init = &__start_modinit_sec;
    do {
        (*mod_init)(app_ctx->cmn_ctx.base);
        mod_init++;
    } while (mod_init < &__stop_modinit_sec);
}

int 
c_builtin_app_start(void *arg)
{   
    struct c_app_ctx    *app_ctx = arg;

    if (app_ctx->thread_idx == 0) {
        mod_initcalls(app_ctx);
    }

    return 0;
}

/* Housekeep Timer for app monitoring */
static void UNUSED
c_app_main_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                 void *arg)
{
    struct c_app_ctx *app_ctx  = arg;
    struct timeval   tv        = { 1 , 0 };
   
    evtimer_add(app_ctx->app_main_timer_event, &tv);
}

static void
c_app_vty(void *arg UNUSED)
{
    /* Nothing to do */ 
    return;
}

static void
c_app_main(void *arg UNUSED)
{
    /* Nothing to do */
    return;
}

module_init(c_app_main);
module_vty_init(c_app_vty);
