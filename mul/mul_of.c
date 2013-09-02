/*
 *  mul_of.c: MUL openflow abstractions 
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

static void of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, 
                             uint32_t buffer_id, bool ha_sync);
static void of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent,
                             uint16_t oport, bool strict);
static void of_send_flow_del_strict(c_switch_t *sw, c_fl_entry_t *ent,
                                    uint16_t oport);
static c_fl_entry_t *__of_flow_get_exm(c_switch_t *sw, struct flow *fl);
static void of_flow_rule_free(void *arg, void *u_arg);

static inline int
of_flow_mod_validate_parms(struct of_flow_mod_params *fl_parms)
{
    if (fl_parms->tbl_idx > C_MAX_RULE_FLOW_TBLS || 
        (!fl_parms->app_owner) ||
        (fl_parms->flags & C_FL_ENT_CLONE && fl_parms->flags & C_FL_ENT_LOCAL) ||
        (fl_parms->flags & C_FL_ENT_NOCACHE)) { 
        c_log_err("%s: Invalid flow mod flags", FN);
        return -1;
    }

    return 0;
}

static inline int
of_exm_flow_mod_validate_parms(struct of_flow_mod_params *fl_parms)
{
    if (fl_parms->flags & C_FL_ENT_CLONE || fl_parms->flags & C_FL_ENT_NOCACHE || 
        !fl_parms->app_owner) { 
        c_log_err("%s: Invalid flow mod flags", FN);
        return -1;
    }

    return 0;
}

static inline void
c_switch_tx(c_switch_t *sw, struct cbuf *b, bool only_q)
{
    if (c_switch_is_virtual(sw)) {
        free_cbuf(b);
        return;
    } 

    c_thread_tx(&sw->conn, b, only_q);
}

static inline void
c_switch_chain_tx(c_switch_t *sw, struct cbuf **b, size_t nbufs)
{
    int n = 0;
    if (c_switch_is_virtual(sw)) {
        for (n = 0; n < nbufs; n++) {
            free_cbuf(b[n]);
        }
        return;
    } 

    c_thread_chain_tx(&sw->conn, b, nbufs);
}

static void
of_flow_app_ref_free(void *arg UNUSED)
{
    /* Nothing to do */
    return;
}


char *
of_dump_flow_all(struct flow *fl)   
{   
#define FL_PBUF_SZ 2048 
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow tuple:\r\n");
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                   "%-10s:%02x:%02x:%02x:%02x:%02x:%02x\r\n" 
                   "%-10s:%02x:%02x:%02x:%02x:%02x:%02x\r\n",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5],
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%-10s:0x%04x\r\n%-10s:0x%04x\r\n%-10s:0x%04x\r\n",
                     "eth-type", ntohs(fl->dl_type), 
                     "vlan-id",  ntohs(fl->dl_vlan), 
                     "vlan-pcp", ntohs(fl->dl_vlan_pcp));
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%-10s:0x%08x\r\n%-10s:0x%08x\r\n%-10s:0x%02x\r\n%-10s:0x%x\r\n",
                     "dest-ip", ntohl(fl->nw_dst), 
                     "src-ip", ntohl(fl->nw_src), 
                     "ip-proto", fl->nw_proto, 
                     "ip-tos", fl->nw_tos);  
    assert(len < FL_PBUF_SZ-1);
    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%-10s:0x%04x\r\n%-10s:0x%04x\r\n%-10s:0x%x\r\n", 
                    "src-port", ntohs(fl->tp_src), 
                    "dst-port", ntohs(fl->tp_dst), 
                    "in-port", ntohs(fl->in_port));

    return pbuf;
}

char *
of_dump_fl_app(c_fl_entry_t *ent)  
{
    c_app_info_t *app;
    GSList *iterator; 
#define FL_APP_BUF_SZ 1024
    char *pbuf = calloc(1, FL_APP_BUF_SZ);
    int len = 0;
    
    len += snprintf(pbuf+len, FL_APP_BUF_SZ-len-1, "Owner: ");
    assert(len < FL_APP_BUF_SZ-1);

    c_rd_lock(&ent->FL_LOCK);
    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        len += snprintf(pbuf+len, FL_APP_BUF_SZ-len-1, "%s ", app->app_name);
        assert(len < FL_APP_BUF_SZ-1);
    }
    c_rd_unlock(&ent->FL_LOCK);

    return pbuf;
}

bool
of_switch_port_valid(c_switch_t *sw, uint16_t port, uint32_t wc)
{
    if (!(ntohl(wc) & OFPFW_IN_PORT)) {
        return __c_switch_port_valid(sw, port);
    }

    return true;
}

int
of_validate_actions_strict(c_switch_t *sw, void *actions, size_t action_len)
{
    size_t                   parsed_len = 0;
    uint16_t                 act_type;
    struct ofp_action_header *hdr;

    while (action_len) {
        hdr =  (struct ofp_action_header *)actions;
        act_type = ntohs(hdr->type);
        switch (act_type) {
        case OFPAT_OUTPUT:
            {
                struct ofp_action_output *op_act = (void *)hdr;
                if(!ntohs(op_act->port) ||
                   !__c_switch_port_valid(sw, ntohs(op_act->port))) {
                    c_log_err("%s: port 0x%x", FN, ntohs(op_act->port));
                    return -1;
                }
                parsed_len = sizeof(*op_act);
                break;
            }
        case OFPAT_SET_VLAN_VID:
            {
                struct ofp_action_vlan_vid *vid_act = (void *)hdr;    
                parsed_len = sizeof(*vid_act);
                break;
                                 
            } 
        case OFPAT_SET_DL_DST:
        case OFPAT_SET_DL_SRC:
            {
                struct ofp_action_dl_addr *mac_act = (void *)hdr;
                parsed_len = sizeof(*mac_act);
                break;
            }
        case OFPAT_SET_VLAN_PCP:
            {
                struct ofp_action_vlan_pcp *vpcp_act = (void *)hdr;
                parsed_len = sizeof(*vpcp_act);
                break;

            }
        case OFPAT_STRIP_VLAN:
            {
                struct ofp_action_header *strip_vlan_act UNUSED = (void *)hdr;
                parsed_len = sizeof(*strip_vlan_act);
                break;
            }
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                parsed_len = sizeof(*nw_addr_act);
                break;
            }
        default:
            {
                c_log_err("%s:unhandled action %u", FN, act_type);
                return -1;
            }
        }

        action_len -= parsed_len;
        actions = ((uint8_t *)actions + parsed_len);
    }

    return 0;
}

static unsigned int
of_switch_hash_key(const void *p)
{
    c_switch_t *sw = (c_switch_t *) p;

    return (unsigned int)(sw->DPID);
}

static int 
of_switch_hash_cmp(const void *p1, const void *p2)
{
    const c_switch_t *sw1 = (c_switch_t *) p1;
    const c_switch_t *sw2 = (c_switch_t *) p2;

    if (sw1->DPID == sw2->DPID) {
        return 1; /* TRUE */
    } else {
        return 0; /* FALSE */
    }
}

void
of_switch_add(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl; 
    c_switch_t *old_sw;

    c_wr_lock(&ctrl->lock);
    if (!ctrl->sw_hash_tbl) {
        ctrl->sw_hash_tbl = g_hash_table_new(of_switch_hash_key, 
                                             of_switch_hash_cmp);
    } else {
        if ((old_sw =__of_switch_get(ctrl, sw->DPID))) {
            c_log_err("%s: switch 0x%llx exists", FN, sw->DPID);
            of_switch_put(old_sw);
            c_wr_unlock(&ctrl->lock);
            return;
        }
    }

    g_hash_table_add(ctrl->sw_hash_tbl, sw);
    if ((sw->alias_id = ipool_get(ctrl->sw_ipool, sw)) < 0) {
        /* Throw a log and continue as we still can continue */
        c_log_err("%s: Cant get alias for switch 0x%llx\n", FN, sw->DPID);
    }

    c_wr_unlock(&ctrl->lock);

}

static int 
of_switch_clone_on_conn(c_switch_t *sw, c_switch_t *old_sw)
{
    if (old_sw == sw) {
        return SW_CLONE_USE;
    }

    if (!(old_sw->switch_state & SW_DEAD)) {
        return SW_CLONE_DENY;
    }

    return SW_CLONE_OLD;
}

void
of_switch_del(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl;

    c_conn_destroy(&sw->conn);

    c_wr_lock(&ctrl->lock);
    if (ctrl->sw_hash_tbl) {
       g_hash_table_remove(ctrl->sw_hash_tbl, sw);
    }

    if (ctrl->sw_ipool) {
        if (sw->switch_state & SW_REGISTERED)
            ipool_put(ctrl->sw_ipool, sw->alias_id);
    }
    c_wr_unlock(&ctrl->lock);

    if (sw->switch_state & SW_REGISTERED)
        c_signal_app_event(sw, NULL, C_DP_UNREG, NULL, NULL);

    sw->switch_state |= SW_DEAD;
}

void
of_switch_mark_sticky_del(c_switch_t *sw)
{
    sw->last_refresh_time = time(NULL);
    sw->switch_state |= SW_DEAD;
}

void *
of_switch_alloc(void *ctx)
{
    c_switch_t *new_switch;

    new_switch = calloc(1, sizeof(c_switch_t));
    assert(new_switch);

    new_switch->switch_state = SW_INIT;
    new_switch->ctx = ctx;
    new_switch->last_refresh_time = time(NULL);
    c_rw_lock_init(&new_switch->lock);
    c_rw_lock_init(&new_switch->conn.conn_lock);
    cbuf_list_head_init(&new_switch->conn.tx_q);

    return new_switch;
}

c_switch_t *
of_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid)
{
    c_switch_t       key, *sw = NULL; 
    unsigned int     found;

    if (!ctrl->sw_hash_tbl) {
        return NULL;
    }

    key.datapath_id = dpid;

    c_rd_lock(&ctrl->lock);

    found = g_hash_table_lookup_extended(ctrl->sw_hash_tbl, &key, 
                                         NULL, (gpointer*)&sw);
    if (found) {
        atomic_inc(&sw->ref, 1);
    }

    c_rd_unlock(&ctrl->lock);

    return sw;
}

c_switch_t *
of_switch_alias_get(ctrl_hdl_t *ctrl, int alias)
{
    c_switch_t       *sw; 

    c_rd_lock(&ctrl->lock);

    sw = ipool_idx_priv(ctrl->sw_ipool, alias);
    if (sw) {
        atomic_inc(&sw->ref, 1);
    }

    c_rd_unlock(&ctrl->lock);

    return sw;
}

c_switch_t *
__of_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid)
{
    c_switch_t       key, *sw = NULL; 
    unsigned int     found;

    key.datapath_id = dpid;

    if (ctrl->sw_hash_tbl) {
        found = g_hash_table_lookup_extended(ctrl->sw_hash_tbl, &key, 
                                             NULL, (gpointer*)&sw);
        if (found) {
            atomic_inc(&sw->ref, 1);
        }

    }

    return sw;
}


void
of_switch_put(c_switch_t *sw)
{
    if (atomic_read(&sw->ref) == 0){
        c_log_debug("sw (0x:%llx) freed", sw->DPID);
        of_switch_flow_tbl_delete(sw);
        if (sw->fp_ops.fp_db_dtor) {
            sw->fp_ops.fp_db_dtor(sw);
        }
        free(sw);
    } else {
        //c_log_debug("sw (0x:%llx) ref (%u)", sw->DPID, 
        //            (unsigned int)atomic_read(&sw->ref));
        atomic_dec(&sw->ref, 1);
    }
}

void
of_switch_detail_info(c_switch_t *sw,
                      struct ofp_switch_features *osf)
{
    struct ofp_phy_port *port_msg, *port;
    int n = 0;

    osf->datapath_id = htonll(sw->DPID);
    osf->n_buffers = htonl(sw->n_buffers);
    osf->n_tables = sw->n_tables;
    osf->capabilities = htonl(sw->capabilities);
    osf->actions = htonl(sw->actions);

    port_msg = osf->ports;

    for (; n < OFSW_MAX_PORTS; n++) {
        if (!sw->ports[n].valid) continue;

        port = &sw->ports[n].p_info;

        port_msg->port_no = htons(n);
        port_msg->config = htonl(port->config);
        port_msg->state = htonl(port->state);
        port_msg->curr = htonl(port->curr);
        port_msg->advertised = htonl(port->advertised);
        port_msg->supported = htonl(port->supported);
        port_msg->peer = htonl(port->peer);

        memcpy(port_msg->name, port->name, OFP_MAX_PORT_NAME_LEN);
        memcpy(port_msg->hw_addr, port->hw_addr, OFP_ETH_ALEN);

        port_msg++;
    }
}

void
of_switch_brief_info(c_switch_t *sw,
                     struct c_ofp_switch_brief *cofp_sb) 
{
    cofp_sb->switch_id.datapath_id = htonll(sw->DPID);
    cofp_sb->n_ports = ntohl(sw->n_ports);
    cofp_sb->state = ntohl(sw->switch_state); 
    strncpy(cofp_sb->conn_str, sw->conn.conn_str, OFP_CONN_DESC_SZ);
    cofp_sb->conn_str[OFP_CONN_DESC_SZ-1] = '\0';
}


void
of_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc iter_fn, void *arg)
{

    c_rd_lock(&hdl->lock);

    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)iter_fn, arg);
    }

    c_rd_unlock(&hdl->lock);

}

void
__of_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc iter_fn, void *arg)
{

    if (hdl->sw_hash_tbl) {
        g_hash_table_foreach(hdl->sw_hash_tbl,
                             (GHFunc)iter_fn, arg);
    }
}

static unsigned int
of_flow_exm_key(const void *p)
{
    const struct flow *fl = p;

    return hash_words((const uint32_t *) fl,
                      sizeof *fl/sizeof(uint32_t), 1);
}

static int 
of_flow_exm_key_cmp (const void *p1, const void *p2)
{
    struct flow *fl1 = (struct flow *) p1;
    struct flow *fl2 = (struct flow *) p2;

    return !memcmp(fl1, fl2, sizeof(*fl1));
}

static void
of_flow_exm_key_free(void *arg UNUSED)
{
    return;
}

static void
__of_flow_exm_release(void *arg)
{
    c_fl_entry_t *ent = arg;
    c_fl_entry_t *parent = ent->parent;

    if (parent) {
        parent->cloned_list = g_slist_remove(parent->cloned_list, ent);
        of_flow_entry_put(parent);
    }
    of_flow_entry_put(ent);
}

static void
of_flow_exm_release(void *arg, void *u_arg)
{
    c_flow_tbl_t *tbl;
    c_switch_t  *sw = u_arg;
    c_fl_entry_t *ent = arg;

    tbl = &sw->exm_flow_tbl;

    if (tbl->exm_fl_hash_tbl) {
        /* This will lead a call to __of_flow_exm_release() */
        g_hash_table_remove(tbl->exm_fl_hash_tbl, &ent->fl);
    }

    return;
}

static int
of_flow_add_app_ownership(c_fl_entry_t *ent, void *new_app)
{
    GSList       *iterator = NULL;
    void         *app;

    c_wr_lock(&ent->FL_LOCK);
    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        if (app == new_app) {
            c_wr_unlock(&ent->FL_LOCK);
            return -EEXIST;
        }
    }

    c_app_ref(new_app); 
    atomic_inc(&ent->app_ref, 1);
    ent->app_owner_list = g_slist_append(ent->app_owner_list, new_app);    
    c_wr_unlock(&ent->FL_LOCK);
 
    return 0;
}

int
__of_flow_find_app_ownership(void *key_arg UNUSED, void *ent_arg, void *app)
{
    GSList       *iterator = NULL;
    void         *app_owner;
    c_fl_entry_t *ent = ent_arg;

    for (iterator = ent->app_owner_list; iterator; iterator = iterator->next) {
        app_owner = iterator->data;
        if (app_owner == app) {
            return 1;
        }
    }

    return 0;
}

/* Ownership needs to be verified before calling */
static int
__of_flow_del_app_ownership(c_fl_entry_t *ent, void *app)
{
    ent->app_owner_list = g_slist_remove(ent->app_owner_list, app);    
    atomic_dec(&ent->app_ref, 1);
    c_app_unref(app); 
 
    return 0;
}

static int
of_flow_find_del_app_ownership(void *key_arg UNUSED, void *ent_arg, void *app)
{
    c_fl_entry_t *ent = ent_arg;

    c_wr_lock(&ent->FL_LOCK);

    if (__of_flow_find_app_ownership(NULL, ent, app) ) {
        __of_flow_del_app_ownership(ent, app);

        if (!atomic_read(&ent->app_ref)) {
            c_wr_unlock(&ent->FL_LOCK);
            return 1;
        }

        if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) { 
            of_send_flow_del(ent->sw, ent, 0, false);
        }
    }

    c_wr_unlock(&ent->FL_LOCK);

    return 0;
}

static void 
__of_per_switch_del_app_flow_rule(c_switch_t *sw, GSList **list, void *app) 
{
    GSList *tmp, *tmp1, *prev = NULL;
    c_fl_entry_t *ent;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     
        c_wr_lock(&ent->FL_LOCK);
        if (__of_flow_find_app_ownership(NULL, ent, app)) { 
            __of_flow_del_app_ownership(ent, app);
            c_wr_unlock(&ent->FL_LOCK);
            tmp1 = tmp;

            if (!atomic_read(&ent->app_ref)) {
                if (prev) {
                    prev->next = tmp->next;
                    tmp = tmp->next;
                } else {
                    *list = tmp->next;
                    tmp = *list;
                }

                if (!ent->parent && !(ent->FL_FLAGS & C_FL_ENT_LOCAL)) { 
                    of_send_flow_del(sw, ent, 0, false);
                }

                g_slist_free_1(tmp1);
                of_flow_rule_free(ent, sw);
                continue;
            }
        }

        c_wr_unlock(&ent->FL_LOCK);
        prev = tmp;
        tmp = prev->next;
    }

    return;
}

static void 
__of_per_switch_del_app_flow_exm(c_switch_t *sw, void *app) 
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;

    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_foreach_remove(tbl->exm_fl_hash_tbl,
                                    of_flow_find_del_app_ownership, app);
    }
}

void
__of_per_switch_del_app_flow_ownership(c_switch_t *sw, void *app)
{
    int idx = 0;    
    c_flow_tbl_t *tbl;

    for (idx = 0; idx < C_MAX_RULE_FLOW_TBLS; idx++) {
        tbl = &sw->rule_flow_tbls[idx];
        __of_per_switch_del_app_flow_rule(sw, &tbl->rule_fl_tbl, app);
    }

    __of_per_switch_del_app_flow_exm(sw, app);

}

static int  UNUSED
of_flow_exm_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    c_fl_entry_t *new_ent, *ent;
    c_flow_tbl_t  *tbl;
    int ret = 0;
    bool need_hw_sync = FL_EXM_NEED_HW_SYNC(fl_parms);

    if (of_exm_flow_mod_validate_parms(fl_parms)) {
        return -EINVAL;
    }

    new_ent = calloc(1, sizeof(*new_ent));
    assert(new_ent);

    c_rw_lock_init(&new_ent->FL_LOCK);
    new_ent->sw = sw;
    new_ent->FL_ENT_TYPE = C_TBL_EXM;
    new_ent->FL_FLAGS = fl_parms->flags;
    new_ent->FL_HWTBL_IDX = C_TBL_HW_IDX_DFL;
    
    new_ent->FL_PRIO = C_FL_PRIO_EXM;
    memcpy(&new_ent->fl, fl_parms->flow, sizeof(struct flow));
    new_ent->action_len = fl_parms->action_len;
    new_ent->actions    = fl_parms->actions;
    atomic_inc(&new_ent->FL_REF, 1);

    tbl = &sw->exm_flow_tbl;

    c_wr_lock(&sw->lock);

    if ((ent = __of_flow_get_exm(sw, fl_parms->flow))) {
        ret = -EEXIST;
        if ((fl_parms->flags & C_FL_ENT_LOCAL) &&
            (ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
           ret = of_flow_add_app_ownership(ent, fl_parms->app_owner);
        }

        c_wr_unlock(&sw->lock);
        of_flow_entry_put((void *)ent);
        free(new_ent);
        return ret;
    }

    of_flow_add_app_ownership(new_ent, fl_parms->app_owner);

    g_hash_table_insert(tbl->exm_fl_hash_tbl, &new_ent->fl, new_ent);

    c_wr_unlock(&sw->lock);

    if (need_hw_sync) {
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id, true);
    }

    of_flow_entry_put(new_ent);

    return ret;
}

/*
 * Parent should be held before hand 
 */
static c_fl_entry_t * 
of_flow_clone_exm(c_switch_t *sw, struct flow *flow, c_fl_entry_t *parent)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t  *tbl;

    ent = calloc(1, sizeof(*ent));
    assert(ent);

    ent->FL_ENT_TYPE = C_TBL_EXM;
    ent->FL_FLAGS = 0;
    ent->FL_HWTBL_IDX = parent->FL_HWTBL_IDX;
    
    ent->FL_ITIMEO = C_FL_IDLE_DFL_TIMEO;
    ent->FL_HTIMEO = C_FL_HARD_DFL_TIMEO;
    ent->FL_PRIO = C_FL_PRIO_EXM;
    memcpy(&ent->fl, flow, sizeof(*flow));
    ent->action_len = parent->action_len;
    ent->actions    = parent->actions;
    ent->parent     = parent;
    atomic_inc(&ent->FL_REF, 1);

    c_wr_lock(&sw->lock);

    tbl = &sw->exm_flow_tbl;

    parent->cloned_list = g_slist_append(parent->cloned_list, ent);
    g_hash_table_insert(tbl->exm_fl_hash_tbl, &ent->fl, ent);

    c_wr_unlock(&sw->lock);

    return ent;
}

static int  UNUSED
of_flow_exm_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    c_flow_tbl_t        *tbl;
    static c_fl_entry_t *fl_ent;

    if (of_exm_flow_mod_validate_parms(fl_parms)) {
        return -EINVAL;   
    }

    tbl = &sw->exm_flow_tbl;

    c_wr_lock(&sw->lock);

    fl_ent = __of_flow_get_exm(sw, fl_parms->flow);
    if (!fl_ent) {
        c_wr_unlock(&sw->lock);
        return -EINVAL;
    }


    c_wr_lock(&fl_ent->FL_LOCK);
    if (__of_flow_find_app_ownership(NULL, fl_ent, fl_parms->app_owner)) {
        __of_flow_del_app_ownership(fl_ent, fl_parms->app_owner);
        c_wr_unlock(&fl_ent->FL_LOCK);
    } else {
        c_log_err("%s: Ownership mismatch. Flow del failed", FN);
        c_wr_unlock(&fl_ent->FL_LOCK);
        c_wr_unlock(&sw->lock);
        return -EINVAL;
    }

    if (!atomic_read(&fl_ent->app_ref)) {
        g_hash_table_remove(tbl->exm_fl_hash_tbl, fl_parms->flow);
    }

    if (!(fl_ent->FL_FLAGS & C_FL_ENT_LOCAL)) 
        of_send_flow_del(sw, fl_ent, 0, true);


    c_wr_unlock(&sw->lock);

    of_flow_entry_put(fl_ent);

    return 0;
}

static void
of_flow_exm_iter(void *k UNUSED, void *v, void *args)
{
    struct c_iter_args *u_parms = args;
    c_fl_entry_t       *ent = v;
    flow_parser_fn     fn;

    fn = (flow_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, ent); 
}


static void
of_flow_rule_free(void *arg, void *u_arg)
{
    c_fl_entry_t *ent = arg;

    if (ent->cloned_list) {
        g_slist_foreach(ent->cloned_list, (GFunc)of_flow_exm_release, u_arg);
        g_slist_free(ent->cloned_list); 
    }

    of_flow_entry_put(ent);
}

static void
of_flow_rule_iter(void *k, void *args)
{
    struct c_iter_args *u_parms = args;
    c_fl_entry_t       *ent = k;
    flow_parser_fn     fn;

    fn = (flow_parser_fn)(u_parms->u_fn);

    fn(u_parms->u_arg, ent); 
}


static c_fl_entry_t * UNUSED
__of_flow_lookup_rule_strict(GSList *list, struct flow *fl, uint32_t wildcards)
{
    GSList *iterator = NULL;
    c_fl_entry_t *ent;

    for (iterator = list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if (!memcmp(&ent->fl, fl, sizeof(*fl)) 
            && ent->FL_WILDCARDS == wildcards) {
            return ent;
        }
    }

    return NULL;
}

static c_fl_entry_t * 
__of_flow_lookup_rule_strict_prio_hint_detail(c_switch_t *sw UNUSED, GSList **list,
                                       struct flow *fl, uint32_t wildcards,
                                       uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;
    struct flow *ent_fl;
    uint32_t fl_wildcards, ip_wc;
    uint32_t nw_dst_mask, nw_src_mask;

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) ||
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        }

        fl_wildcards = ntohl(ent->FL_WILDCARDS);
        if (ent->FL_WILDCARDS != wildcards) continue;

        fl_wildcards = ntohl(ent->FL_WILDCARDS);
        ent_fl = &ent->fl;

        ip_wc = ((fl_wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
        nw_dst_mask = ip_wc >= 32 ? 0 :
                                    make_inet_mask(32-ip_wc);

        ip_wc = ((fl_wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
        nw_src_mask = ip_wc >= 32 ? 0 :
                                    make_inet_mask(32-ip_wc);

        if ((fl->nw_dst & htonl(nw_dst_mask)) == ent_fl->nw_dst &&
            (fl->nw_src & htonl(nw_src_mask)) == ent_fl->nw_src &&
            (fl_wildcards & OFPFW_NW_PROTO || fl->nw_proto == ent_fl->nw_proto) &&
            (fl_wildcards & OFPFW_NW_TOS || fl->nw_tos == ent_fl->nw_tos) &&
            (fl_wildcards & OFPFW_TP_DST || fl->tp_dst == ent_fl->tp_dst) &&
            (fl_wildcards & OFPFW_TP_SRC || fl->tp_src == ent_fl->tp_src) &&
            (fl_wildcards & OFPFW_DL_SRC || !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (fl_wildcards & OFPFW_DL_DST || !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (fl_wildcards & OFPFW_DL_TYPE || fl->dl_type == ent_fl->dl_type) &&
            (fl_wildcards & OFPFW_DL_VLAN || fl->dl_vlan == ent_fl->dl_vlan) &&
            (fl_wildcards & OFPFW_DL_VLAN_PCP || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (fl_wildcards & OFPFW_IN_PORT || fl->in_port == ent_fl->in_port) &&
            ent->FL_PRIO == prio)  {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}


static c_fl_entry_t *
__of_flow_lookup_rule_strict_prio_hint(GSList **list, struct flow *fl, uint32_t wildcards,
                                       uint16_t prio)
{
    GSList *iterator = NULL, *hint = NULL;
    c_fl_entry_t *ent;

    for (iterator = *list; iterator; iterator = iterator->next) {
        ent = iterator->data;
        if ((hint && ((c_fl_entry_t *)(hint->data))->FL_PRIO > ent->FL_PRIO) || 
            (prio >= ent->FL_PRIO)) {
            hint = iterator;
        } 
        if (!memcmp(&ent->fl, fl, sizeof(*fl)) 
            && ent->FL_WILDCARDS == wildcards &&
            ent->FL_PRIO == prio) {
            *list = hint;
            return ent;
        }
    }

    *list = hint;
    return NULL;
}

static void UNUSED
of_flow_print_no_match(c_fl_entry_t  *ent, struct flow *fl)
{
    uint32_t      wildcards, ip_wc;
    uint32_t      nw_dst_mask, nw_src_mask;  
    struct flow   *ent_fl;
    char          *miss_str = NULL;

    ent_fl = &ent->fl;
    wildcards = ntohl(ent->FL_WILDCARDS);

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 :
                                make_inet_mask(32-ip_wc);

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 :
                                make_inet_mask(32-ip_wc);


    /* Move this to generic match for any of version */
    if ((fl->nw_dst & htonl(nw_dst_mask)) != ent_fl->nw_dst) {
        miss_str = "nw dst"; 
        goto out;
    }
    if ((fl->nw_src & htonl(nw_src_mask)) != ent_fl->nw_src) {
        miss_str = "nw src";
        goto out;
    }
    
    if (!(wildcards & OFPFW_NW_PROTO) && fl->nw_proto != ent_fl->nw_proto) {
        miss_str = "nw proto";
        goto out;
    }
    if (!(wildcards & OFPFW_NW_TOS) && fl->nw_tos != ent_fl->nw_tos) {
        miss_str = "nw tos";
        goto out;
    }
    if (!(wildcards & OFPFW_TP_DST) && fl->tp_dst != ent_fl->tp_dst) {
        miss_str = "nw tp dst";
        goto out;
    }
    if (!(wildcards & OFPFW_TP_SRC) && fl->tp_src != ent_fl->tp_src) {
        miss_str = "nw tp src";
        goto out;
    }
    if (!(wildcards & OFPFW_DL_SRC) && memcmp(fl->dl_src, ent_fl->dl_src, 6)) {
        miss_str = "nw dl src";
        goto out;
    } 
    if (!(wildcards & OFPFW_DL_DST) && memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) {
        miss_str = "nw dl dst";
        goto out;

    }
    if (!(wildcards & OFPFW_DL_TYPE) && fl->dl_type != ent_fl->dl_type) {
        miss_str = "nw dl type";
        goto out;

    }
    if (!(wildcards & OFPFW_DL_VLAN) && fl->dl_vlan != ent_fl->dl_vlan) {
        miss_str = "dl_vlan";
        goto out;
    }
    if (!(wildcards & OFPFW_DL_VLAN_PCP) && fl->dl_vlan_pcp != ent_fl->dl_vlan_pcp) { 
        miss_str = "dl_vlan_pcp";
        goto out;
    }    
    if (!(wildcards & OFPFW_IN_PORT) && fl->in_port != ent_fl->in_port)  {
        miss_str = "in port";
        goto out;
    }
out:

    if (miss_str) {
        c_log_debug ("Mismatch @ %s", miss_str); 
    }

    return;
}

static c_fl_entry_t *
__of_flow_lookup_rule(c_switch_t *sw UNUSED, struct flow *fl, c_flow_tbl_t *tbl)
{
    GSList *list, *iterator = NULL;
    c_fl_entry_t  *ent;
    struct flow   *ent_fl;
    uint32_t      wildcards, ip_wc;
    uint32_t      nw_dst_mask, nw_src_mask; 

    list = tbl->rule_fl_tbl;

    for (iterator = list; iterator; iterator = iterator->next) {
        
        ent = iterator->data;
        ent_fl = &ent->fl;
        wildcards = ntohl(ent->FL_WILDCARDS);

        ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
        nw_dst_mask = ip_wc >= 32 ? 0 :
                                    make_inet_mask(32-ip_wc);

        ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
        nw_src_mask = ip_wc >= 32 ? 0 :
                                    make_inet_mask(32-ip_wc);


        /* Move this to generic match for any of version */
        if ((fl->nw_dst & htonl(nw_dst_mask)) == ent_fl->nw_dst &&
            (fl->nw_src & htonl(nw_src_mask)) == ent_fl->nw_src && 
            (wildcards & OFPFW_NW_PROTO || fl->nw_proto == ent_fl->nw_proto) &&
            (wildcards & OFPFW_NW_TOS || fl->nw_tos == ent_fl->nw_tos) &&
            (wildcards & OFPFW_TP_DST || fl->tp_dst == ent_fl->tp_dst) &&
            (wildcards & OFPFW_TP_SRC || fl->tp_src == ent_fl->tp_src) &&
            (wildcards & OFPFW_DL_SRC || !memcmp(fl->dl_src, ent_fl->dl_src, 6)) &&
            (wildcards & OFPFW_DL_DST || !memcmp(fl->dl_dst, ent_fl->dl_dst, 6)) &&
            (wildcards & OFPFW_DL_TYPE || fl->dl_type == ent_fl->dl_type) && 
            (wildcards & OFPFW_DL_VLAN || fl->dl_vlan == ent_fl->dl_vlan) &&
            (wildcards & OFPFW_DL_VLAN_PCP || fl->dl_vlan_pcp == ent_fl->dl_vlan_pcp) &&
            (wildcards & OFPFW_IN_PORT || fl->in_port == ent_fl->in_port))  {
            return ent;
        }

    }

    return NULL;
}


static int
of_flow_rule_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
    GSList       *list;
    c_fl_entry_t *new_ent, *ent;
    c_flow_tbl_t *tbl;
    int          ret = 0;
    bool         hw_sync = FL_NEED_HW_SYNC(fl_parms); 

    new_ent = calloc(1, sizeof(*new_ent));
    assert(new_ent);

    if (of_flow_mod_validate_parms(fl_parms)) {
        return -EINVAL;
    }

    /* FIXME Move allocation and init to common function */
    c_rw_lock_init(&new_ent->FL_LOCK);
    new_ent->sw = sw;
    new_ent->FL_ENT_TYPE = C_TBL_RULE;
    new_ent->FL_FLAGS = fl_parms->flags;
    new_ent->FL_WILDCARDS = fl_parms->wildcards;
    new_ent->FL_HWTBL_IDX = C_TBL_HW_IDX_DFL; 

    new_ent->FL_PRIO = fl_parms->prio;
    memcpy(&new_ent->fl, fl_parms->flow, sizeof(struct flow));
    new_ent->action_len = fl_parms->action_len;
    new_ent->actions    = fl_parms->actions;
    new_ent->cloned_list = NULL;

    if (hw_sync) {
        atomic_inc(&new_ent->FL_REF, 1); 
    }

    tbl = &sw->rule_flow_tbls[fl_parms->tbl_idx];
    list = tbl->rule_fl_tbl;

    c_wr_lock(&sw->lock);

    /* FIXME : Combine lookup and insert for perf */   
    if ((ent = __of_flow_lookup_rule_strict_prio_hint(&list, fl_parms->flow, 
                                                      fl_parms->wildcards, 
                                                      fl_parms->prio))) {
        ret = -EEXIST;
        if ((fl_parms->flags & C_FL_ENT_LOCAL) && 
            (ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
           ret = of_flow_add_app_ownership(ent, fl_parms->app_owner);
        }

        c_wr_unlock(&sw->lock);
        free(new_ent);
        c_log_debug("%s: Flow already present", FN);
        return ret;
    }

    of_flow_add_app_ownership(new_ent, fl_parms->app_owner);

    tbl->rule_fl_tbl = g_slist_insert_before(tbl->rule_fl_tbl, list, new_ent);
    c_wr_unlock(&sw->lock);

    if (hw_sync) {
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id, true);
        of_flow_entry_put(new_ent);
    }

    return ret;
}

static bool
__of_flow_rule_del_strict(GSList **list, struct flow **flow, 
                          uint32_t wildcards, uint16_t prio, 
                          void *app)
{
    GSList *tmp, *prev = NULL;
    c_fl_entry_t *ent;
    bool found = false;
    
    tmp = *list;
    while (tmp) {
        ent = tmp->data;     

        c_wr_lock(&ent->FL_LOCK);
        if (!memcmp(&ent->fl, *flow, sizeof(struct flow)) &&
            ent->FL_WILDCARDS == wildcards && 
            ent->FL_PRIO == prio &&
            __of_flow_find_app_ownership(NULL, ent, app)) { 

            __of_flow_del_app_ownership(ent, app);

            c_wr_unlock(&ent->FL_LOCK);
            *flow = &ent->fl;
            found = TRUE;

            if (atomic_read(&ent->app_ref)) {
                break;
            }

            if (prev)
                prev->next = tmp->next;
            else
                *list = tmp->next;
            g_slist_free_1 (tmp);
            break;
        }
        prev = tmp;
        tmp = prev->next;
        c_wr_unlock(&ent->FL_LOCK);
    }       

    return found;
}

static int
of_flow_rule_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t  *tbl;
    struct flow *flow = fl_parms->flow;

    if (of_flow_mod_validate_parms(fl_parms)) {
        return -1;
    }

    tbl = &sw->rule_flow_tbls[fl_parms->tbl_idx];

    c_wr_lock(&sw->lock);

    if (!__of_flow_rule_del_strict(&tbl->rule_fl_tbl, &flow, 
                                   fl_parms->wildcards, fl_parms->prio, 
                                   fl_parms->app_owner)) {
        c_log_err("%s: Flow not present", FN);
        c_wr_unlock(&sw->lock);
        return -1;
    }

    /* FIXME : Take this ent and add to a tentative list 
     * If we get negative ack from switch add it back to flow
     * table else free it. 
     */
    ent = container_of(flow, c_fl_entry_t, fl);

    if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
        of_send_flow_del_strict(sw, ent, 0);
    }

    if (!atomic_read(&ent->app_ref)) {
        of_flow_rule_free(ent, sw);
    }

    c_wr_unlock(&sw->lock);

    return 0;
}

int
of_flow_add(c_switch_t *sw, struct of_flow_mod_params *fl_parms)
{
#ifdef CONFIG_FLOW_EXM
    if (fl_parms->wildcards) {
        return of_flow_rule_add(sw, fl_parms);
    } else {
        return of_flow_exm_add(sw, fl_parms);
    }

    return 0;
#else
    return of_flow_rule_add(sw, fl_parms);
#endif
}

int
of_flow_del(c_switch_t *sw, struct of_flow_mod_params *fl_parms) 
{
#ifdef CONFIG_FLOW_EXM
    if (fl_parms->wildcards) {
        return of_flow_rule_del(sw, fl_parms);
    } else {
        return of_flow_exm_del(sw, fl_parms);
    }

    return 0;
#else
    return of_flow_rule_del(sw, fl_parms);
#endif
}


static void
c_per_flow_resync_hw(void *arg UNUSED, c_fl_entry_t *ent)
{
    if (ent->FL_FLAGS & C_FL_ENT_NOSYNC ||  ent->FL_FLAGS & C_FL_ENT_CLONE ||
        ent->FL_FLAGS & C_FL_ENT_LOCAL ) {
        return;
    }

    of_send_flow_add(ent->sw, ent, 0xffffffff, false);
}

void
c_per_switch_flow_resync_hw(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;

    c_log_info("%s: Resync of-flows switch 0x%llx", FN, sw->DPID);
    c_rd_lock(&sw->lock);
    of_flow_traverse_tbl_all(sw, arg, c_per_flow_resync_hw);
    c_rd_unlock(&sw->lock);
}

void
of_flow_resync_hw_all(ctrl_hdl_t *c_hdl)
{
    c_log_info("%s: ", FN);
    of_switch_traverse_all(c_hdl, c_per_switch_flow_resync_hw,
                           NULL);
}

static void
of_flow_traverse_tbl(c_switch_t *sw, uint8_t tbl_type, uint8_t tbl_idx, 
                     void *u_arg, flow_parser_fn fn)
{
    struct c_iter_args  args;
    c_flow_tbl_t        *tbl;

    if (tbl_type && tbl_idx >= C_MAX_RULE_FLOW_TBLS) {
        c_log_err("%s unknown tbl type", FN);
        return;
    }

    args.u_arg = u_arg;
    args.u_fn  = (void *)fn;

    c_rd_lock(&sw->lock);

    if (!tbl_type) {
        tbl = &sw->exm_flow_tbl;
    } else {
        tbl = &sw->rule_flow_tbls[tbl_idx];
    }

    if (tbl->c_fl_tbl_type == C_TBL_EXM &&
        tbl->exm_fl_hash_tbl) {
        g_hash_table_foreach(tbl->exm_fl_hash_tbl,
                             (GHFunc)of_flow_exm_iter, &args);
    } else if (tbl->c_fl_tbl_type == C_TBL_RULE &&
               tbl->rule_fl_tbl){
        g_slist_foreach(tbl->rule_fl_tbl, 
                        (GFunc)of_flow_rule_iter, &args);
    }

    c_rd_unlock(&sw->lock);
}

void 
of_flow_traverse_tbl_all(c_switch_t *sw, void *u_arg, flow_parser_fn fn)
{
    uint8_t       tbl_idx = 0;

#ifdef CONFIG_FLOW_EXM
    of_flow_traverse_tbl(sw, C_TBL_EXM, tbl_idx, u_arg, fn);
#endif

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        of_flow_traverse_tbl(sw, C_TBL_RULE, tbl_idx, u_arg, fn);
    }
 
}

static void
of_switch_flow_tbl_create(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;
    
    c_wr_lock(&sw->lock);

    tbl = &sw->exm_flow_tbl;
    if (!tbl->exm_fl_hash_tbl) {
        tbl->exm_fl_hash_tbl =
                    g_hash_table_new_full(of_flow_exm_key,
                                          of_flow_exm_key_cmp,
                                          of_flow_exm_key_free,
                                          __of_flow_exm_release);
        assert(tbl->exm_fl_hash_tbl);
        tbl->c_fl_tbl_type = C_TBL_EXM;
        tbl->hw_tbl_idx = C_TBL_HW_IDX_DFL;
    }

    for (tbl_idx = 0; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        /* list created on demand */
        tbl->c_fl_tbl_type = C_TBL_RULE; 
        tbl->hw_tbl_idx = C_TBL_HW_IDX_DFL;
    }
    c_wr_unlock(&sw->lock);
}

void
of_switch_flow_tbl_delete(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;

    c_wr_lock(&sw->lock);

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        if (tbl->rule_fl_tbl) {
            g_slist_foreach(tbl->rule_fl_tbl, (GFunc)of_flow_rule_free, sw);
            g_slist_free(tbl->rule_fl_tbl);
            tbl->rule_fl_tbl = NULL;
        }
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_destroy(tbl->exm_fl_hash_tbl);
        tbl->exm_fl_hash_tbl = NULL;
    }

    c_wr_unlock(&sw->lock);
}

void
of_switch_flow_tbl_reset(c_switch_t *sw)
{
    int           tbl_idx = 0;
    c_flow_tbl_t  *tbl;

    c_wr_lock(&sw->lock);

    for (; tbl_idx < C_MAX_RULE_FLOW_TBLS; tbl_idx++) {
        tbl = &sw->rule_flow_tbls[tbl_idx];
        if (tbl->rule_fl_tbl) {
            g_slist_foreach(tbl->rule_fl_tbl, (GFunc)of_flow_rule_free, sw);
            g_slist_free(tbl->rule_fl_tbl);
            tbl->rule_fl_tbl = NULL;
        }
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_remove_all(tbl->exm_fl_hash_tbl);
    }

    c_wr_unlock(&sw->lock);
}

static inline void
of_prep_msg_on_stack(struct cbuf *b, size_t len, uint8_t type, uint32_t xid)
{
    struct ofp_header *h;

    h = (void *)(b->data);

    h->version = OFP_VERSION;
    h->type = type;
    h->length = htons(len);

    h->xid = xid;

    /* NOTE - No memset of extra data for performance */

    return;
}

void
of_send_features_request(c_switch_t *sw)
{
    struct cbuf *b;

    /* Send OFPT_FEATURES_REQUEST. */
    b = of_prep_msg(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, 0);

    c_switch_tx(sw, b, true);
}

void
__of_send_features_request(c_switch_t *sw)
{
    of_send_features_request(sw);
    c_thread_sg_tx_sync(&sw->conn);
}

void
of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len)
{
    struct cbuf *b;
    struct ofp_switch_config *ofp_sc;
    
    /* Send OFPT_SET_CONFIG. */
    b = of_prep_msg(sizeof(struct ofp_switch_config), OFPT_SET_CONFIG, 0);
    ofp_sc = (void *)(b->data);
    ofp_sc->flags = htons(flags);
    ofp_sc->miss_send_len = htons(miss_len);

    c_switch_tx(sw, b, true);
}

void
__of_send_set_config(c_switch_t *sw, uint16_t flags, uint16_t miss_len)
{
    of_send_set_config(sw, flags, miss_len);
    c_thread_sg_tx_sync(&sw->conn);
}

void
of_send_echo_request(c_switch_t *sw)
{
    struct cbuf *b;

    /* Send OFPT_ECHO_REQUEST. */
    b = of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REQUEST, 0);

    c_switch_tx(sw, b, false);
}

void
__of_send_echo_request(c_switch_t *sw)
{
    of_send_echo_request(sw);
}

void
of_send_echo_reply(c_switch_t *sw, uint32_t xid)
{
    struct cbuf *b;

    /* Send OFPT_ECHO_REPLY */
    b = of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REPLY, xid);

    c_switch_tx(sw, b, false);
}

void
__of_send_echo_reply(c_switch_t *sw, uint32_t xid)
{
    of_send_echo_reply(sw, xid);
}

void
of_send_hello(c_switch_t *sw)
{
    struct cbuf *b;

    /* Send OFPT_HELLO */
    b = of_prep_msg(sizeof(struct ofp_header), OFPT_HELLO, 0);

    c_switch_tx(sw, b, false);
}

void __fastpath
of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    struct cbuf           *b;

    b = of_prep_pkt_out_msg(parms);

    c_switch_tx(sw, b, true);
} 

void __fastpath
of_send_pkt_out_inline(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    struct cbuf     b;
    size_t          tot_len;
    uint8_t         data[C_INLINE_BUF_SZ];
    struct ofp_packet_out *out;

    tot_len = sizeof(struct ofp_packet_out)+parms->action_len+parms->data_len;

    if (tot_len > C_INLINE_BUF_SZ) return of_send_pkt_out(sw, parms);

    cbuf_init_on_stack(&b, data, tot_len);
    of_prep_msg_on_stack(&b, tot_len, OFPT_PACKET_OUT, 
                         (unsigned long)parms->data);

    out = (void *)b.data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htons(parms->in_port);
    out->actions_len = htons(parms->action_len);
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy((uint8_t *)out->actions + parms->action_len, 
            parms->data, parms->data_len);

    c_switch_tx(sw, &b, false);
} 

void __fastpath
__of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    of_send_pkt_out(sw, parms);
    c_thread_sg_tx_sync(&sw->conn);
}

static void
of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id,
                 bool ha_sync UNUSED)
{
    struct cbuf *b = of_prep_flow_add_msg(&ent->fl, buffer_id, ent->actions, 
                                          ent->action_len, ent->FL_ITIMEO,
                                          ent->FL_HTIMEO, ent->FL_WILDCARDS,
                                          ent->FL_PRIO);
    c_switch_tx(sw, b, true);
} 

static void UNUSED
__of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id,
                   bool ha_sync)
{
    of_send_flow_add(sw, ent, buffer_id, ha_sync);
    c_thread_sg_tx_sync(&sw->conn);
}


int __fastpath
of_send_flow_add_nocache(c_switch_t *sw, struct flow *fl, uint32_t buffer_id,
                         void *actions, size_t action_len, uint16_t itimeo,
                         uint16_t htimeo, uint32_t wildcards, uint16_t prio)
{
    struct cbuf *b = of_prep_flow_add_msg(fl, buffer_id, actions, 
                                          action_len, itimeo, htimeo,
                                          wildcards, prio);
    c_switch_tx(sw, b, true);

    return 0;
} 

int __fastpath
__of_send_flow_add_nocache(c_switch_t *sw, struct flow *fl, uint32_t buffer_id,
                           void *actions, size_t action_len, uint16_t itimeo,
                           uint16_t htimeo, uint32_t wildcards, uint16_t prio)
{
    int ret;
    ret = of_send_flow_add_nocache(sw, fl, buffer_id, actions, action_len,
                                   itimeo, htimeo, wildcards, prio);
    c_thread_sg_tx_sync(&sw->conn);
    
    return ret;
}

static void
of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport, bool strict)
{
    struct cbuf *b = of_prep_flow_del_msg(&ent->fl, ent->FL_WILDCARDS, oport,
                                          strict); 
    c_switch_tx(sw, b, true);
}

static void
of_send_flow_del_strict(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport)
{
    struct cbuf *b = of_prep_flow_del_msg(&ent->fl, ent->FL_WILDCARDS, oport,
                                          true); 
    struct ofp_flow_mod *ofm = (void *)(b->data);

    /* Kludge which I hate */
    ofm->priority = htons(ent->FL_PRIO);
    c_switch_tx(sw, b, true);
}

static void UNUSED
__of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent, uint16_t oport, bool strict)
{
    of_send_flow_del(sw, ent, oport, strict);
    c_thread_sg_tx_sync(&sw->conn);
}

int
of_send_flow_del_nocache(c_switch_t *sw, struct flow *fl, uint32_t wildcards,
                         uint16_t oport, bool strict)
{
    struct cbuf *b = of_prep_flow_del_msg(fl, wildcards, oport, strict);

    c_switch_tx(sw, b, true);

    return 0;
}

int
__of_send_flow_del_nocache(c_switch_t *sw, struct flow *fl, uint32_t wildcards,
                         uint16_t oport, bool strict)
{
    of_send_flow_del_nocache(sw, fl, wildcards, oport, strict);
    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

int
of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow, 
                      uint32_t wildcards, uint8_t tbl_id, uint16_t oport)
{
    struct cbuf *b = of_prep_flow_stat_msg(flow, wildcards, tbl_id, oport); 
    
    c_switch_tx(sw, b, true);
    return 0;
}

int
__of_send_flow_stat_req(c_switch_t *sw, const struct flow *flow, 
                        uint32_t wildcards, uint8_t tbl_id, uint16_t oport)
{
    of_send_flow_stat_req(sw, flow, wildcards, tbl_id, oport);

    c_thread_sg_tx_sync(&sw->conn);
    return 0;
}

static void 
of_process_phy_port(c_switch_t *sw, void *opp_, uint8_t reason,
                    struct c_port_cfg_state_mask *chg_mask)
{
    const struct ofp_phy_port   *opp;
    struct ofp_phy_port         *port_desc;
    uint16_t                     port_no;

    opp     = opp_;
    port_no = ntohs(opp->port_no);

    if (port_no >= OFSW_MAX_PORTS) {
        c_log_err("%s:Cant process out-of-range dp port(%u)", FN, port_no);
        return;
    }

    port_desc = &sw->ports[port_no].p_info;

    switch (reason) {
    case OFPPR_DELETE:
        c_log_err("%s: %llx port(%u) delete", FN, sw->DPID, port_no);
        if (!(sw->ports[port_no].valid & OFC_SW_PORT_VALID)) {
            /* Nothing to do */
            return;
        }

        sw->n_ports--;
        memset (&sw->ports[port_no], 0, sizeof(struct ofp_phy_port));
        sw->ports[port_no].valid = OFC_SW_PORT_INVALID;
        return;
    case OFPPR_ADD:
    case OFPPR_MODIFY:
        if (!(sw->ports[port_no].valid & OFC_SW_PORT_VALID)) { 
            sw->n_ports++;
        }
        break;
    default:
        c_log_err("%s: Unknown port(%u) change reason(%u)", FN, port_no, reason);
        return;
    }

    sw->ports[port_no].valid = OFC_SW_PORT_VALID;

    if (chg_mask) { 
        chg_mask->config_mask = port_desc->config ^ ntohl(opp->config);
        chg_mask->state_mask = port_desc->state ^ ntohl(opp->state);
    }

    port_desc->port_no  = port_no;
    port_desc->config   = ntohl(opp->config);
    port_desc->state    = ntohl(opp->state);
    port_desc->curr     = ntohl(opp->curr);
    port_desc->advertised= ntohl(opp->advertised);
    port_desc->supported = ntohl(opp->supported);
    port_desc->peer      = ntohl(opp->peer);

    memcpy(port_desc->name, opp->name, OFP_MAX_PORT_NAME_LEN);
    port_desc->name[OFP_MAX_PORT_NAME_LEN-1] = '\0';

    memcpy(port_desc->hw_addr, opp->hw_addr, OFP_ETH_ALEN);

    return;
}

static void
of_recv_port_status(c_switch_t *sw, struct cbuf *b)
{
    struct c_port_cfg_state_mask chg_mask = { 0, 0 };
    struct ofp_port_status *ops = (void *)(b->data);

    c_wr_lock(&sw->lock);
    of_process_phy_port(sw, &ops->desc, ops->reason, &chg_mask);
    c_wr_unlock(&sw->lock);

    c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &chg_mask);
}

static void
of_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_switch_features  *osf = (void *)(b->data);
    size_t                       n_ports, i;
    c_switch_t                  *old_sw = NULL;
    struct flow                  flow;

    memset(&flow, 0, sizeof(flow));
    old_sw = of_switch_get(sw->c_hdl, ntohll(osf->datapath_id));
    if (old_sw) {
        switch (of_switch_clone_on_conn(sw, old_sw)) {
        case SW_CLONE_USE: 
            c_log_debug("%s: Use new switch conn", FN);
            of_switch_put(old_sw);
            break;
        case SW_CLONE_DENY:
            c_log_debug("%s: Denied new switch conn", FN);
            sw->conn.dead = true; /* Indication to close the conn on switch delete */
            of_switch_mark_sticky_del(sw); /* eventually switch should go */
            of_switch_put(old_sw);
            return;
        case SW_CLONE_OLD:
            c_log_debug("%s: Clone old switch conn", FN);
            c_conn_events_del(&sw->conn);
            of_switch_mark_sticky_del(sw);
            old_sw->reinit_fd = sw->conn.fd;
            old_sw->switch_state |= c_switch_is_virtual(sw) ?
                                   SW_REINIT_VIRT:
                                   SW_REINIT;
            old_sw->switch_state &= ~SW_DEAD;
            of_switch_put(old_sw);
            return;
        default:
            c_log_err("%s: Unknown clone state", FN);
            of_switch_put(old_sw);
            return;
        }
    }
    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof *osf->ports);

    sw->datapath_id = ntohll(osf->datapath_id);
    sw->version     = osf->header.version;
    sw->n_buffers   = ntohl(osf->n_buffers);
    sw->n_ports     = 0;
    sw->n_tables    = osf->n_tables;
    sw->actions     = ntohl(osf->actions);
    sw->capabilities = ntohl(osf->capabilities);
    memset(sw->ports, 0, sizeof(sw->ports)); 

    for (i = 0; i < n_ports; i++) {
        of_process_phy_port(sw, &osf->ports[i], OFPPR_ADD, NULL);
    }

    if (!(sw->switch_state & SW_REGISTERED)) {
        of_switch_flow_tbl_create(sw);
        of_switch_add(sw);
        sw->switch_state |= SW_REGISTERED;
        sw->last_sample_time = time(NULL);
        sw->fp_ops.fp_fwd = of_dfl_fwd;
        sw->fp_ops.fp_port_status = of_dfl_port_status;

        __of_send_flow_del_nocache(sw, &flow, htonl(OFPFW_ALL),
                               OFPP_NONE, false);
        __of_send_set_config(sw, 0x3, C_MAX_MISS_SEND_LEN);
        c_signal_app_event(sw, b, C_DP_REG, NULL, NULL);
    }
}

int __fastpath
of_flow_extract(uint8_t *pkt, struct flow *flow, 
                uint16_t in_port, size_t pkt_len,
                bool only_l2)
{
    struct eth_header *eth;
    int    retval = 0;
    size_t rem_len = pkt_len;

    memset(flow, 0, sizeof *flow);
    flow->dl_vlan = 0;  //htons(OFP_VLAN_NONE);
    flow->in_port = htons(in_port);

    if (unlikely(rem_len < sizeof(*eth))) {
        return -1;
    }

    eth = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
    rem_len -= sizeof(*eth);
    if (likely(ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF)) {
        /* This is an Ethernet II frame */
        flow->dl_type = eth->eth_type;
    } else {
        /* This is an 802.2 frame */
        c_log_err("802.2 recvd. Not handled");
        return -1;
    }

    /* Check for a VLAN tag */
    if (unlikely(flow->dl_type == htons(ETH_TYPE_VLAN))) {
        struct vlan_header *vh;
        if (rem_len < sizeof(*vh)) {
            return -1;
        }
        vh =  OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*vh);
        flow->dl_type = vh->vlan_next_type;
        flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK);
        flow->dl_vlan_pcp = (uint8_t)((ntohs(vh->vlan_tci)  >>  
                                        VLAN_PCP_SHIFT) & VLAN_PCP_BITMASK);
    }

    memcpy(flow->dl_dst, eth->eth_dst, 2*ETH_ADDR_LEN);

    if (likely(only_l2)) {
        return 0;
    }

    if (likely(flow->dl_type == htons(ETH_TYPE_IP))) {
        const struct ip_header *nh;

        if (rem_len < sizeof(*nh)) {
            return -1;
        }
        nh = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
        rem_len -= sizeof(*nh);

        flow->nw_tos = nh->ip_tos & 0xfc;
        flow->nw_proto = nh->ip_proto;
        flow->nw_src = nh->ip_src;
        flow->nw_dst = nh->ip_dst;
        if (likely(!IP_IS_FRAGMENT(nh->ip_frag_off))) {
            if (flow->nw_proto == IP_TYPE_TCP) {
                const struct tcp_header *tcp;
                if (rem_len < sizeof(*tcp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                tcp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);;
                rem_len -= sizeof(*tcp);

                flow->tp_src = tcp->tcp_src;
                flow->tp_dst = tcp->tcp_dst;
            } else if (flow->nw_proto == IP_TYPE_UDP) {
                const struct udp_header *udp;
                if (rem_len < sizeof(*udp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                udp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
                rem_len -= sizeof(*udp);

                flow->tp_src = udp->udp_src;
                flow->tp_dst = udp->udp_dst;
            } else if (flow->nw_proto == IP_TYPE_ICMP) {
                const struct icmp_header *icmp;
                if (rem_len < sizeof(*icmp)) {
                    flow->nw_proto = 0;
                    return 0;
                }
                icmp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len);
                rem_len -= sizeof(*icmp);

                flow->tp_src = htons(icmp->icmp_type);
                flow->tp_dst = htons(icmp->icmp_code);
            }
       } else {
                retval = 1;
       }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        const struct arp_eth_header *arp;
        if (rem_len < sizeof(*arp)) {
            return -1;
        }
        arp = OF_PKT_NEXT_HDR(pkt, pkt_len, rem_len); 
        rem_len -= sizeof(*arp);

        if (arp->ar_pro == htons(ARP_PRO_IP) && 
            arp->ar_pln == IP_ADDR_LEN) {
                flow->nw_src = arp->ar_spa;
                flow->nw_dst = arp->ar_tpa;
        }
        flow->nw_proto = ntohs(arp->ar_op) && 0xff;
    }
    return retval;
}

static c_fl_entry_t * UNUSED 
of_flow_get_exm(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;
    c_fl_entry_t     *ent = NULL;
    unsigned int     found;

    c_rd_lock(&sw->lock);

    found = g_hash_table_lookup_extended(tbl->exm_fl_hash_tbl, fl,
                                         NULL, (gpointer*)&ent);
    if (found) {
        atomic_inc(&ent->FL_REF, 1);
    }

    c_rd_unlock(&sw->lock);

    return ent;

}

static c_fl_entry_t *
__of_flow_get_exm(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl = &sw->exm_flow_tbl;
    c_fl_entry_t     *ent = NULL;
    unsigned int     found;

    found = g_hash_table_lookup_extended(tbl->exm_fl_hash_tbl, fl,
                                         NULL, (gpointer*)&ent);
    if (found) {
        atomic_inc(&ent->FL_REF, 1);
    }

    return ent;
}

static inline c_fl_entry_t *
of_do_flow_lookup_slow(c_switch_t *sw, struct flow *fl)
{
    c_flow_tbl_t     *tbl;
    c_fl_entry_t     *ent = NULL;
    int              idx;
    
    c_rd_lock(&sw->lock);
    for (idx = 0; idx < C_MAX_RULE_FLOW_TBLS; idx++) {
        tbl = &sw->rule_flow_tbls[idx];
        if (tbl && (ent = __of_flow_lookup_rule(sw, fl, tbl))) {
            atomic_inc(&ent->FL_REF, 1);
            c_rd_unlock(&sw->lock);
            return ent;
        }
    }
    c_rd_unlock(&sw->lock);

    return NULL;
}

static c_fl_entry_t *
of_do_flow_lookup_with_details(c_switch_t *sw, struct flow *fl,
                               uint32_t wildcards, uint16_t prio)
{
    c_flow_tbl_t     *tbl;
    c_fl_entry_t     *ent = NULL;
    int              idx;
    GSList           *list = NULL;

    c_rd_lock(&sw->lock);
    for (idx = 0; idx < C_MAX_RULE_FLOW_TBLS; idx++) {
        tbl = &sw->rule_flow_tbls[idx];
        list = tbl->rule_fl_tbl;
        if (tbl &&
            (ent = __of_flow_lookup_rule_strict_prio_hint_detail
                            (sw, &list, fl, wildcards, prio))) {
            atomic_inc(&ent->FL_REF, 1);
            c_rd_unlock(&sw->lock);
            return ent;
        }
    }
    c_rd_unlock(&sw->lock);

    return NULL;
}

static inline c_fl_entry_t *
of_do_flow_lookup(c_switch_t *sw, struct flow *fl)
{

#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = of_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return of_do_flow_lookup_slow(sw, fl);
}

static inline c_fl_entry_t *
of_do_flow_lookup_with_detail(c_switch_t *sw, struct flow *fl,
                              uint32_t wildcards, uint16_t prio)
{
#ifdef CONFIG_FLOW_EXM
    c_fl_entry_t *ent = NULL;

    if ((ent = of_flow_get_exm(sw, fl))) {
        return ent;
    }
#endif
    return of_do_flow_lookup_with_details(sw, fl, wildcards, prio);
}

void
of_flow_entry_put(c_fl_entry_t *ent)
{
    if (atomic_read(&ent->FL_REF) == 0) {
        if (ent->actions &&
            !(ent->FL_FLAGS & C_FL_ENT_CLONE))  {
            /* Cloned entry refs parent action list */
            free(ent->actions);
        }

        if (ent->app_owner_list) {
            g_slist_free_full(ent->app_owner_list, of_flow_app_ref_free);
            ent->app_owner_list = NULL;
        }

        free(ent);
        //c_log_debug("%s: Freed", FN);
    } else {
        atomic_dec(&ent->FL_REF, 1);
        //c_log_debug("%s: Ref dec", FN);
    }
}


static inline void
c_mcast_app_packet_in(c_switch_t *sw, struct cbuf *b,
                      c_fl_entry_t *fl_ent, struct flow *fl)
{
    void    *app;
    GSList  *iterator;

    c_rd_lock(&fl_ent->FL_LOCK);
    for (iterator = fl_ent->app_owner_list; iterator; iterator = iterator->next) {
        app = iterator->data;
        c_signal_app_event(sw, b, C_PACKET_IN, app, fl);
    }

    c_rd_unlock(&fl_ent->FL_LOCK);
}

int 
of_dfl_fwd(struct c_switch *sw, struct cbuf *b, void *data, size_t pkt_len,
           struct flow *fl, uint16_t in_port)
{
    struct of_pkt_out_params parms;
    c_fl_entry_t  *fl_ent;
    struct ofp_packet_in *opi = (void *)(b->data);

    if(!(fl_ent = of_do_flow_lookup(sw, fl))) {
        //c_log_debug("Flow lookup fail");
        return 0;
    }

    if (fl_ent->FL_ENT_TYPE != C_TBL_EXM &&
        fl_ent->FL_FLAGS & C_FL_ENT_CLONE) {
        fl_ent = of_flow_clone_exm(sw, fl, fl_ent);
    }

    if (fl_ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        c_mcast_app_packet_in(sw, b, fl_ent, fl);

        of_flow_entry_put(fl_ent);
        return 0;
    }

    of_send_flow_add(sw, fl_ent, ntohl(opi->buffer_id), true);

    parms.data       = 0;
    parms.data_len   = 0;
    parms.buffer_id  = ntohl(opi->buffer_id);
    parms.in_port    = in_port;
    parms.action_len = fl_ent->action_len;
    parms.action_list = fl_ent->actions;
    parms.data_len = pkt_len;
    parms.data = data;

    of_send_pkt_out(sw, &parms);
    of_flow_entry_put(fl_ent);

    return 0;
}

int
of_dfl_port_status(c_switch_t *sw UNUSED, uint32_t cfg UNUSED, uint32_t state UNUSED)
{
    /* Nothing to do for now */
    return 0;
}

static void __fastpath
of_recv_packet_in(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_packet_in *opi __aligned = (void *)(b->data);
    size_t               pkt_ofs, pkt_len;
    struct flow          fl;
    uint16_t             in_port = ntohs(opi->in_port);
    bool                 only_l2 = sw->fp_ops.fp_fwd == c_l2_lrn_fwd ? true : false;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;

    if(!sw->fp_ops.fp_fwd ||
        of_flow_extract(opi->data, &fl, in_port, pkt_len, only_l2) < 0) {
        return;
    }

    sw->fp_ops.fp_fwd(sw, b, opi->data, pkt_len, &fl, in_port);

    return;
}

static void
of_recv_echo_request(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_header *h = (void *)(b->data);

    return of_send_echo_reply(sw, h->xid);
}

static void
of_recv_echo_reply(c_switch_t *sw UNUSED, struct cbuf *b UNUSED)
{
    /* Nothing to do as timestamp is already updated */
}

static void
of_flow_removed(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct ofp_flow_removed     *ofm = (void *)(b->data);
    struct of_flow_mod_params   fl_parms;

    memset(&fl_parms, 0, sizeof(fl_parms));
    memset(&flow, 0, sizeof(flow));

    fl_parms.wildcards = ofm->match.wildcards;
    fl_parms.prio = ntohs(ofm->priority);

    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.nw_src = ofm->match.nw_src;
    flow.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.flow = &flow;
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;
    
    /*
     * It is upto the application to check what flows are removed
     * by the switch and inform the controller so the controller 
     * itself does not take any action 
     */
    c_signal_app_event(sw, b, C_FLOW_REMOVED, NULL, &fl_parms);
}

static void
of_recv_flow_mod_failed(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct ofp_error_msg        *ofp_err = (void *)(b->data);
    struct ofp_flow_mod         *ofm = (void *)(ofp_err->data);
    struct of_flow_mod_params   fl_parms;
    void                        *app;
    char                        *print_str;

    memset(&flow, 0, sizeof(flow));
    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.nw_src = ofm->match.nw_src;
    flow.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.wildcards = ofm->match.wildcards;
    fl_parms.flow = &flow;
    fl_parms.prio = ntohs(ofm->priority);
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;

    /* Controller owns only vty intalled static flows */
    if (!(app = c_app_get(sw->c_hdl, C_VTY_NAME))) {
        goto app_signal_out;
    }

    fl_parms.app_owner = app;
    of_flow_del(sw, &fl_parms);
    c_app_put(app);
    fl_parms.app_owner = NULL;

app_signal_out:
    /* We take a very conservative approach here and multicast
     * flow mod failed to all apps irrespective of they are owners
     * of this flow or not to maintain sanity because some apps
     * may implicitly use this flow for some operation
     */
    c_signal_app_event(sw, b, C_FLOW_MOD_FAILED, NULL, &fl_parms);

    print_str= of_dump_flow(&flow, fl_parms.wildcards);
    c_log_err("%s: flow-mod failed for flow:", FN);
    c_log_err("%s", print_str);
    free(print_str);

    return;
} 

static void
of_recv_err_msg(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_error_msg *ofp_err = (void *)(b->data);

    c_log_err("%s: switch 0x%llx sent error type %hu code %hu", FN, 
               sw->DPID, ntohs(ofp_err->type), ntohs(ofp_err->code));

    switch(ntohs(ofp_err->type)) {
    case OFPET_FLOW_MOD_FAILED:
        return of_recv_flow_mod_failed(sw, b);
    default:
        break;
    }
}

static int
of_flow_stats_update(c_switch_t *sw, struct ofp_flow_stats *ofp_stats)
{
    c_fl_entry_t    *ent;
    struct flow     flow;
    time_t          curr_time, time_diff;
    int             ret = ntohs(ofp_stats->length) - sizeof(*ofp_stats);;

    memset(&flow, 0, sizeof(flow));

    flow.in_port = ofp_stats->match.in_port;
    memcpy(flow.dl_src, ofp_stats->match.dl_src, sizeof ofp_stats->match.dl_src);
    memcpy(flow.dl_dst, ofp_stats->match.dl_dst, sizeof ofp_stats->match.dl_dst);
    flow.dl_vlan = ofp_stats->match.dl_vlan;
    flow.dl_type = ofp_stats->match.dl_type;
    flow.dl_vlan_pcp = ofp_stats->match.dl_vlan_pcp;
    flow.nw_src = ofp_stats->match.nw_src;
    flow.nw_dst = ofp_stats->match.nw_dst;
    flow.nw_proto = ofp_stats->match.nw_proto;
    flow.tp_src = ofp_stats->match.tp_src;
    flow.tp_dst = ofp_stats->match.tp_dst;

    ent = of_do_flow_lookup_with_detail(sw, &flow,
                    ofp_stats->match.wildcards, htons(ofp_stats->priority));

    if (!ent ||
        ret != ent->action_len ||
        (ret && memcmp(ofp_stats->actions, ent->actions, ent->action_len))) {
        char *fl_str;
        fl_str = of_dump_flow(&flow, ofp_stats->match.wildcards);
        c_log_err("%s: 0x%llx Unknown flow (%s) in stats reply",
                  FN, sw->DPID, fl_str);
        free(fl_str);
        if (ent) of_flow_entry_put(ent);
        return ret;
    }

    curr_time = time(NULL);
    time_diff = curr_time - ent->fl_stats.last_refresh; 

    if (ent->fl_stats.last_refresh && time_diff) {
        if (ntohll(ofp_stats->byte_count) >= ent->fl_stats.byte_count) {
            ent->fl_stats.bps = (double)(ntohll(ofp_stats->byte_count)
                                         - ent->fl_stats.byte_count)/time_diff;
        } else {
            c_log_err("%s: Byte count wrap around", FN);
        }
        if (ntohll(ofp_stats->packet_count) >= ent->fl_stats.pkt_count) {
            ent->fl_stats.pps = (double)(ntohll(ofp_stats->packet_count)
                                         - ent->fl_stats.pkt_count)/time_diff;
        } else {
            c_log_err("%s: Pkt count wrap around", FN);
        }
    }

    ent->fl_stats.byte_count = ntohll(ofp_stats->byte_count);
    ent->fl_stats.pkt_count = ntohll(ofp_stats->packet_count);
    ent->fl_stats.last_refresh = curr_time;

    of_flow_entry_put(ent);

    return ret;
}

static void
of_per_flow_stats_scan(void *time_arg, c_fl_entry_t *ent)
{
    time_t time = *(time_t *)time_arg;

    if ((ent->FL_ENT_TYPE != C_TBL_EXM &&
        ent->FL_FLAGS & C_FL_ENT_CLONE) || 
        ent->FL_FLAGS & C_FL_ENT_LOCAL) {
        return;
    }

    if (ent->FL_FLAGS & C_FL_ENT_GSTATS) 
        if (!ent->fl_stats.last_refresh || 
            ((time - ent->fl_stats.last_refresh) > C_FL_STAT_TIMEO)) {
            __of_send_flow_stat_req(ent->sw, &ent->fl, ent->FL_WILDCARDS, 
                                    OF_ALL_TABLES, 0);   
        }
}

void
of_per_switch_flow_stats_scan(c_switch_t *sw, time_t curr_time)
{
    of_flow_traverse_tbl_all(sw, (void *)&curr_time, of_per_flow_stats_scan);    
}
 
static void
of_recv_flow_mod(c_switch_t *sw, struct cbuf *b)
{
    struct flow                 flow;
    struct ofp_flow_mod         *ofm = (void *)(b->data);
    struct of_flow_mod_params   fl_parms;
    void                        *app;
    uint16_t                    command = ntohs(ofm->command);
    bool                        flow_add;

    if (!c_switch_is_virtual(sw)) {
        c_log_err("%s: Unexpected msg", FN);
        return;
    }

    switch (command) {
    case OFPFC_MODIFY_STRICT:
        flow_add = true;
        break;
    case OFPFC_DELETE:
    case OFPFC_DELETE_STRICT: 
        flow_add = false;
        break;
    default:
        c_log_err("%s: Unexpected flow mod command", FN);
        return;
    }

    memset(&flow, 0, sizeof(flow));
    flow.in_port = ofm->match.in_port;
    memcpy(flow.dl_src, ofm->match.dl_src, sizeof ofm->match.dl_src);
    memcpy(flow.dl_dst, ofm->match.dl_dst, sizeof ofm->match.dl_dst);
    flow.dl_vlan = ofm->match.dl_vlan;
    flow.dl_type = ofm->match.dl_type;
    flow.dl_vlan_pcp = ofm->match.dl_vlan_pcp;
    flow.nw_src = ofm->match.nw_src;
    flow.nw_dst = ofm->match.nw_dst;
    flow.nw_proto = ofm->match.nw_proto;
    flow.tp_src = ofm->match.tp_src;
    flow.tp_dst = ofm->match.tp_dst;

    fl_parms.wildcards = ofm->match.wildcards;
    fl_parms.flow = &flow;
    fl_parms.flags = (uint8_t)ntohl(ofm->buffer_id);
    fl_parms.prio = ntohs(ofm->priority);
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;
    if (flow_add) {
        fl_parms.action_len = ntohs(ofm->header.length) - sizeof(*ofm); 
        fl_parms.actions = calloc(1, fl_parms.action_len);
        memcpy(fl_parms.actions, ofm->actions, fl_parms.action_len);
    }

    /* Controller owns only vty intalled static flows */
    if (!(app = c_app_get(sw->c_hdl, C_VTY_NAME))) {
        c_log_err("%s: |PANIC| Native vty app not found", FN);
        return;
    }

    fl_parms.app_owner = app;
    if (flow_add) {
        of_flow_add(sw, &fl_parms);
    } else {
        of_flow_del(sw, &fl_parms);
    }
    c_app_put(app);
}
 
static void
of_recv_stats_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_stats_reply *ofp_sr = (void *)(b->data);
    int act_len = 0;

    switch(ntohs(ofp_sr->type)) {
    case OFPST_FLOW:
        {
            struct ofp_flow_stats *ofp_stats = (void *)(ofp_sr->body);
            size_t stat_length = ntohs(ofp_sr->header.length) - sizeof(*ofp_sr);

            while (stat_length) {
                act_len = of_flow_stats_update(sw, (void *)(ofp_stats));
                if (!act_len) break;
                ofp_stats = (void *)((uint8_t *)(ofp_stats + 1) + act_len);
                stat_length -= (sizeof(*ofp_stats) + act_len);
            }
            break;
        }
    default:
        c_log_err("%s: Unhandled stats reply 0x%x", FN, ntohs(ofp_sr->type));
        break;
    }

    return;
}

struct of_handler of_handlers[] __aligned = {
    NULL_OF_HANDLER,                                                /* OFPT_HELLO */
    { of_recv_err_msg, sizeof(struct ofp_error_msg), NULL },        /* OFPT_ERROR */
    { of_recv_echo_request, OFP_HDR_SZ, NULL },                     /* OFPT_ECHO_REQUEST */
    { of_recv_echo_reply, OFP_HDR_SZ, NULL },                       /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER,                                                /* OFPT_VENDOR */
    NULL_OF_HANDLER,                                                /* OFPT_FEATURES_REQUEST */
    { of_recv_features_reply, OFP_HDR_SZ, NULL},                    /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER,                                                /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER,                                                /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,                                                /* OFPT_SET_CONFIG */
    { of_recv_packet_in, sizeof(struct ofp_packet_in), NULL },      /* OFPT_PACKET_IN */
    { of_flow_removed, sizeof(struct ofp_flow_removed), NULL },     /* OFPT_FLOW_REMOVED */
    { of_recv_port_status, sizeof(struct ofp_port_status), NULL },  /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER,                                                /* OFPT_PACKET_OUT */
    NULL_OF_HANDLER,                                                /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER,                                                /* OFPT_PORT_MOD */
    NULL_OF_HANDLER,                                                /* OFPT_STATS_REQUEST */
    { of_recv_stats_reply, sizeof(struct ofp_stats_reply), NULL },  /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER,                                                /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER,                                                /* OFPT_BARRIER_REPLY */
};

void __fastpath
of_switch_recv_msg(void *sw_arg, struct cbuf *b)
{
    c_switch_t        *sw = sw_arg;
    struct ofp_header *oh;

    prefetch(&of_handlers[OFPT_PACKET_IN]);

    oh = (void *)b->data;

    //c_log_debug("OF MSG RX TYPE (%d)", oh->type);

    if (unlikely(sw->datapath_id == 0
        && oh->type != OFPT_ECHO_REQUEST
        && oh->type != OFPT_FEATURES_REPLY)) {
        of_send_features_request(sw);
        return;
    }

    sw->last_refresh_time = time(NULL);
    sw->conn.rx_pkts++;

    RET_OF_MSG_HANDLER(sw, of_handlers, b, oh->type, b->len);
}
