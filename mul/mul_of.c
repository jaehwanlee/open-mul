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

static void of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id);
static void of_send_flow_del(c_switch_t *sw, c_fl_entry_t *ent,
                             uint16_t oport, bool strict);
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
of_dump_flow(struct flow *fl, uint32_t wildcards)   
{   
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t ip_wc;

    wildcards = ntohl(wildcards);
    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 :
                           make_inet_mask(32-ip_wc);

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 :
                           make_inet_mask(32-ip_wc);

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (wildcards == OFPFW_ALL) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "All Fields Wildcards");
        assert(len < FL_PBUF_SZ-1);
        return pbuf;
    }

    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ", 
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ",
                     "eth-type", ntohs(fl->dl_type)); 
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ",
                     "vlan-id",  ntohs(fl->dl_vlan)); 
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ",
                     "vlan-pcp", ntohs(fl->dl_vlan_pcp));
        assert(len < FL_PBUF_SZ-1);

    }
    if (nw_dst_mask) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%08x ",
                     "dest-ip", ntohl(fl->nw_dst) & nw_dst_mask); 
        assert(len < FL_PBUF_SZ-1);
    }
    if (nw_src_mask) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%08x ",
                     "src-ip", ntohl(fl->nw_src) & nw_src_mask); 
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ",
                     "ip-proto", fl->nw_proto); 
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ",
                     "ip-tos", fl->nw_tos);  
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ", 
                    "src-port", ntohs(fl->tp_src)); 
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ", 
                    "dst-port", ntohs(fl->tp_dst)); 
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, 
                    "%s:0x%x ", 
                    "in-port", ntohs(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

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

static unsigned int
of_switch_hash_key (const void *p)
{
    c_switch_t *sw = (c_switch_t *) p;

    return (unsigned int)(sw->DPID);
}

static int 
of_switch_hash_cmp (const void *p1, const void *p2)
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

    c_wr_lock(&ctrl->lock);
    if (!ctrl->sw_hash_tbl) {
        ctrl->sw_hash_tbl = g_hash_table_new(of_switch_hash_key, 
                                             of_switch_hash_cmp);
    }

    g_hash_table_add(ctrl->sw_hash_tbl, sw);

    c_wr_unlock(&ctrl->lock);

}

void
of_switch_del(c_switch_t *sw)
{
    struct c_cmn_ctx *cmn_ctx = sw->ctx;
    ctrl_hdl_t *ctrl          = cmn_ctx->c_hdl;

    c_wr_lock(&ctrl->lock);
    if (ctrl->sw_hash_tbl) {
       g_hash_table_remove(ctrl->sw_hash_tbl, sw);
    }
    c_wr_unlock(&ctrl->lock);

    if (sw->conn.cbuf) {
        free_cbuf(sw->conn.cbuf);
        sw->conn.cbuf = NULL;
    }

    sw->switch_state = SW_DEAD;
    c_signal_app_event(sw, NULL, C_DP_UNREG, NULL, NULL);
}

void *
of_switch_alloc(void *ctx)
{
    c_switch_t *new_switch;

    new_switch = calloc(1, sizeof(c_switch_t));
    assert(new_switch);

    new_switch->switch_state = SW_INIT;
    new_switch->ctx = ctx;
    new_switch->last_refresh_time = g_get_monotonic_time();
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
        cbuf_list_purge(&sw->conn.tx_q);
        of_switch_flow_tbl_delete(sw);
        free(sw);
    } else {
        //c_log_debug("sw (0x:%llx) ref (%u)", sw->DPID, 
        //            (unsigned int)atomic_read(&sw->ref));
        atomic_dec(&sw->ref, 1);
    }
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

static int
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
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id);
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
            && ent->FL_WILDCARDS == wildcards) {
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
        of_send_flow_add(sw, new_ent, fl_parms->buffer_id);
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
        c_wr_unlock(&sw->lock);
        return -1;
    }

    /* FIXME : Take this ent and add to a tentative list 
     * If we get negative ack from switch add it back to flow
     * table else free it. 
     */
    ent = container_of(flow, c_fl_entry_t, fl);

    if (!(ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
        of_send_flow_del(sw, ent, 0, false);
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

    if (tbl->c_fl_tbl_type == C_TBL_EXM) {
        g_hash_table_foreach(tbl->exm_fl_hash_tbl,
                             (GHFunc)of_flow_exm_iter, &args);
    } else if (tbl->c_fl_tbl_type == C_TBL_RULE){
        g_slist_foreach(tbl->rule_fl_tbl, 
                        (GFunc)of_flow_rule_iter, &args);
    }

    c_rd_unlock(&sw->lock);
}

void 
of_flow_traverse_tbl_all(c_switch_t *sw, void *u_arg, flow_parser_fn fn)
{
    uint8_t       tbl_idx = 0;

    of_flow_traverse_tbl(sw, C_TBL_EXM, tbl_idx, u_arg, fn);

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
    tbl->exm_fl_hash_tbl =
                    g_hash_table_new_full(of_flow_exm_key,
                                          of_flow_exm_key_cmp,
                                          of_flow_exm_key_free,
                                          __of_flow_exm_release);
    assert(tbl->exm_fl_hash_tbl);
    tbl->c_fl_tbl_type = C_TBL_EXM;
    tbl->hw_tbl_idx = C_TBL_HW_IDX_DFL;

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
        }
    }

    tbl = &sw->exm_flow_tbl;
    if (tbl->exm_fl_hash_tbl) {
        g_hash_table_destroy(tbl->exm_fl_hash_tbl);
    }

    tbl = &sw->app_flow_tbl;
    if (tbl->exm_fl_hash_tbl && tbl->dtor) {
         tbl->dtor(sw, tbl);
    }

    c_wr_unlock(&sw->lock);
}

void
of_send_features_request(c_switch_t *sw)
{
    struct cbuf *b;

    /* Send OFPT_FEATURES_REQUEST. */
    b = of_prep_msg(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, 0);

    c_thread_tx(&sw->conn, b, true);
}

void
__of_send_features_request(c_switch_t *sw)
{
    of_send_features_request(sw);
    c_thread_sg_tx_sync(&sw->conn);
}

void
of_send_echo_request(c_switch_t *sw)
{
    struct cbuf *b;

    /* Send OFPT_ECHO_REQUEST. */
    b = of_prep_msg(sizeof(struct ofp_header), OFPT_ECHO_REQUEST, 0);

    c_thread_tx(&sw->conn, b, false);
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

    c_thread_tx(&sw->conn, b, false);
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

    c_thread_tx(&sw->conn, b, false);
}

void __fastpath
of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    struct cbuf           *b;

    b = of_prep_pkt_out_msg(parms);

    c_thread_tx(&sw->conn, b, true);
} 

void __fastpath
__of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms)
{
    of_send_pkt_out(sw, parms);
    c_thread_sg_tx_sync(&sw->conn);
}

static void
of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id)
{
    struct cbuf *b = of_prep_flow_add_msg(&ent->fl, buffer_id, ent->actions, 
                                          ent->action_len, ent->FL_ITIMEO,
                                          ent->FL_HTIMEO, ent->FL_WILDCARDS,
                                          ent->FL_PRIO);
    c_thread_tx(&sw->conn, b, true);
} 

static void UNUSED
__of_send_flow_add(c_switch_t *sw, c_fl_entry_t *ent, uint32_t buffer_id)
{
    of_send_flow_add(sw, ent, buffer_id);
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
    c_thread_tx(&sw->conn, b, true);

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
    c_thread_tx(&sw->conn, b, true);
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

    c_thread_tx(&sw->conn, b, true);

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
        if (!(sw->ports[port_no].valid & OFC_SW_PORT_VALID)) {
            /* Nothing to do */
            return;
        }

        memset (&sw->ports[port_no], 0, sizeof(struct ofp_phy_port));
        return;
    case OFPPR_ADD:
    case OFPPR_MODIFY:
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

    of_process_phy_port(sw, &ops->desc, ops->reason, &chg_mask);

    c_signal_app_event(sw, b, C_PORT_CHANGE, NULL, &chg_mask);
}

static void
of_recv_features_reply(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_switch_features  *osf = (void *)(b->data);
    size_t                       n_ports, i;

    n_ports = ((ntohs(osf->header.length)
                - offsetof(struct ofp_switch_features, ports))
            / sizeof *osf->ports);

    sw->datapath_id = ntohll(osf->datapath_id);
    sw->version     = osf->header.version;
    sw->n_buffers   = ntohl(osf->n_buffers);
    sw->n_tables    = osf->n_tables;
    sw->actions     = ntohl(osf->actions);
    sw->capabilities = ntohl(osf->capabilities);

    for (i = 0; i < n_ports; i++) {
        of_process_phy_port(sw, &osf->ports[i], OFPPR_ADD, NULL);
    }

    of_switch_flow_tbl_create(sw);

    sw->n_ports = n_ports;

    if (sw->switch_state != SW_REGISTERED) {
        of_switch_add(sw);
        sw->switch_state = SW_REGISTERED;
        sw->last_sample_time = g_get_monotonic_time();
        sw->fp_ops.fp_fwd = of_dfl_fwd;
        sw->fp_ops.fp_port_status = of_dfl_port_status;

        c_signal_app_event(sw, b, C_DP_REG, NULL, NULL);
    }
}

int __fastpath
of_flow_extract(uint8_t *pkt, struct flow *flow, 
                uint16_t in_port, size_t pkt_len)
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

    memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
    memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

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

    of_send_flow_add(sw, fl_ent, ntohl(opi->buffer_id));

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

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;

    if(!sw->fp_ops.fp_fwd || of_flow_extract(opi->data, &fl, in_port, pkt_len) < 0) {
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
    
    c_signal_app_event(sw, b, C_FLOW_REMOVED, NULL, &fl_parms);
}

static void
of_recv_err_msg(c_switch_t *sw, struct cbuf *b)
{
    struct ofp_error_msg    *ofp_err = (void *)(b->data);

    c_log_err("%s: switch 0x%llx sent error type %hu code %hu", FN, 
               sw->DPID, ntohs(ofp_err->type), ntohs(ofp_err->code));

    switch(ntohs(ofp_err->type)) {
    case OFPET_FLOW_MOD_FAILED:
        {
            struct flow flow;
            char *print_str;
            struct ofp_flow_mod *ofm = (void *)(ofp_err->data);
            uint32_t wildcards = ofm->match.wildcards;

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

            print_str= of_dump_flow(&flow, wildcards);
            c_log_debug("%s", print_str);
            free(print_str);
            break;
        }
    default:
        break;
    }
}

struct of_handler of_handlers[] __aligned = {
    NULL_OF_HANDLER,                                            /* OFPT_HELLO */
    { of_recv_err_msg, sizeof(struct ofp_error_msg) },          /* OFPT_ERROR */
    { of_recv_echo_request, OFP_HDR_SZ },                       /* OFPT_ECHO_REQUEST */
    { of_recv_echo_reply, OFP_HDR_SZ },                         /* OFPT_ECHO_REPLY */
    NULL_OF_HANDLER,                                            /* OFPT_VENDOR */
    NULL_OF_HANDLER,                                            /* OFPT_FEATURES_REQUEST */
    { of_recv_features_reply, OFP_HDR_SZ },                     /* OFPT_FEATURES_REPLY */
    NULL_OF_HANDLER,                                            /* OFPT_GET_CONFIG_REQUEST */
    NULL_OF_HANDLER,                                            /* OFPT_GET_CONFIG_REPLY */
    NULL_OF_HANDLER,                                            /* OFPT_SET_CONFIG */
    { of_recv_packet_in, sizeof(struct ofp_packet_in) },        /* OFPT_PACKET_IN */
    { of_flow_removed, sizeof(struct ofp_flow_removed) },       /* OFPT_FLOW_REMOVED */
    { of_recv_port_status, sizeof(struct ofp_port_status) },    /* OFPT_PORT_STATUS */
    NULL_OF_HANDLER,                                            /* OFPT_PACKET_OUT */
    NULL_OF_HANDLER,                                            /* OFPT_FLOW_MOD */
    NULL_OF_HANDLER,                                            /* OFPT_PORT_MOD */
    NULL_OF_HANDLER,                                            /* OFPT_STATS_REQUEST */
    NULL_OF_HANDLER,                                            /* OFPT_STATS_REPLY */
    NULL_OF_HANDLER,                                            /* OFPT_BARRIER_REQUEST */
    NULL_OF_HANDLER,                                            /* OFPT_BARRIER_REPLY */
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

    sw->last_refresh_time = g_get_monotonic_time();
    sw->conn.rx_pkts++;

    RET_OF_MSG_HANDLER(sw, of_handlers, b, oh->type, b->len);
}
    
int
of_ctrl_init(ctrl_hdl_t *c_hdl, size_t nthreads, size_t n_appthreads)
{
    memset (c_hdl, 0, sizeof(ctrl_hdl_t));
    c_rw_lock_init(&c_hdl->lock);

    c_hdl->worker_ctx_list = (struct c_cmn_ctx **)malloc(nthreads * sizeof(void *));
    assert(c_hdl->worker_ctx_list);

    c_hdl->n_threads = nthreads;
    c_hdl->n_appthreads = n_appthreads;

    return 0;
}
