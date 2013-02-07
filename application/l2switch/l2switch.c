/*
 *  l2switch.c: L2switch application for MUL Controller 
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
#include "config.h"
#include "mul_common.h"
#include "mul_vty.h"
#include "l2switch.h"

l2port_t *l2sw_port_find(l2sw_t *sw, uint16_t port_no);
int l2sw_mod_flow(void *arg, l2sw_t *l2sw, l2fdb_ent_t *fdb, 
                  bool add_del, uint32_t buffer_id);
static void l2sw_install_dfl_flows(uint64_t dpid);
static void l2_slist_ent_free(void *arg);

l2sw_hdl_t *l2sw_hdl;

#ifndef CONFIG_L2SW_FDB_CACHE
static int
l2sw_set_fp_ops(l2sw_t *l2sw)
{
    c_ofp_set_fp_ops_t  *cofp_fp;
    struct cbuf         *b;

    b = of_prep_msg(sizeof(*cofp_fp), C_OFPT_SET_FPOPS, 0);

    cofp_fp = (void *)(b->data);
    cofp_fp->datapath_id = htonll(l2sw->swid); 
    cofp_fp->fp_type = htonl(C_FP_TYPE_L2);

    return mul_app_command_handler(L2SW_APP_NAME, b);
}
#endif

static inline void    
l2sw_put(l2sw_t *sw)
{                                               
    if (atomic_read(&sw->ref) == 0){            
        if (sw->l2fdb_htbl) g_hash_table_destroy(sw->l2fdb_htbl);
        if (sw->port_list) g_slist_free_full(sw->port_list, l2_slist_ent_free);
        free(sw);
    } else {
        atomic_dec(&sw->ref, 1);
    }
}           

static void
l2sw_free(void *arg)
{
    l2sw_put((l2sw_t *)arg);
}

static void
l2_slist_ent_free(void *arg)
{
    free(arg);
}

static unsigned int 
l2fdb_key(const void *p)
{   
    const uint8_t *mac_da = p;
    
    return hash_bytes(mac_da, OFP_ETH_ALEN, 1);
}

static int
l2fdb_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, OFP_ETH_ALEN);
}

static int
l2port_equal(const void *p1, const void *p2)
{
    return !(((l2port_t *)p1)->port_no == *(uint16_t *)(p2));
}

l2port_t *
l2sw_port_find(l2sw_t *sw, uint16_t port_no)
{
    GSList   *iterator;
    l2port_t *port = NULL;

    c_rd_lock(&sw->lock);

    iterator = g_slist_find_custom(sw->port_list, &port_no, l2port_equal);
    if (iterator) {
        port = iterator->data;
    }
    
    c_rd_unlock(&sw->lock);

    return port;
}

static l2port_t *
__l2sw_port_find(l2sw_t *sw, uint16_t port_no)
{
    GSList   *iterator;
    l2port_t *port = NULL;

    iterator = g_slist_find_custom(sw->port_list, &port_no, l2port_equal);
    if (iterator) {
        port = iterator->data;
    }
    
    return port;
}

static int
__l2sw_port_del(l2sw_t *sw, l2port_t *port)
{
    sw->port_list = g_slist_remove(sw->port_list, port);

    return 0;
}

static void 
l2port_traverse_all(l2sw_t *l2sw, GFunc iter_fn, void *arg) 
{

    c_rd_lock(&l2sw->lock);
    if (l2sw->port_list) {
        g_slist_foreach(l2sw->port_list, (GFunc)iter_fn, arg);
    }
    c_rd_unlock(&l2sw->lock);

    return;
}

#ifdef CONFIG_L2SW_FDB_CACHE
static int
check_l2port_down_l2sw_fdb(void *key UNUSED, void *ent, void *u_arg)
{
    l2fdb_ent_t                 *fdb = ent;
    struct l2sw_fdb_port_args   *args = u_arg;
    l2sw_t                      *l2sw = args->sw;

    if (fdb->lrn_port != args->port) {
        return 0;
    }

    l2sw_mod_flow(NULL, l2sw, fdb, false, L2SW_UNK_BUFFER_ID);
    return 1;
}
#endif

static void 
l2sw_traverse_all(l2sw_hdl_t *l2sw_hdl, GHFunc iter_fn, void *arg) 
{

    c_rd_lock(&l2sw_hdl->lock);
    if (l2sw_hdl->l2sw_htbl) {
        g_hash_table_foreach(l2sw_hdl->l2sw_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&l2sw_hdl->lock);

    return;
}

static int 
l2sw_add(l2sw_hdl_t *l2sw_hdl, uint64_t dpid, c_ofp_switch_add_t *cofp_sa)
{
    uint32_t    n_ports, idx = 0;
    l2sw_t      *l2sw = NULL;

    n_ports =  ((ntohs(cofp_sa->header.length)
                - offsetof(c_ofp_switch_add_t, ports))
               / sizeof *cofp_sa->ports); 

    c_wr_lock(&l2sw_hdl->lock);
    if (g_hash_table_lookup(l2sw_hdl->l2sw_htbl, &dpid)) {
        c_wr_unlock(&l2sw_hdl->lock);
        c_log_err("%s: sw(0x%llx) exists", FN, (unsigned long long)dpid);
        return -1;
    }

    if (!(l2sw = calloc(1, sizeof(*l2sw)))) {
        c_wr_unlock(&l2sw_hdl->lock);
        c_log_err("%s: l2sw alloc failed", FN);
        return -1;
    }
    
    l2sw->swid = dpid;
    l2sw->l2fdb_htbl = g_hash_table_new_full(l2fdb_key,
                                             l2fdb_equal,
                                             NULL,
                                             l2_slist_ent_free);
    assert(l2sw->l2fdb_htbl);

    for (; idx < n_ports; idx++) {
        struct ofp_phy_port *opp = &cofp_sa->ports[idx]; 
        l2port_t *port = calloc(1, sizeof(l2port_t));

        port->port_no = ntohs(opp->port_no);
        port->state = ntohl(opp->state);
        port->config = ntohl(opp->config);
        l2sw->port_list = g_slist_append(l2sw->port_list, port);        
    }

    c_rw_lock_init(&l2sw->lock);
    atomic_inc(&l2sw->ref, 1);

    g_hash_table_insert(l2sw_hdl->l2sw_htbl, &l2sw->swid, l2sw);
    c_wr_unlock(&l2sw_hdl->lock);

#ifndef CONFIG_L2SW_FDB_CACHE
    /* Let controller handle exception forwarding */
    l2sw_set_fp_ops(l2sw);
#endif

    /* Add flood flows for this switch eg Brdcast, mcast etc */
    l2sw_install_dfl_flows(dpid);

    l2sw_put(l2sw);

    c_log_debug("L2 Switch 0x%llx added", (unsigned long long)dpid);

    return 0;
}

static void
l2sw_install_dfl_flows(uint64_t dpid)
{
    struct flow                 fl;

    memset(&fl, 0, sizeof(fl));

    /* Clear all entries for this switch */
    mul_app_send_flow_del(L2SW_APP_NAME, NULL, dpid, &fl,
                          OFPFW_ALL, OFPP_NONE, 0, C_FL_ENT_NOCACHE);

    /* Zero DST MAC Drop */
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, L2SW_UNK_BUFFER_ID,
                          NULL, 0, 0, 0, OFPFW_ALL & ~(OFPFW_DL_DST),
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Zero SRC MAC Drop */
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, L2SW_UNK_BUFFER_ID,
                          NULL, 0, 0, 0, OFPFW_ALL & ~(OFPFW_DL_SRC),
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

    /* Broadcast SRC MAC Drop */
    memset(&fl.dl_src, 0xff, OFP_ETH_ALEN);
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, L2SW_UNK_BUFFER_ID,
                          NULL, 0, 0, 0, OFPFW_ALL & ~(OFPFW_DL_SRC),
                          C_FL_PRIO_DRP, C_FL_ENT_NOCACHE);

#ifdef CONFIG_L2SW_FDB_CACHE
    /* Send any unknown flow to app */
    memset(&fl, 0, sizeof(fl));
    mul_app_send_flow_add(L2SW_APP_NAME, NULL, dpid, &fl, L2SW_UNK_BUFFER_ID,
                          NULL, 0, 0, 0, OFPFW_ALL, C_FL_PRIO_DFL, 
                          C_FL_ENT_LOCAL);
#endif
}


static int l2sw_del(l2sw_hdl_t *l2sw_hdl, uint64_t dpid)
{
    c_wr_lock(&l2sw_hdl->lock);

    g_hash_table_remove(l2sw_hdl->l2sw_htbl, &dpid);

    c_wr_unlock(&l2sw_hdl->lock);

    c_log_debug("L2 Switch 0x%llx removed", (unsigned long long)dpid);
    return 0;
}


int 
l2sw_mod_flow(void *arg, l2sw_t *l2sw, l2fdb_ent_t *fdb, 
              bool add, uint32_t buffer_id)
{
    struct ofp_action_output    op_act, *p_op_act = NULL;
    uint32_t                    wildcards = OFPFW_ALL;
    struct flow                 fl = { 0 , 0, 0, 0, 0, 0, 0, 
                                      { 0, 0, 0, 0, 0, 0} ,
                                      { 0, 0, 0, 0, 0, 0} ,
                                      0, 0, 0, { 0, 0, 0 },
                                      };
    wildcards &= ~(OFPFW_DL_DST);
    memcpy(&fl.dl_dst, fdb->mac_da, OFP_ETH_ALEN);

    if (add) { 
        p_op_act = &op_act;
        of_make_action_output((char **)&p_op_act, 
                              sizeof(struct ofp_action_output),
                              fdb->lrn_port);
        mul_app_send_flow_add(L2SW_APP_NAME, arg, l2sw->swid, &fl, buffer_id,
                              p_op_act, sizeof(struct ofp_action_output),
                              L2FDB_ITIMEO_DFL, L2FDB_HTIMEO_DFL,
                              wildcards, C_FL_PRIO_DFL, C_FL_ENT_NOCACHE);
    } else {
        mul_app_send_flow_del(L2SW_APP_NAME, arg, l2sw->swid, &fl,
                              wildcards, OFPP_NONE, C_FL_PRIO_DFL, C_FL_ENT_NOCACHE);
    }

    return 0;
}

static int __fastpath
l2sw_learn_and_fwd(void *opaque_c_arg, 
                   l2sw_hdl_t *l2sw_hdl, uint64_t dpid,
                   struct flow *fl, struct cbuf *pkt)
{
    l2sw_t                      *l2sw = NULL;
#ifdef CONFIG_L2SW_FDB_CACHE
    l2fdb_ent_t                 *fdb;
#endif
    uint32_t                    oport = OFPP_ALL;
    size_t                      pkt_len, pkt_ofs;
    struct of_pkt_out_params    parms;
    struct ofp_action_output    op_act;
    struct c_ofp_packet_in      *opi =(void *)(pkt->data);

    /* Check packet validity */
    if (is_zero_ether_addr(fl->dl_src) || 
        is_zero_ether_addr(fl->dl_dst) ||
        is_multicast_ether_addr(fl->dl_src) || 
        is_broadcast_ether_addr(fl->dl_src)) {
        c_log_debug("%s: Invalid src/dst mac addr", FN);
        return -1;
    }

    pkt_ofs = offsetof(struct c_ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;

    c_rd_lock(&l2sw_hdl->lock);
    if (!(l2sw = g_hash_table_lookup(l2sw_hdl->l2sw_htbl, &dpid))) {
        c_rd_unlock(&l2sw_hdl->lock);
        c_log_err("%s: sw(0x%llx) does not exist", FN, (unsigned long long)dpid);
        return -1;
    }

    atomic_inc(&l2sw->ref, 1);
    c_rd_unlock(&l2sw_hdl->lock);

#ifdef CONFIG_L2SW_FDB_CACHE
    c_wr_lock(&l2sw->lock);
    fdb = g_hash_table_lookup(l2sw->l2fdb_htbl, fl->dl_src);
    if (fdb) { 
        /* Station moved ? */
        if (ntohs(fl->in_port) != fdb->lrn_port) {
            l2sw_mod_flow(opaque_c_arg, l2sw, fdb, false, (uint32_t)(-1));
            fdb->lrn_port = ntohs(fl->in_port); 
            l2sw_mod_flow(opaque_c_arg, l2sw, fdb, true, (uint32_t)(-1));
        }  

        goto l2_fwd;
    }
    fdb = malloc(sizeof(*fdb));
    memcpy(fdb->mac_da, fl->dl_src, OFP_ETH_ALEN);
    fdb->lrn_port = ntohs(fl->in_port);
    g_hash_table_insert(l2sw->l2fdb_htbl, fdb->mac_da, fdb);

l2_fwd:

    fdb = g_hash_table_lookup(l2sw->l2fdb_htbl, fl->dl_dst);
    if (fdb) { 
        oport = fdb->lrn_port;
        l2sw_mod_flow(opaque_c_arg, l2sw, fdb, true, L2SW_UNK_BUFFER_ID);
    } 
    c_wr_unlock(&l2sw->lock);
#endif

    l2sw_put(l2sw); 

    if (opi->buffer_id != L2SW_UNK_BUFFER_ID) {
        pkt_len = 0;
    }

    parms.buffer_id = ntohl(opi->buffer_id);
    parms.in_port = ntohs(opi->in_port);
    parms.action_list = &op_act;
    of_make_action_output((char **)&parms.action_list, sizeof(op_act), oport);
    parms.action_len = sizeof(op_act);
    parms.data_len = pkt_len;
    parms.data = opi->data;
    mul_app_send_pkt_out(opaque_c_arg, l2sw->swid, &parms);

    return 0;
}

static int
__l2sw_fdb_traverse_all(l2sw_t *l2sw, GHFunc iter_fn, void *arg) 
{
    if (l2sw->l2fdb_htbl) {
        g_hash_table_foreach(l2sw->l2fdb_htbl,
                             (GHFunc)iter_fn, arg);
    }

    return 0;
}


#ifdef CONFIG_L2SW_FDB_CACHE
static int 
__l2sw_fdb_del_all_with_inport(l2sw_t *l2sw, uint16_t in_port) 
{
    struct l2sw_fdb_port_args args;

    args.sw = l2sw;
    args.port = in_port;
    g_hash_table_foreach_remove(l2sw->l2fdb_htbl, check_l2port_down_l2sw_fdb,
                                (void *)&args);
    
    return 0;
}

#else

static int 
__l2sw_fdb_del_all_with_inport(l2sw_t *l2sw, uint16_t in_port) 
{
    c_ofp_flow_mod_t            *cofp_fm;
    uint32_t                    wildcards = OFPFW_ALL;
    struct cbuf                 *b;

    b = of_prep_msg(sizeof(*cofp_fm), C_OFPT_FLOW_MOD, 0);

    cofp_fm = (void *)(b->data);
    cofp_fm->datapath_id = htonll(l2sw->swid);
    cofp_fm->command = C_OFPC_DEL;
    cofp_fm->flags = C_FL_ENT_NOCACHE;
    cofp_fm->wildcards = htonl(wildcards);
    cofp_fm->itimeo = htons(L2FDB_ITIMEO_DFL);
    cofp_fm->htimeo = htons(L2FDB_HTIMEO_DFL);
    cofp_fm->buffer_id = (uint32_t)(-1);
    cofp_fm->oport = htons(in_port);

    return mul_app_command_handler(L2SW_APP_NAME, b);
}
#endif

static void 
l2sw_port_handler(l2sw_hdl_t *l2sw_hdl, uint64_t dpid, 
                  c_ofp_port_status_t *ofp_psts) 
{
    l2sw_t              *l2sw;
    l2port_t            *port;
    uint16_t            in_port = 0;
    uint32_t            config_mask, state_mask;
    struct ofp_phy_port *ofpp = &ofp_psts->desc;

    config_mask = ntohl(ofp_psts->config_mask);
    state_mask  = ntohl(ofp_psts->state_mask);
    in_port     = ntohs(ofp_psts->desc.port_no);

    c_rd_lock(&l2sw_hdl->lock);
    if (!(l2sw = g_hash_table_lookup(l2sw_hdl->l2sw_htbl, &dpid))) {
        c_rd_unlock(&l2sw_hdl->lock);
        c_log_err("%s: sw(0x%llx) does not exist", FN, (unsigned long long)dpid);
        return; 
    }

    atomic_inc(&l2sw->ref, 1);
    c_rd_unlock(&l2sw_hdl->lock);

    /* Process the port change */
    c_wr_lock(&l2sw->lock);
    port = __l2sw_port_find(l2sw, in_port);    

    switch(ofp_psts->reason) {
    case OFPPR_ADD:
        if (!port) {
            port = calloc(1, sizeof(*port));
            l2sw->port_list = g_slist_append(l2sw->port_list, port);
        }
        port->port_no = ntohs(ofpp->port_no);
        /* Fall through */
    case OFPPR_MODIFY:
        if (port) {
            port->state = ntohl(ofpp->state);
            port->config = ntohl(ofpp->config);
        }
        break;
    case OFPPR_DELETE:
        if (port) __l2sw_port_del(l2sw, port); 
        break;
    default:
        c_log_err("%s: unknown port change code", FN);
        return;
    }

    if (config_mask & OFPPC_PORT_DOWN ||
        state_mask & OFPPS_LINK_DOWN) { 
        __l2sw_fdb_del_all_with_inport(l2sw, in_port);
    }

    c_wr_unlock(&l2sw->lock);
    l2sw_put(l2sw); 
}

static void __fastpath
l2sw_event_notifier(void *app_arg, void *pkt_arg)
{
    struct cbuf         *b = pkt_arg;
    struct ofp_header   *hdr;

    if (!b) {
        c_log_err("%s: Invalid arg", FN);
        return;
    }

    hdr = (void *)(b->data);

    switch(hdr->type) {
    case C_OFPT_SWITCH_ADD: 
        {
            c_ofp_switch_add_t *ofp_sa = (void *)(hdr);
            l2sw_add(l2sw_hdl, ntohll(ofp_sa->datapath_id), ofp_sa);
            break;
        }
    case C_OFPT_SWITCH_DELETE:
        {
            c_ofp_switch_delete_t *ofp_sd = (void *)(hdr);
            l2sw_del(l2sw_hdl, ntohll(ofp_sd->datapath_id));
            break;
        }
    case C_OFPT_PACKET_IN:
        {
            c_ofp_packet_in_t *ofp_pin = (void *)(hdr);

            l2sw_learn_and_fwd(app_arg, l2sw_hdl, ntohll(ofp_pin->datapath_id),
                               &ofp_pin->fl, b);
            break;
        }
    case C_OFPT_PORT_STATUS:
        {
            c_ofp_port_status_t *ofp_psts = (void *)(hdr);

            l2sw_port_handler(l2sw_hdl, ntohll(ofp_psts->datapath_id), 
                              ofp_psts);
            break;
        }
    case C_OFPT_RECONN_APP:
        mul_register_app(NULL, L2SW_APP_NAME,
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, l2sw_event_notifier);
        break;
    case C_OFPT_NOCONN_APP: 
        /* 
         * FIXME : This is not optimal. What we really need is 
         * wait for reconn and stale out switches which might go
         * during wait period. And the delete all fdbs for existing
         * switches which we might have learnt to maintain coherency.
         */
        g_hash_table_remove_all(l2sw_hdl->l2sw_htbl); 
        break;
    default:
        return;
    }
}

/* Housekeep Timer for app monitoring */
static void
l2sw_main_timer(evutil_socket_t fd UNUSED, short event UNUSED,
                void *arg)
{
    l2sw_hdl_t     *hdl  = arg;
    struct timeval tv    = { 1 , 0 };

    evtimer_add(hdl->l2sw_timer_event, &tv);
}  

void
l2sw_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { 1, 0 };
    l2sw_hdl_t        *hdl = NULL;

    c_log_debug("%s", FN);

    hdl = calloc(1, sizeof(l2sw_hdl_t));
    if (!hdl) {
        c_log_err("%s: alloc failed", FN);
        return;
    }

    hdl->base = base;
    c_rw_lock_init(&hdl->lock);
    hdl->l2sw_htbl = g_hash_table_new_full(g_int64_hash,
                                           g_int64_equal,
                                           NULL, l2sw_free);

    hdl->l2sw_timer_event = evtimer_new(base,
                                        l2sw_main_timer,
                                        (void *)hdl);
    evtimer_add(hdl->l2sw_timer_event, &tv);
    l2sw_hdl = hdl;

    mul_register_app(NULL, L2SW_APP_NAME, 
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, l2sw_event_notifier);

    return;
}

static void
show_l2port_info(void *port_arg, void *uarg)
{
    l2port_t    *port = port_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "%hu(%x:%x) ", port->port_no, 
            !(port->config & OFPPC_PORT_DOWN), 
            !(port->state & OFPPS_LINK_DOWN)); 
}

static void
show_l2sw_info(void *key UNUSED, void *sw_arg, void *uarg)
{
    l2sw_t      *sw = sw_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "0x%-16llx ", (unsigned long long)sw->swid); 
    l2port_traverse_all(sw, show_l2port_info, vty);
    vty_out(vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
}

static void
show_l2sw_fdb_info(void *key UNUSED, void *fdb_arg, void *uarg)
{
    l2fdb_ent_t *fdb = fdb_arg;
    struct vty  *vty = uarg;

    vty_out(vty, "%02x:%02x:%02x:%02x:%02x:%02x %5hu%s", 
            fdb->mac_da[0], fdb->mac_da[1], fdb->mac_da[2],
            fdb->mac_da[3], fdb->mac_da[4], fdb->mac_da[5],
            fdb->lrn_port, VTY_NEWLINE);
}

DEFUN (show_l2sw,
       show_l2sw_cmd,
       "show l2-switch all",
       SHOW_STR
       "L2 switches\n"
       "Summary information for all")
{

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    vty_out(vty, "%10s %18s %s%s", "l2sw-id", 
            "Port-list","<port-num>(admin:link)", VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    l2sw_traverse_all(l2sw_hdl, show_l2sw_info, vty);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_l2sw_fdb,
       show_l2sw_fdb_cmd,
       "show l2-switch X fdb",
       SHOW_STR
       "L2 switches\n"
       "Datapath-id in 0xXXX format\n"
       "Learned Forwarding database\n")
{
    uint64_t    swid;
    l2sw_t      *l2sw;

    swid = strtoull(argv[0], NULL, 16);

    c_rd_lock(&l2sw_hdl->lock);
    if (!(l2sw = g_hash_table_lookup(l2sw_hdl->l2sw_htbl, &swid))) {
        c_rd_unlock(&l2sw_hdl->lock);
        vty_out(vty, "sw(0x%llx) does not exist", (unsigned long long)swid);
        return CMD_WARNING;
    }

    atomic_inc(&l2sw->ref, 1);
    c_rd_unlock(&l2sw_hdl->lock);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    vty_out (vty, "%8s %18s%s", "mac", "lrn_port", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    c_rd_lock(&l2sw_hdl->lock);
    __l2sw_fdb_traverse_all(l2sw, show_l2sw_fdb_info, vty);
    c_rd_unlock(&l2sw_hdl->lock);

    l2sw_put(l2sw);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

void
l2sw_module_vty_init(void *arg UNUSED)
{
    c_log_debug("%s:", FN);
    install_element(ENABLE_NODE, &show_l2sw_cmd);
    install_element(ENABLE_NODE, &show_l2sw_fdb_cmd);
}

module_init(l2sw_module_init);
module_vty_init(l2sw_module_vty_init);
