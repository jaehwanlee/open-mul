/*
 *  mul_fabric.c: Fabric application for MUL Controller 
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
#include "mul_fabric_common.h"

fab_struct_t *fab_ctx;

/** 
 * fab_timer_event -
 *
 * timer for handling fabric events 
 */
static void
fab_timer_event(evutil_socket_t fd UNUSED, short event UNUSED,
                void *arg)
{
    fab_struct_t    *fab_ctx  = arg;
    struct timeval  tv    = { FAB_TIMER_SEC_INT, FAB_TIMER_USEC_INT};

    fab_route_per_sec_timer(fab_ctx);

    evtimer_add(fab_ctx->fab_timer_event, &tv);
}

/** 
 * fab_pkt_rcv -
 *
 * Handler for packet receive events 
 */
static void
fab_pkt_rcv(void *opq, fab_struct_t *fab_ctx, c_ofp_packet_in_t *pin)
{
    fab_learn_host(opq, fab_ctx, pin);
}

/** 
 * fab_switch_add_notifier -
 *
 * Handler for switch add/join event
 */
static void
fab_switch_add_notifier(void *opq, fab_struct_t *fab_ctx,
                        c_ofp_switch_add_t *ofp_sa)
{
    size_t num_port;
    int i = 0, ret = -1;
    struct ofp_phy_port *port;

    c_wr_lock(&fab_ctx->lock);
    if ((ret = __fab_switch_add(fab_ctx, ntohll(ofp_sa->datapath_id), 
                         C_GET_ALIAS_IN_SWADD(ofp_sa)))) {
        c_log_err("%s: Switch(0x%llx) add failed", 
                  FN, ntohll(ofp_sa->datapath_id));
        c_wr_unlock(&fab_ctx->lock);
        return;
    }

    num_port = ( ntohs((ofp_sa->header).length) -
                sizeof(c_ofp_switch_add_t) ) / sizeof(struct ofp_phy_port);

    for (i = 0; i < num_port; i++){
        port = &((struct ofp_phy_port *) &(ofp_sa[1]))[i];
        __fab_port_add(fab_ctx, 
                       __fab_switch_find(fab_ctx, C_GET_ALIAS_IN_SWADD(ofp_sa)),
                       ntohs(port->port_no));
    }

    __fab_activate_all_hosts_on_switch(fab_ctx, ntohll(ofp_sa->datapath_id));

    c_wr_unlock(&fab_ctx->lock);
}


/** 
 * fab_switch_delete_notifier -
 *
 * Handler for switch delete/leave event
 */
void
fab_switch_delete_notifier(fab_struct_t *fab_ctx, int sw_alias, bool locked)
{
    fab_switch_t *sw;

    if (!locked) c_wr_lock(&fab_ctx->lock);

    sw = __fab_switch_find(fab_ctx, sw_alias);
    if (!sw) {
        c_log_err("%s: Switch(alias %d) not found", FN, sw_alias);
        if (!locked) c_wr_unlock(&fab_ctx->lock);
        return;
    }

    __fab_delete_all_hosts_on_switch(fab_ctx, sw->dpid);
    __fab_switch_del(fab_ctx, sw_alias);

    if (!locked) c_wr_unlock(&fab_ctx->lock);
}

/** 
 * fab_recv_err_msg -
 *
 * Handler for error notifications from controller/switch 
 */
static void
fab_recv_err_msg(fab_struct_t *fab_ctx UNUSED, c_ofp_error_msg_t *cofp_err)
{
    c_log_err("%s: Controller sent error type %hu code %hu", FN,
               ntohs(cofp_err->type), ntohs(cofp_err->code));

    /* FIXME : Handle errors */
}

/**
 * fab_port_status_handler -
 *
 * Handler for port status update events
 */
static void
fab_port_status_handler(void *opq UNUSED, fab_struct_t *fab_ctx,
                        c_ofp_port_status_t *port_stat)
{
    uint32_t config, state;
    uint32_t config_mask, state_mask;
    uint16_t port_no;

    port_no = ntohs(port_stat->desc.port_no);
    if (port_no > OFPP_MAX){
        /* ignore control ports */
        return;
    }

    config = ntohl(port_stat->desc.config);
    config_mask = ntohl(port_stat->config_mask);
    state = ntohl(port_stat->desc.state);
    state_mask = ntohl(port_stat->state_mask);

    c_log_debug("%s: Port %hu admin %s link %s\n", FN, port_no,
                (config & OFPPC_PORT_DOWN)? "down": "up",
                (state & OFPPS_LINK_DOWN)? "down" : "up");

    switch (port_stat->reason){
    case OFPPR_ADD:
        /* We can aggresively timeout the existing routes or recalc routes
          and compare based on which old and inferior routes can be deleted */
        c_wr_lock(&fab_ctx->lock);
        __fab_port_add(fab_ctx,
                       __fab_switch_find(fab_ctx, ntohl(port_stat->sw_alias)),
                       port_no);
        c_wr_unlock(&fab_ctx->lock);
        break;
    case OFPPR_MODIFY:
        if ((config_mask & OFPPC_PORT_DOWN)||
            (state_mask & OFPPS_LINK_DOWN)) {
            if (!(config & OFPPC_PORT_DOWN) && !(state & OFPPS_LINK_DOWN)) {
                fab_ctx->rt_scan_all_pending = true;
                break;
            }
        } else break;
        /* Fall through */
    case OFPPR_DELETE:
        c_log_debug("%s: %hu ->DOWN", FN, port_no);
        fab_delete_routes_with_port(fab_ctx,
                                    (int) ntohl(port_stat->sw_alias),
                                    port_no);
        break;
    default:
        c_log_err("%s: unknown reason %d", FN, port_stat->reason);
        break;
    }
}

/**
 * fab_event_notifier -
 *
 * Main Handler for all network and controller events 
 */
static void
fab_event_notifier(void *opq, void *pkt_arg)
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
        fab_switch_add_notifier(opq, fab_ctx, (void *)hdr);
        break;
    case C_OFPT_SWITCH_DELETE:
        {
            c_ofp_switch_delete_t *ofp_sd = (void *)(hdr);
            fab_switch_delete_notifier(fab_ctx, ntohl(ofp_sd->sw_alias), false);
            fab_reset_all_routes(fab_ctx);
            break;
        }
    case C_OFPT_PACKET_IN:
        {
            fab_pkt_rcv(opq, fab_ctx, (void *)hdr);
            break;
        }
    case C_OFPT_PORT_STATUS:
        {
            fab_port_status_handler(opq, fab_ctx, (void *)hdr);
            break;
        }
    case C_OFPT_RECONN_APP:
        mul_register_app(NULL, FAB_APP_NAME,
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, fab_event_notifier);
        break;
    case C_OFPT_NOCONN_APP:
        fab_switches_reset(fab_ctx, __fab_delete_all_hosts_on_switch);
        break;
    case C_OFPT_ERR_MSG:
        fab_recv_err_msg(fab_ctx, (void *)hdr);    
    default:
        return;
    }
}

/**
 * fabric_service_error -
 *
 * Sends error message to service requester in case of error 
 */
static void
fabric_service_error(void *tr_service, struct cbuf *b,
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

    c_service_send(tr_service, new_b);
}


/**
 * fabric_service_success -
 *
 * Sends success message to service requester
 */
static void
fabric_service_success(void *fab_service)
{
    struct cbuf             *new_b;
    struct c_ofp_auxapp_cmd *cofp_aac;

    new_b = of_prep_msg(sizeof(*cofp_aac), C_OFPT_AUX_CMD, 0);

    cofp_aac = (void *)(new_b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_SUCCESS);

    c_service_send(fab_service, new_b);
}

/**
 * fabric_put_route_elem -
 */
static void
fabric_put_route_elem(void *rt_arg, void *u_arg)
{
    struct c_ofp_route_link *cofp_rl = *(struct c_ofp_route_link **)(u_arg);
    rt_path_elem_t *rt_elem = rt_arg;
    fab_switch_t *fab_sw;

    fab_sw = __fab_switch_find(fab_ctx, rt_elem->sw_alias);
    if (!fab_sw) {
        /* We cant fail here so pretend */
        cofp_rl->datapath_id = 0;
    } else {
        cofp_rl->datapath_id = htonll(fab_sw->dpid);
    }

    cofp_rl->src_link = htons(rt_elem->link.la);
    cofp_rl->dst_link = htons(rt_elem->link.lb);
    
    *(struct c_ofp_route_link **)(u_arg) = cofp_rl + 1;
}


/**
 * fab_service_send_single_route -
 */
static void
fab_service_send_single_route(void *route, void *fab_service)
{
    fab_route_t *froute = route;
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct c_ofp_route *cofp_r;
    struct c_ofp_route_link *cofp_rl;
    size_t n_links = g_slist_length(froute->iroute);
    uint64_t dpid = 0;
    
    b = of_prep_msg(sizeof(*cofp_aac) +
                    sizeof(*cofp_r) + (n_links * sizeof(*cofp_rl)),
                    C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_ROUTE);
    cofp_r = (void *)(cofp_aac->data);
    cofp_rl = (void *)(cofp_r->route_links);

    fab_dump_single_host_to_flow(froute->src, &cofp_r->src_host.host_flow, &dpid);
    cofp_r->src_host.switch_id.datapath_id = htonll(dpid);

    fab_dump_single_host_to_flow(froute->dst, &cofp_r->dst_host.host_flow, &dpid);
    cofp_r->dst_host.switch_id.datapath_id = htonll(dpid);

    mul_route_path_traverse(froute->iroute, fabric_put_route_elem,
                            (void *)(&cofp_rl));

    c_service_send(fab_service, b);
}

/**
 * __fabric_service_show_host_route -
 */
static void
__fabric_service_show_host_route(void *host_arg, void *value UNUSED,
                                 void *fab_service)
{
    fab_loop_all_host_routes(host_arg, fab_service_send_single_route,
                             fab_service);
}

/**
 * fabric_service_show_route -
 *
 * Service handler for route show 
 */
static void
fabric_service_show_routes(void *fab_service)
{
    fab_loop_all_hosts(fab_ctx, (GHFunc)__fabric_service_show_host_route, fab_service);

    return fabric_service_success(fab_service); 
}


/**
 * fabric_service_send_host_info -
 */
static void
fabric_service_send_host_info(void *host, void *v_arg UNUSED,
                              void *fab_service)
{
    struct c_ofp_host_mod *cofp_hm;
    struct c_ofp_auxapp_cmd *cofp_aac;
    struct cbuf *b;
    uint64_t dpid = 0;


    b = of_prep_msg(sizeof(*cofp_aac) + sizeof(*cofp_hm), C_OFPT_AUX_CMD, 0);
    cofp_aac = (void *)(b->data);
    cofp_aac->cmd_code = htonl(C_AUX_CMD_FAB_HOST_ADD);
    cofp_hm = (void *)(cofp_aac->data);

    fab_dump_single_host_to_flow(host, &cofp_hm->host_flow, &dpid);
    cofp_hm->switch_id.datapath_id = htonll(dpid);

    c_service_send(fab_service, b);
}

/**
 * fabric_service_show_hosts -
 *
 * Service handler for host show 
 */
static void
fabric_service_show_hosts(void *fab_service, bool active)
{
    if (active) {
        fab_loop_all_hosts(fab_ctx, fabric_service_send_host_info, fab_service);
    } else {
        fab_loop_all_inactive_hosts(fab_ctx, fabric_service_send_host_info,
                                    fab_service);
    }

    return fabric_service_success(fab_service); 
}

/**
 * fabric_service_host_mod -
 *
 * Service handler for host add/del
 */
static void
fabric_service_host_mod(void *fab_service, struct cbuf *b,
                        struct c_ofp_auxapp_cmd *cofp_aac,
                        bool add)
{
    int ret = -1;
    struct c_ofp_host_mod *cofp_hm;

    if (ntohs(cofp_aac->header.length) < 
              sizeof(*cofp_aac) + sizeof(*cofp_hm)) {
        c_log_err("%s: Size err (%u) of (%u)", FN,
                  ntohs(cofp_aac->header.length),
                  sizeof(*cofp_aac) + sizeof(*cofp_hm));
        goto err;
    }

    cofp_hm = (void *)(cofp_aac->data);

    if (add) {
        ret = fab_host_add(fab_ctx, ntohll(cofp_hm->switch_id.datapath_id),
                           &cofp_hm->host_flow);
    } else {
        ret = fab_host_delete(fab_ctx, &cofp_hm->host_flow, NULL, NULL);     
                           
    }

    if (!ret) {
        return fabric_service_success(fab_service); 
    }

err:
    return fabric_service_error(fab_service, b, OFPET_BAD_REQUEST,
                                OFPBRC_BAD_GENERIC);
}

/**
 * fabric_service_handler -
 *
 * Handler service requests 
 */
static void
fabric_service_handler(void *fab_service, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%u) of (%u)", FN,
                  ntohs(cofp_aac->header.length),
                  sizeof(struct c_ofp_auxapp_cmd));
        return fabric_service_error(fab_service, b, OFPET_BAD_REQUEST,
                                    OFPBRC_BAD_LEN);
    }

    switch(ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_FAB_HOST_ADD:
        return fabric_service_host_mod(fab_service, b, cofp_aac,
                                       true);
    case C_AUX_CMD_FAB_HOST_DEL:
        return fabric_service_host_mod(fab_service, b, cofp_aac,
                                       false);
    case C_AUX_CMD_FAB_SHOW_ACTIVE_HOSTS:
        return fabric_service_show_hosts(fab_service, true);
    case C_AUX_CMD_FAB_SHOW_INACTIVE_HOSTS:
        return fabric_service_show_hosts(fab_service, false);
    case C_AUX_CMD_FAB_SHOW_ROUTES:
        return fabric_service_show_routes(fab_service);
    default:
        fabric_service_error(fab_service, b, OFPET_BAD_REQUEST,
                             OFPBRC_BAD_GENERIC);
    }

}

/**
 * fabric_module_init -
 *
 * Fabric application entry point 
 */
void
fabric_module_init(void *base_arg)
{
    struct event_base *base = base_arg;
    struct timeval    tv = { FAB_TIMER_SEC_INT, FAB_TIMER_USEC_INT };
    
    c_log_debug("%s", FN);

    fab_ctx = fab_zalloc(sizeof(fab_struct_t));

    fab_ctx->base = base;
    c_rw_lock_init(&fab_ctx->lock);

    fab_switches_init(fab_ctx);

    fab_ctx->host_htbl = g_hash_table_new_full(fab_host_hash_func,
                                               fab_host_equal_func,
                                               NULL, __fab_host_delete);
    assert(fab_ctx->host_htbl);

    fab_ctx->inact_host_htbl = g_hash_table_new_full(fab_host_hash_func,
                                               fab_host_equal_func,
                                               NULL, __fab_host_delete);
    assert(fab_ctx->inact_host_htbl);

    fab_ctx->tenant_net_htbl = g_hash_table_new_full(fab_tenant_nw_hash_func,
                                                 fab_tenant_nw_equal_func,
                                                 NULL, __fab_tenant_nw_delete);
    assert(fab_ctx->tenant_net_htbl);

    fab_ctx->fab_timer_event = evtimer_new(base,
                                           fab_timer_event,
                                           (void *)fab_ctx);

    fab_ctx->fab_cli_service = mul_app_create_service(MUL_FAB_CLI_SERVICE_NAME,
                                                      fabric_service_handler);
    assert(fab_ctx->fab_cli_service);

    fab_ctx->route_service = mul_app_get_service(MUL_ROUTE_SERVICE_NAME);
    assert(fab_ctx->route_service);

    evtimer_add(fab_ctx->fab_timer_event, &tv);

    mul_register_app(NULL, FAB_APP_NAME, 
                     C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, fab_event_notifier);

    return;
}

/**
 * fabric_module_vty_init -
 *
 * Fabric application's vty entry point 
 */
void
fabric_module_vty_init(void *arg)
{
    c_log_debug("%s:", FN);

    fabric_vty_init(arg);
}

module_init(fabric_module_init);
module_vty_init(fabric_module_vty_init);
