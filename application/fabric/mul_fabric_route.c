/*
 *  mul_fabric_route.c: Fabric routing for MUL Controller 
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

extern fab_struct_t *fab_ctx;

/**
 * fab_route_from_host_cmp - 
 *
 * Check whether route originates from a host 
 */
static int
fab_route_from_host_cmp(void *route_elem, void *h_arg)
{
    fab_route_t *froute = route_elem;
    fab_host_t *host = h_arg;

    if (host == froute->src) return 0; 

    return 1;
} 

/**
 * fab_route_to_host_cmp - 
 *
 * Check whether route terminates at host 
 */
static int
fab_route_to_host_cmp(void *route_elem, void *h_arg)
{
    fab_route_t *froute = route_elem;
    fab_host_t *host = h_arg;

    if (host == froute->dst) return 0; 

    return 1;
} 

/**
 * fab_dump_single_pending_route -
 *
 * Dump a single pending route
 */
void
fab_dump_single_pending_route(void *route, void *arg UNUSED)
{
    fab_route_t *froute = route;

    c_log_debug("%s: Pending route between (0x%llx:%d -Port(%u)) -> (0x%llx:%d - Port (%u))",
                FN, froute->src->sw.swid, froute->src->sw.alias , froute->src->sw.port,
                froute->dst->sw.swid, froute->dst->sw.alias, froute->dst->sw.port);
}

/**
 * __fab_loop_all_pending_routes -
 * @fab_ctx : Fabric ctx pointer
 * @iter_fn : Iteration callback for each route of host
 * @u_data  : User arg to be passed to iter_fn
 *
 * Loop over all pending routes
 */
void
__fab_loop_all_pending_routes(fab_struct_t *fab_ctx, GFunc iter_fn, void *u_data)
{
    if (fab_ctx->rt_pending_list) {
        g_slist_foreach(fab_ctx->rt_pending_list,
                        (GFunc)iter_fn, u_data);
    }
}

/**
 * fab_route_elem_oport_cmp -
 *
 * Check whether fabric route element has port as out_port for this node
 */
static int
fab_route_elem_oport_cmp(void *rt_path_arg, void *sw_arg)
{
    rt_path_elem_t *rt_elem = rt_path_arg;
    fab_host_sw_t  *sw = sw_arg;

    if (rt_elem->sw_alias == sw->alias &&
        rt_elem->link.la == sw->port) {
        c_log_err("%s: Match", FN);
        return 0;
    }

    return 1;
}

/**
 * fab_per_switch_route_install- 
 * @rt : a route element  
 * @u_arg : fabric route pointer  
 *
 * Install a fabric route element to a switch node
 */
static void
fab_per_switch_route_install(void *rt, void *u_arg)
{
    rt_path_elem_t              *rt_elem = rt;
    fab_route_t                 *froute = u_arg;
    uint8_t                     *actions, *pactions;
    size_t                      action_len = sizeof(struct ofp_action_output);
    uint16_t                    out_port;
    uint16_t                    tenant_id;
    bool                        fhop, lhop; 
    bool                        add_pkt_tenant = false, strip_pkt_tenant = false;

    c_log_err("%s: ", FN);

    lhop = rt_elem->flags & RT_PELEM_LAST_HOP ? true: false;
    fhop = rt_elem->flags & RT_PELEM_FIRST_HOP ? true: false;

    tenant_id = fab_tnid_to_tid(froute->src->hkey.tn_id);
    out_port = lhop ? froute->dst->sw.port : rt_elem->link.la;

    /* 
     * Update the last hop oport in the route
     * This is not accomplshed by route-service 
     */
    rt_elem->link.la = out_port;

    if (tenant_id) {
        if (lhop && fhop) { 
            goto apply_route;
        } else if (fhop) {
            action_len += sizeof(struct ofp_action_vlan_vid);
            add_pkt_tenant = true;
            goto apply_route;
        } else if (!lhop) {
            action_len += sizeof(struct ofp_action_vlan_vid);
            add_pkt_tenant = true;
        } else {
            /* Last hop */
            action_len += sizeof(struct ofp_action_header); 
            strip_pkt_tenant = true;
        } 

        fab_add_tenant_id(&froute->rt_flow, &froute->rt_wildcards, tenant_id);
    }

apply_route:
    actions = fab_zalloc(action_len);
    pactions = actions;

    if (add_pkt_tenant) {
        of_make_action_set_vid((char **)&pactions,
                          sizeof(struct ofp_action_vlan_vid),
                          tenant_id);
        pactions += sizeof(struct ofp_action_vlan_vid); 
    } else if (strip_pkt_tenant) {
        of_make_action_strip_vlan((char **)&pactions,
                          sizeof(struct ofp_action_header));
        pactions += sizeof(struct ofp_action_header);
    }

    of_make_action_output((char **)&pactions,
                          sizeof(struct ofp_action_output),
                          out_port);

    mul_app_send_flow_add(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias), 
                          &froute->rt_flow, FAB_UNK_BUFFER_ID,
                          actions, action_len, 
                          0, 0, froute->rt_wildcards,
                          froute->prio, C_FL_ENT_SWALIAS);

    froute->rt_flow.dl_type = ntohs(ETH_TYPE_ARP);
    mul_app_send_flow_add(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias), 
                          &froute->rt_flow, FAB_UNK_BUFFER_ID,
                          actions, action_len, 
                          0, 0, froute->rt_wildcards,
                          froute->prio, C_FL_ENT_SWALIAS);

    /* Reset flow modifications if any */
    froute->rt_flow.dl_type = ntohs(ETH_TYPE_IP);
    if (tenant_id) {
        fab_reset_tenant_id(&froute->rt_flow, &froute->rt_wildcards);
    }
}

/**
 * fab_per_switch_route_uninstall- 
 * @rt : a route element  
 * @u_arg : fabric route pointer  
 *
 * Uninstall a fabric route element from a switch node
 */
static void
fab_per_switch_route_uninstall(void *rt, void *u_arg)
{
    rt_path_elem_t   *rt_elem = rt;
    fab_route_t      *froute = u_arg;
    uint16_t         tenant_id = fab_tnid_to_tid(froute->src->hkey.tn_id);       
    bool             fhop;


    c_log_debug("%s: ", FN);

    fhop = rt_elem->flags & RT_PELEM_FIRST_HOP ? true: false;
    if (tenant_id && !fhop) {
         fab_add_tenant_id(&froute->rt_flow, &froute->rt_wildcards, tenant_id);
    }

    mul_app_send_flow_del(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias),
                          &froute->rt_flow, froute->rt_wildcards, OFPP_NONE, 
                          froute->prio, C_FL_ENT_SWALIAS);

#ifndef CONFIG_HAVE_PROXY_ARP
    froute->rt_flow.dl_type = ntohs(ETH_TYPE_ARP);
    mul_app_send_flow_del(FAB_APP_NAME, NULL, (uint64_t)(rt_elem->sw_alias),
                          &froute->rt_flow, froute->rt_wildcards, OFPP_NONE, 
                          froute->prio, C_FL_ENT_SWALIAS);
#endif

    froute->rt_flow.dl_type = ntohs(ETH_TYPE_IP);
    if (tenant_id && !fhop) {
        fab_reset_tenant_id(&froute->rt_flow, &froute->rt_wildcards);
    }
}

/**
 * fab_route_install - 
 * @froute : Fabric route to install  
 *
 * Install a fabric route to hardware
 */
static void
fab_route_install(fab_route_t *froute)
{
    froute->flags &= ~FAB_ROUTE_DIRTY;
    mul_route_path_traverse(froute->iroute, fab_per_switch_route_install, 
                            froute); 
}

/**
 * fab_route_uninstall - 
 * @froute : Fabric route to uninstall  
 *
 * Uninstall a fabric route from hardware
 */
static void
fab_route_uninstall(fab_route_t *froute)
{
    mul_route_path_traverse(froute->iroute, fab_per_switch_route_uninstall, 
                            froute); 
    froute->flags |= FAB_ROUTE_DEAD;
}

/**
 * fab_zaproute - 
 * @route : Fabric route to destroy  
 *
 * Destructor for a fabric route
 */
static void
fab_zaproute(void *route)
{
    fab_route_t *froute = route;

    if (froute->iroute) {
        mul_destroy_route(froute->iroute);
    }

    fab_host_put(froute->src);
    fab_host_put(froute->dst);

    fab_free(froute);
}


/**
 * __fab_del_pending_route -
 * @fab_ctx : Fabric context pointer
 * @route : Fabric route
 *
 * Delete route from pending list
 */
static void
__fab_del_pending_route(fab_struct_t *fab_ctx, fab_route_t *froute)
{
    fab_ctx->rt_pending_list = g_slist_remove(fab_ctx->rt_pending_list, froute);
}


/**
 * __fab_del_pending_routes_tofro_host -
 * @fab_ctx : Fabric context pointer
 * @host : Fabric host 
 *
 * Delete pending routes to and from a host
 */
void
__fab_del_pending_routes_tofro_host(fab_struct_t *fab_ctx, fab_host_t *host)
{
    GSList *iterator;

    iterator = g_slist_find_custom(fab_ctx->rt_pending_list,
                                   host,
                                   (GCompareFunc)fab_route_from_host_cmp);

    if (iterator) {
        __fab_del_pending_route(fab_ctx, iterator->data);
    }

    iterator = g_slist_find_custom(fab_ctx->rt_pending_list,
                                   host,
                                   (GCompareFunc)fab_route_to_host_cmp);

    if (iterator) {
        __fab_del_pending_route(fab_ctx, iterator->data);
    }
}


/**
 * __fab_add_to_pending_routes - 
 * @fab_ctx : Fabric context pointer  
 * @route : Fabric route  
 *
 * Add a host-pair route as pending
 */
static void
__fab_add_to_pending_routes(fab_struct_t *fab_ctx, fab_route_t *froute)
{
    froute->expiry_ts = time(NULL) + FAB_ROUTE_RETRY_INIT_TS;
    fab_ctx->rt_pending_list = g_slist_append(fab_ctx->rt_pending_list, froute);
}

/**
 * fab_flush_pending_routes - 
 * @fab_ctx : Fabric context pointer  
 *
 * Flush all pending host-pair routes 
 */
void
fab_flush_pending_routes(fab_struct_t *fab_ctx)
{
    c_wr_lock(&fab_ctx->lock);
    g_slist_free_full(fab_ctx->rt_pending_list, (GDestroyNotify)fab_zaproute);
    fab_ctx->rt_pending_list = NULL;
    c_wr_unlock(&fab_ctx->lock);
}

/**
 * fab_retry_pending_routes - 
 * @fab_ctx : Fabric context pointer  
 * @curr_ts : Current timestamp
 *
 * Retry establishing all pending host-pair routes 
 */
static void
fab_retry_pending_routes(fab_struct_t *fab_ctx, time_t curr_ts)
{
    GSList *iterator, *prev = NULL;
    fab_route_t *froute;
    bool scan_all_pending;
    int num_runs = 0;

start:
    scan_all_pending = fab_ctx->rt_scan_all_pending;
    fab_ctx->rt_scan_all_pending ^= fab_ctx->rt_scan_all_pending;

    c_wr_lock(&fab_ctx->lock);

restart:
    prev = NULL;
    iterator = fab_ctx->rt_pending_list; 
    while (iterator) {
        froute = iterator->data;
        if(scan_all_pending ||
           curr_ts > froute->expiry_ts) {
            c_log_debug("%s: Pending route between (0x%x) -> (0x%x)",
                  FN, froute->src->hkey.host_ip, froute->dst->hkey.host_ip);


           if ((froute->iroute = mul_route_get(fab_ctx->route_service,
                                           froute->src->sw.alias, 
                                           froute->dst->sw.alias)) ||
                froute->src->dead || froute->dst->dead) {

                if (!froute->src->dead && !froute->dst->dead) {

                    /* Routes are now reachable. Install it */
                    c_wr_lock(&froute->dst->lock);
                    froute->dst->host_routes = 
                            g_slist_append(froute->dst->host_routes, froute);
                    fab_route_install(froute);
                    c_wr_unlock(&froute->dst->lock);
                } else {
                    c_log_debug("%s: Zapped route(%d)->(%d)", FN,
                                froute->src->sw.alias, froute->dst->sw.alias);
                    fab_zaproute(froute);
                }

                /* Delete it from the pending list */
                if (prev) {
                    prev->next = iterator->next;
                } else {
                    fab_ctx->rt_pending_list = iterator->next;
                }   
                g_slist_free_1(iterator);
                goto restart;
            }
            froute->expiry_ts = curr_ts + FAB_ROUTE_RETRY_TS;
        }
        
        prev = iterator;
        iterator = iterator->next;
    }

    c_wr_unlock(&fab_ctx->lock);

    if (fab_ctx->rt_scan_all_pending && ++num_runs > FAB_MAX_PENDING_LOOPS) {
        goto start;
    }

    if (num_runs > FAB_MAX_PENDING_LOOPS) {
        c_log_err("%s: Ran too many times", FN);
    }
}

/**
 * fab_mkroute - 
 * @src : Source host 
 * @dst : Destination host
 *
 * Make a route from a source to a destination host 
 */
static fab_route_t * 
fab_mkroute(fab_host_t *src, fab_host_t *dst)
{
    fab_route_t *froute;

    froute = fab_zalloc(sizeof(fab_route_t));

    fab_host_get(src);
    fab_host_get(dst);
    froute->src = src;
    froute->dst = dst;
    froute->flags = FAB_ROUTE_DIRTY;
    if (froute->src->sw.alias == froute->dst->sw.alias) {
         froute->flags |= FAB_ROUTE_SAME_SWITCH;
    }

    froute->rt_wildcards = OFPFW_ALL;   

#if 0
    fab_add_tenant_id(&froute->rt_flow, &froute->rt_wildcards, 
                      fab_tnid_to_tid(src->hkey.tn_id));
#endif

    if (src->dfl_gw || dst->dfl_gw) {
        froute->prio = C_FL_PRIO_DFL;
    } else {
        froute->prio = C_FL_PRIO_FWD;
    }

    if (!src->dfl_gw) {
        froute->rt_flow.nw_src = ntohl(src->hkey.host_ip);
        froute->rt_wildcards &= ~(OFPFW_NW_SRC_MASK);
    }

    if (!dst->dfl_gw) {
        froute->rt_flow.nw_dst = ntohl(dst->hkey.host_ip);
        froute->rt_wildcards &= ~(OFPFW_NW_DST_MASK);
    }

    froute->rt_flow.dl_type = ntohs(ETH_TYPE_IP);
    froute->rt_wildcards &= ~(OFPFW_DL_TYPE);

    froute->iroute = mul_route_get(fab_ctx->route_service,
                                   src->sw.alias, dst->sw.alias);
    if (!froute->iroute) {
        c_log_err("%s: No host route src(0x%x)[0x%llx:%d]->dst(0x%x)[0x%llx:%d]",
                  FN, src->hkey.host_ip, src->sw.swid, src->sw.alias, 
                  dst->hkey.host_ip, dst->sw.swid, dst->sw.alias);
        __fab_add_to_pending_routes(fab_ctx, froute);
        //fab_zaproute(froute);
        return NULL;
    }

    return froute;
}

/**
 * __fab_loop_all_host_routes - 
 * @host    : Fabric host pointer 
 * @iter_fn : Iteration callback for each route of host 
 * @u_data  : User arg to be passed to iter_fn 
 *
 * Loop over all routes of a host and invoke callback for each
 */
static void
__fab_loop_all_host_routes(fab_host_t *host, GFunc iter_fn, void *u_data)
{                               
    if (host->host_routes) {
        g_slist_foreach(host->host_routes,
                        (GFunc)iter_fn, u_data);
    }
}

/**
 * fab_loop_all_host_routes - 
 * @host    : Fabric host pointer 
 * @iter_fn : Iteration callback for each route of host 
 * @u_data  : User arg to be passed to iter_fn 
 *
 * Loop over all routes of a host and invoke callback for each
 * while holding host lock
 */
void
fab_loop_all_host_routes(fab_host_t *host, GFunc iter_fn, void *u_data)
{                               
    c_rd_lock(&host->lock);
    if (host->host_routes) {
        g_slist_foreach(host->host_routes,
                        (GFunc)iter_fn, u_data);
    }
    c_rd_unlock(&host->lock);
}

/**
 * fab_host_route_delete_1 - 
 * @iroute: Fabric route to destroy 
 * @u_arg : User arg (unused) 
 *
 * Uninstall and destroy a single fabric route
 */
static void 
fab_host_route_delete_1(void *iroute, void *u_arg UNUSED)
{
    fab_route_uninstall(iroute);
    fab_zaproute(iroute);
}

/**
 * fab_host_route_add -
 *
 * Add route from src to dst 
 */
static int
fab_host_route_add(fab_host_t *src, fab_host_t *dst)
{
    fab_route_t *froute;

    if (src == dst) {
        return -1;
    }
    
    froute = fab_mkroute(src, dst);
    if (froute) {
        c_wr_lock(&dst->lock);
        dst->host_routes = g_slist_append(dst->host_routes, froute);
        fab_route_install(froute);
        c_wr_unlock(&dst->lock);

        return 0;
    }

    return -1;
}

/**
 * fab_host_per_tenant_nw_add_route_pair - 
 * @shost : Source host 
 * @dhost : Destination host
 *
 * Add host routes for a given src<->dst host pairs 
 */
static void 
fab_host_per_tenant_nw_add_route_pair(void *shost, void *dhost)
{
    fab_host_route_add(shost, dhost);
    fab_host_route_add(dhost, shost);
}

/**
 * fab_host_per_tenant_nw_add_route - 
 * @shost : Source host 
 * @dhost : Destination host
 *
 * Add host routes for a given src->dst host 
 */
static void 
fab_host_per_tenant_nw_add_route(void *shost, void *dhost)
{
    fab_host_route_add(shost, dhost);
}

/**
 * fab_route_port_cmp -
 *
 * Check whether fabric route has port as out_port for any path
 */
static int
fab_route_port_cmp(void *route_elem, void *sw_arg)
{
    fab_route_t *froute = route_elem;
    GSList *iterator;

    if (!froute->iroute) return 1;

    iterator = g_slist_find_custom(froute->iroute,
                                   sw_arg,
                                   (GCompareFunc)fab_route_elem_oport_cmp);
    if (iterator) return 0;

    return 1;
}

/**
 * fab_host_per_tenant_nw_delete_route - 
 * @elem_host : host of a tenant network
 * @arg_host : host getting deleted 
 *
 * Delete host routes for a given host 
 */
static void 
fab_host_per_tenant_nw_delete_route(void *elem_host, void *arg_host)
{
    fab_host_t *host = elem_host;
    fab_host_t *del_host = arg_host;
    GSList *iterator;

    if (host == del_host) {
        return;
    }

    c_wr_lock(&host->lock);
    iterator = g_slist_find_custom(host->host_routes,
                                   del_host,
                                   (GCompareFunc)fab_route_from_host_cmp);
    if (!iterator) {
        c_log_err("%s: No host route between (0x%llx:%d) -> (0x%llx:%d)",
                  FN, del_host->sw.swid, del_host->sw.alias,
                  host->sw.swid, host->sw.alias);
        c_wr_unlock(&host->lock);
        return;
    }

    fab_host_route_delete_1(iterator->data, NULL);

    host->host_routes = g_slist_remove(host->host_routes, iterator->data);
    c_wr_unlock(&host->lock);  

    return;
}

/**
 * __fab_routes_tofro_host_add - 
 * @host_arg : Fabric host pointer
 * @u_arg : User arg whether to install pair routes or not 
 *
 * Add host routes from all other hosts of same tenant network
 * NOTE - It is assumed that fab_ctx main lock is held prior
 * to invocation 
 */
void
__fab_routes_tofro_host_add(void *host_arg, void *u_arg)
{
    fab_host_t *host = host_arg;
    bool install_pair = *(bool *)u_arg;

    /* Do not continue if there is pending recalc all */
    if (fab_ctx->rt_recalc_pending) {
        c_log_err("%s: Cant add host route - Pending recal event", FN);
        return;
    }

    __fab_tenant_nw_loop_all_hosts(host->tenant_nw,
                                   install_pair ? 
                                   fab_host_per_tenant_nw_add_route_pair :
                                   fab_host_per_tenant_nw_add_route,
                                   host);
}

/**
 * __fab_host_route_del_with_port -
 *
 * Delete all routes for a host which matches oport for a switch node */
static void
__fab_host_route_del_with_port(void *host_arg, void *key_arg UNUSED,
                               void *sw_arg)
{
    fab_host_t *host = host_arg;
    GSList *iterator;
    fab_route_t *froute;

    c_wr_lock(&host->lock);
    iterator = g_slist_find_custom(host->host_routes,
                                   sw_arg,
                                   (GCompareFunc)fab_route_port_cmp);
    if (!iterator) {
        c_wr_unlock(&host->lock);
        return;
    }

    froute = iterator->data;
    fab_route_uninstall(froute);

    host->host_routes = g_slist_remove(host->host_routes, iterator->data);
    c_wr_unlock(&host->lock);

    mul_destroy_route(froute->iroute);
    froute->iroute = NULL;

    usleep(10000); /* 10ms breather to routing */
    fab_host_per_tenant_nw_add_route(froute->src, froute->dst);
    fab_zaproute(froute);

    /*
     * Place a call to __fab_add_to_pending_routes(fab_ctx, froute);
     * instead of above 2 lines if there is no hurry to recalc new route
     */

    return;
}


/**
 * __fab_host_route_delete - 
 * @host_arg : Fabric host pointer 
 * @ctx_arg : Fabric context pointer 
 *
 * Delete host routes from all other hosts of same tenant network
 * NOTE - It is assumed that fab_ctx main lock is held prior
 * to invocation 
 */
void
__fab_host_route_delete(void *host_arg, void *v_arg UNUSED, void *ctx_arg UNUSED)
{
    fab_host_t *host = host_arg;

    c_log_err("%s", FN);
    c_wr_lock(&host->lock);

    __fab_loop_all_host_routes(host, fab_host_route_delete_1, fab_ctx); 
    g_slist_free(host->host_routes);
    host->host_routes = NULL;

    c_wr_unlock(&host->lock);

    __fab_tenant_nw_loop_all_hosts(host->tenant_nw, 
                                   fab_host_per_tenant_nw_delete_route,
                                   host);
}

/**
 * fab_reset_all_routes - 
 * @fab_ctx : Fabric context pointer 
 *
 * Reset all routes for all hosts
 */
void
fab_reset_all_routes(fab_struct_t *fab_ctx)
{
    fab_ctx->rt_recalc_pending = true;
    fab_ctx->rt_recalc_ts = time(NULL) + FAB_RT_RECALC_TS;

    fab_loop_all_hosts(fab_ctx, (GHFunc)__fab_host_route_delete, fab_ctx); 
    //fab_flush_pending_routes(fab_ctx);
}

/**
 * fab_add_all_routes - 
 * @fab_ctx : Fabric context pointer 
 *
 * Recalculate and add all routes for all hosts
 */
void
fab_add_all_routes(fab_struct_t *fab_ctx)
{
    bool add_pair = false;
    fab_loop_all_hosts(fab_ctx, (GHFunc)__fab_routes_tofro_host_add, &add_pair);
}

/**
 * fab_delete_routes_with_port -
 * @fab_ctx :  Fabric context pointer
 * @sw_alias : switch alias id
 * @port_no : port number
 *
 * Delete all routes matching switch id and port number
 */
void
fab_delete_routes_with_port(fab_struct_t *fab_ctx, int sw_alias, uint16_t port_no)
{
    fab_host_sw_t sw = { 0, 0, 0};
    sw.alias = sw_alias;
    sw.port  = port_no;

    fab_loop_all_hosts_wr(fab_ctx, (GHFunc)__fab_host_route_del_with_port, &sw);
}

/**
 * fab_route_per_sec_timer - 
 * @fab_ctx : Fabric context pointer 
 *
 * Per second timer for fabric route management  
 */
void
fab_route_per_sec_timer(fab_struct_t *fab_ctx)
{
    time_t curr_ts = time(NULL);

    if (fab_ctx->rt_recalc_pending && 
        curr_ts > fab_ctx->rt_recalc_ts) {
        fab_ctx->rt_recalc_pending = false;
        fab_add_all_routes(fab_ctx);
    } 

    /* If there is a recalc event then there can be no pending routes */
    if (!fab_ctx->rt_recalc_pending) {
        fab_retry_pending_routes(fab_ctx, curr_ts);
    }

}
