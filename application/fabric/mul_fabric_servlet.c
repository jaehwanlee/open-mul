/*
 *  mul_fabric_servlet.c: MUL fabric cli service 
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

#include "mul_fabric_servlet.h"

/**
 * fab_dump_add_host_cmd_from_flow -
 *
 */
static char *
fab_dump_add_host_cmd_from_flow(uint64_t dpid, struct flow *fl)
{
    char     *pbuf = calloc(1, HOST_PBUF_SZ);
    int      len = 0;
    struct in_addr in_addr = { .s_addr = fl->nw_src };

    len += snprintf(pbuf+len, HOST_PBUF_SZ-len-1,
                    "add fabric-host tenant %hu network %hu host-ip %s host-mac "
                    "%02x:%02x:%02x:%02x:%02x:%02x switch "
                    "0x%llx port %hu %s \r\n",
                    fab_extract_tenant_id(fl),
                    fab_extract_network_id(fl),
                    inet_ntoa(in_addr),
                    fl->dl_src[0], fl->dl_src[1],
                    fl->dl_src[2], fl->dl_src[3],
                    fl->dl_src[4], fl->dl_src[5],
                    dpid,
                    ntohs(fl->in_port),
                    fl->FL_DFL_GW ? "gw" : "non-gw");
    assert(len < HOST_PBUF_SZ-1);
    return pbuf;
}

static bool
check_reply_type(struct cbuf *b, uint32_t cmd_code)
{
    c_ofp_auxapp_cmd_t *cofp_auc  = (void *)(b->data);

    if (ntohs(cofp_auc->header.length) < sizeof(*cofp_auc)) {
        return false;
    }

    if (cofp_auc->header.type != C_OFPT_AUX_CMD ||
        cofp_auc->cmd_code != htonl(cmd_code)) {
        return false;
    }

    return true;
}

static char *
mul_fabric_route_link_dump(struct c_ofp_route_link *rl, size_t n_links)
{
    int i = 0 , len = 0;
    char *pbuf = calloc(1, FAB_DFL_PBUF_SZ);

    if (!pbuf) {
        return NULL;
    }

    for (; i < n_links; i++) {
        len += snprintf(pbuf+len, FAB_DFL_PBUF_SZ-len-1,
                        "Node(0x%llx):Link(%hu)",
                        ntohll(rl->datapath_id), ntohs(rl->src_link));
        if (len >= FAB_DFL_PBUF_SZ-1) {
            c_log_err("%s: print buf overrun", FN);
            free(pbuf);
            return NULL;
        }
        rl++;
    }

    return pbuf;
}

/**
 * mul_fabric_host_mod -
 *
 */
int
mul_fabric_host_mod(void *service, uint64_t dpid, struct flow *fl, bool add)
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_host_mod *cofp_hm;
    int ret = -1;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) +
                    sizeof(struct c_ofp_host_mod),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = add ? htonl(C_AUX_CMD_FAB_HOST_ADD): 
                               htonl(C_AUX_CMD_FAB_HOST_DEL);
    cofp_hm = (void *)(cofp_auc->data);
    cofp_hm->switch_id.datapath_id = htonll(dpid);
    memcpy(&cofp_hm->host_flow, fl, sizeof(*fl));
    
    c_service_send(service, b);
    b = c_service_wait_response(service);
    if (b) {
        if (check_reply_type(b, C_AUX_CMD_SUCCESS)) {
            ret = 0;
        }
        
        free_cbuf(b);
    }

    return ret;
}

/**
 * mul_fabric_show_hosts -
 *
 */
void
mul_fabric_show_hosts(void *service, bool active, bool dump_cmd,
                      void *arg, void (*cb_fn)(void *arg, char *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_host_mod *cofp_hm;
    char *pbuf;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = active ?
                         htonl(C_AUX_CMD_FAB_SHOW_ACTIVE_HOSTS): 
                         htonl(C_AUX_CMD_FAB_SHOW_INACTIVE_HOSTS);
    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_FAB_HOST_ADD)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);
            cofp_hm = (void *)(cofp_auc->data);

            if (ntohs(cofp_auc->header.length)  <
                sizeof(*cofp_auc) + sizeof(*cofp_hm)) {
                free_cbuf(b);
                break;

            }
            
            if (!dump_cmd) {
                pbuf = fab_dump_single_host_from_flow(
                                    ntohll(cofp_hm->switch_id.datapath_id),
                                    &cofp_hm->host_flow);
            } else {
                pbuf = fab_dump_add_host_cmd_from_flow(
                                    ntohll(cofp_hm->switch_id.datapath_id),
                                    &cofp_hm->host_flow);
            }
            if (pbuf) {
                cb_fn(arg, pbuf); 
                free(pbuf);
            }
            free_cbuf(b);
        } else {
            break;
        }
    }
}


/**
 * mul_fabric_show_routes -
 *
 */
void
mul_fabric_show_routes(void *service,
                       void *arg,
                       void (*show_src_host)(void *arg, char *pbuf),
                       void (*show_dst_host)(void *arg, char *pbuf),
                       void (*show_route_links)(void *arg, char *pbuf))
{
    struct cbuf *b;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_route *cofp_r;
    struct c_ofp_route_link *cofp_rl;
    char *pbuf;
    size_t n_links = 0;

    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd),
                    C_OFPT_AUX_CMD, 0);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_FAB_SHOW_ROUTES); 
    c_service_send(service, b);
    while (1) {
        b = c_service_wait_response(service);
        if (b) {
            if (check_reply_type(b, C_AUX_CMD_SUCCESS) ||
                !check_reply_type(b, C_AUX_CMD_FAB_ROUTE)) {
                free_cbuf(b);
                break;
            }
            cofp_auc = (void *)(b->data);

            if (ntohs(cofp_auc->header.length) <
                sizeof(*cofp_auc) + sizeof(*cofp_r)) {
                free_cbuf(b);
                continue;
            }
            n_links = (ntohs(cofp_auc->header.length) - 
                      (sizeof(*cofp_auc) + sizeof(*cofp_r)))/sizeof(*cofp_rl);
            cofp_r = (void *)(cofp_auc->data);
            pbuf = fab_dump_single_host_from_flow(
                                ntohll(cofp_r->src_host.switch_id.datapath_id),
                                &cofp_r->src_host.host_flow);
            if (pbuf) {
                show_src_host(arg, pbuf); 
                free(pbuf);
            }
            pbuf = fab_dump_single_host_from_flow(
                                ntohll(cofp_r->dst_host.switch_id.datapath_id),
                                &cofp_r->dst_host.host_flow);
            if (pbuf) {
                show_dst_host(arg, pbuf); 
                free(pbuf);
            }

            pbuf = mul_fabric_route_link_dump(
                            (void *)(cofp_r->route_links), n_links);
            if (pbuf) {
                show_route_links(arg, pbuf);
                free(pbuf);
            }

            free_cbuf(b);
        } else {
            break;
        }
    }
}
