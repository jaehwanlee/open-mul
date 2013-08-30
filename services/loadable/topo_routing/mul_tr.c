/*  mul_tr.c: MUL topology and routing application module  
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

#include "mul_tr.h"

tr_struct_t *tr_hdl;

/**
 * __tr_get_max_switch_alias -
 */
int
__tr_get_max_switch_alias(tr_struct_t *tr)
{
    return __lldp_get_max_switch_alias(tr->topo_hdl);
}

/**
 * __tr_get_num_switches -
 */
int
__tr_get_num_switches(tr_struct_t *tr)
{
    return __lldp_get_num_switches(tr->topo_hdl);
}

/**
 * __tr_init_neigh_pair_adjacencies -
 */
void
__tr_init_neigh_pair_adjacencies(tr_neigh_query_arg_t *arg)
{
    return __lldp_init_neigh_pair_adjacencies(arg);
}

/**
 * tr_show_route_adj_matrix -
 */
char *
tr_show_route_adj_matrix(tr_struct_t *tr)
{
    char *pbuf = NULL;

    lldp_sw_rd_lock(tr->topo_hdl);

    if(tr->rt.rt_dump_adj_matrix) {
        pbuf = tr->rt.rt_dump_adj_matrix(tr);
    }

    lldp_sw_rd_unlock(tr_hdl->topo_hdl);

    return pbuf;
}

/**
 * tr_get_route -
 *
 * Get a route
 */
GSList *
tr_get_route(tr_struct_t *tr, int src_node, int dst_node)
{
    GSList *route = NULL;
    int num_nodes = 0;
    lldp_sw_rd_lock(tr->topo_hdl);

    num_nodes = __tr_get_max_switch_alias(tr);

    if (!(num_nodes) || 
        src_node < 0 || dst_node < 0 ||
        src_node > num_nodes || dst_node > num_nodes) {
        lldp_sw_rd_unlock(tr->topo_hdl);
        return NULL;        
    }

    if(tr->rt.rt_get_sp) {
        route = tr->rt.rt_get_sp(tr, src_node, dst_node);
    }

    lldp_sw_rd_unlock(tr_hdl->topo_hdl);

    return route;
}

/**
 * tr_dump_route -
 *
 * Dump a route for printing
 */
char *
tr_dump_route(GSList *route_path)
{
    char *pbuf = calloc(1, TR_ROUTE_PBUF_SZ);
    int len = 0;
    GSList *iterator = NULL;
    rt_path_elem_t *rt_elem = NULL;

    len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1, "iROUTE:\r\n");
    assert(len < TR_ROUTE_PBUF_SZ-1);

    for (iterator = route_path; iterator; iterator = iterator->next) {
        rt_elem = iterator->data;

        len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1,
                        "Node(%d):Link(%hu)->", 
                        rt_elem->sw_alias, rt_elem->link.la);
        assert(len < TR_ROUTE_PBUF_SZ-1);
    }


    len += snprintf(pbuf+len, TR_ROUTE_PBUF_SZ-len-1, "||\r\n");
    assert(len < TR_ROUTE_PBUF_SZ-1);

    return pbuf;
}

/**
 * tr_destroy_route -
 *
 * Destroy route. Utility wrapper over mul_destroy_route() 
 */
void
tr_destroy_route(GSList *route)
{
    return mul_destroy_route(route);
}


/**
 * __tr_invoke_routing -
 *
 * Invoke routing subsystem to recalcuate all routes
 */
void
__tr_invoke_routing(tr_struct_t *tr)
{
    if (tr->rt.rt_clean_state) {
        tr->rt.rt_clean_state(tr);
    }
    if (tr->rt.rt_init_state) {
        tr->rt.rt_init_state(tr);
    }
    if (tr->rt.rt_calc) {
        tr->rt.rt_calc(tr);
    }

    if (!tr->rt.rt_init_trigger) {
        tr->rt.rt_init_trigger = true;
    }
}


/**
 * tr_invoke_routing -
 *
 * Invoke routing subsystem to recalculate all routes
 * Reclaim global lock if it is not yet held
 */
void
tr_invoke_routing(tr_struct_t *tr)
{
    int lock;

    if (!tr->rt.rt_init_trigger) {
        return;
    }

    lock = !lldp_sw_wr_trylock(tr->topo_hdl);
    __tr_invoke_routing(tr);
    if (lock) {
        lldp_sw_wr_unlock(tr->topo_hdl);
    }
}

/**
 * tr_service_error -
 *
 * Sends error message to service requester in case of error 
 */
static void 
tr_service_error(void *tr_service, struct cbuf *b,
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
 * tr_service_request_neigh -
 *
 * Handle neigh request 
 */
static void
tr_service_request_neigh(void *tr_service,
                         struct cbuf *req_b,
                         struct c_ofp_auxapp_cmd *cofp_aac)
{
    struct cbuf *b;
    c_ofp_req_dpid_attr_t *req_dpid = (void *)(cofp_aac->data);

    if (ntohs(cofp_aac->header.length) < sizeof(*req_dpid)) {
        c_log_err("%s: Size err (%u) of (%u)", FN,
                  ntohs(cofp_aac->header.length),
                  sizeof(*req_dpid));
        return;
    }

    b = lldp_service_neigh_request(ntohll(req_dpid->datapath_id),
                                   cofp_aac->header.xid); 
    if (b) {
        c_service_send(tr_service, b);
    } else {
        tr_service_error(tr_service, req_b, OFPET_BAD_REQUEST, OFPBRC_BAD_DPID);
    }
}

/**
 * tr_service_handler -
 *
 * Handler service requests 
 */
static void
tr_service_handler(void *tr_service, struct cbuf *b)
{
    struct c_ofp_auxapp_cmd *cofp_aac = (void *)(b->data);

    if (ntohs(cofp_aac->header.length) < sizeof(struct c_ofp_auxapp_cmd)) {
        c_log_err("%s: Size err (%u) of (%u)", FN,
                  ntohs(cofp_aac->header.length),
                  sizeof(struct c_ofp_auxapp_cmd));
        return tr_service_error(tr_service, b, OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch(ntohl(cofp_aac->cmd_code)) {
    case C_AUX_CMD_TR_GET_NEIGH:
        return tr_service_request_neigh(tr_service, b, cofp_aac);
    default:
        tr_service_error(tr_service, b, OFPET_BAD_REQUEST, OFPBRC_BAD_GENERIC);
    }
}

/**
 * tr_create_service -
 *
 * Create a new controller service 
 */
static void * 
tr_create_service(tr_struct_t *tr_hdl UNUSED)
{
    return mul_app_create_service(MUL_TR_SERVICE_NAME, tr_service_handler);        
}

/**
 * tr_packet_in_handler -
 *
 * General PACKET_IN event handler
 */
static int
tr_packet_in_handler(c_ofp_packet_in_t *ofp_pin)
{
	uint64_t receiver_id = ntohll(ofp_pin->datapath_id);
	uint16_t port_id = ntohs(ofp_pin->in_port);

	lldp_pkt_t *lldp_pkt;

	/* check packet validity */
	/* check ether type. */
	struct ethernet2_header *head = (struct ethernet2_header *)ofp_pin->data;
	uint16_t ethertype = ntohs(head->ethertype);

	switch (ethertype){
	case 0x88cc:
		/* LLDP */
		lldp_pkt = (lldp_pkt_t *)ofp_pin->data;
		return lldp_packet_handler(receiver_id, port_id, lldp_pkt);

		/* ADD other pkt types as needed */
	default:
		c_log_debug("%s: ethertype 0x%hx not recognized ",FN,ethertype);
		return -1;
	}

}

/**
 * tr_port_status_handler -
 *
 * PORT_STATUS event handler
 */
static void
tr_port_status_handler(void *app_arg, c_ofp_port_status_t *port_stat)
{
    return lldp_port_status_handler(app_arg, port_stat);
}

/**
 * tr_cleanall -
 *
 * Clean all info TR module is holding
 */
static void
tr_cleanall(tr_struct_t *tr)
{
    lldp_cleanall_switches(tr);
    if(tr->rt.rt_clean_state) {
        tr->rt.rt_clean_state(tr);
    }
}

/**
 * tr_event_notifier -
 *
 * Topo-Routing module main Event handler
 */
static void
tr_event_notifier(void *app_arg, void *pkt_arg)
{
	struct cbuf *b = pkt_arg;
	struct ofp_header *hdr;
	uint64_t dpid;
	if (!b) {
		c_log_err("%s: Invalid arg", FN);
		return;
	}

	hdr = (void *)(b->data);

	switch(hdr->type) {
	case C_OFPT_SWITCH_ADD:
	{
		c_ofp_switch_add_t *ofp_sa = (void *)(hdr);
		dpid = ntohll(ofp_sa->datapath_id);
		if (lldp_switch_add(app_arg, ofp_sa) == 0)
			c_log_debug("LLDP Switch 0x%llx added", (unsigned long long) dpid);

		break;
	}
	case C_OFPT_SWITCH_DELETE:
	{
		c_ofp_switch_delete_t *ofp_sd = (void *)(hdr);
		dpid =  ntohll(ofp_sd->datapath_id);
		lldp_switch_delete(dpid);
		c_log_debug("LLDP Switch 0x%llx deleted", (unsigned long long)dpid);

		break;
	}
	case C_OFPT_PACKET_IN:
	{
		c_ofp_packet_in_t *ofp_pin = (void *)(hdr);

		tr_packet_in_handler(ofp_pin);

		break;
	}
	case C_OFPT_PORT_STATUS:
	{
		c_ofp_port_status_t *ofp_psts = (void *)(hdr);
		/*            c_log_debug("Switch 0x%llx port status", (unsigned long long) ntohll(ofp_psts->datapath_id)); */
		tr_port_status_handler(app_arg, ofp_psts);
		break;
	}
	case C_OFPT_RECONN_APP:
		mul_register_app(NULL, TR_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                         0, NULL, tr_event_notifier);
		break;
	case C_OFPT_NOCONN_APP:
		/*
		 * FIXME : This is not optimal. What we really need is
		 * wait for reconn and stale out switches which might go
		 * during wait period. And the delete all fdbs for existing
		 * switches which we might have learnt to maintain coherency.
		 */
        tr_cleanall(tr_hdl);
		break;
	default:
		c_log_err("%s: Unknown event type %u", FN, hdr->type);
		return;
	}
}

/**
 * tr_module_init -
 */
void
tr_module_init(void *ctx)
{
	tr_struct_t *tr = NULL;

	c_log_debug("%s", FN);

	tr = calloc(1, sizeof(tr_struct_t));
	if (!tr) {
		c_log_err("%s: alloc failed", FN);
		return;
	}

    tr->app_ctx = ctx;
	tr_hdl = tr;

#ifdef CONFIG_MUL_RT
    mul_route_init(tr);
#endif

    tr->rt.rt_next_trigger_ts = time(NULL) + RT_INIT_TRIGGER_TS;

    mul_lldp_init(tr);
    
    tr->tr_service = tr_create_service(tr);
    if (!tr->tr_service) {
        c_log_err("%s: TR service could not be created", FN);
        /* We can still continue albeit with some limited ability */
    }

    mul_register_app(NULL, TR_APP_NAME, C_APP_ALL_SW, C_APP_ALL_EVENTS,
                     0, NULL, tr_event_notifier);
}

/**
 * tr_vty_init -
 */
void
tr_vty_init(void *arg UNUSED)
{
    lldp_vty_init(tr_hdl);
    route_vty_init(tr_hdl);
}

module_init(tr_module_init);
module_vty_init(tr_vty_init);
