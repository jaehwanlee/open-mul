/*  mul_lldp.c: MUL lldp framework  
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

topo_hdl_t *topo_hdl;

/** 
 * __lldp_get_max_switch_alias -
 *
 * Return the max switch alias in lldp db
 */
int
__lldp_get_max_switch_alias(topo_hdl_t *topo)
{
    return topo->max_sw_alias;
}

/** 
 * __lldp_get_num_switches -
 *
 * Return the number of switches in lldp db
 */
int
__lldp_get_num_switches(topo_hdl_t *topo)
{
    return g_hash_table_size(topo->switches);
}

/**
 * lldp_send_rt_neigh_conn -
 *
 * Send a neigh connection betwenn two switches to routing module 
 */
static void 
lldp_send_rt_neigh_conn(void *port_arg, void *u_arg)
{
    tr_neigh_query_arg_t *neigh_query = u_arg;
    lldp_port_t *port = port_arg;
    lweight_pair_t lw_pair;

    assert(neigh_query && neigh_query->tr);

    lw_pair.la = port->port_no;
    lw_pair.lb = port->neighbor_port;
    lw_pair.weight = NEIGH_DFL_WEIGHT;

    if (neigh_query->tr->rt.rt_add_neigh_conn) {
        neigh_query->tr->rt.rt_add_neigh_conn(neigh_query->tr, 
                                              neigh_query->src_sw,
                                              neigh_query->dst_sw,
                                              &lw_pair);
    }

    return;
}

/**
 * __lldp_init_neigh_pair_adjacencies -
 *
 * Send neigh connections betwenn two switches to routing module 
 * NOTE - lockless version expects locking by the caller
 */
void
__lldp_init_neigh_pair_adjacencies(tr_neigh_query_arg_t *arg) 
{
    topo_hdl_t *topo;
    lldp_switch_t *from_sw, *to_sw;
    lldp_neigh_t *neighbour;
    int locked = 0;

    if (!arg) {
        c_log_err("%s: Invalid arg", FN);
        return;
    }

    topo = arg->tr->topo_hdl;

    from_sw = lldp_get_switch_from_imap(topo, arg->src_sw);
    to_sw = lldp_get_switch_from_imap(topo, arg->dst_sw);

    if (!from_sw || !to_sw) {
        c_log_err("%s: NULL switch args", FN);
        return;
    }

    locked = !c_rd_trylock(&from_sw->lock);

    neighbour = g_hash_table_lookup(from_sw->neighbors, &to_sw->dpid);

    if (!neighbour) {
        if (locked) c_rd_unlock(&from_sw->lock);
        //c_log_err("%s: lldp neigh %llx of %llx not found", 
        //          FN, to_sw->dpid, from_sw->dpid);
        return;
    }

    lldp_traverse_all_neigh_ports(neighbour, lldp_send_rt_neigh_conn, 
                                  (void *)arg);
    
    if (locked) c_rd_unlock(&from_sw->lock);
}

/**
 * lldp_switch_traverse_all -
 *
 * Traverse through all the switch list calling iter_fn for each switch found 
 */
void 
lldp_switch_traverse_all(topo_hdl_t *topo_hdl, GHFunc iter_fn, void *arg)
{   

    c_rd_lock(&topo_hdl->switch_lock);
    if (topo_hdl->switches) {
        g_hash_table_foreach(topo_hdl->switches,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&topo_hdl->switch_lock);

}

/**
 * __lldp_switch_traverse_all -
 *
 * Traverse through all the switch list calling iter_fn for each switch found 
 * Lockless version
 */
static void 
__lldp_switch_traverse_all(topo_hdl_t *topo_hdl, GHFunc iter_fn, void *arg)
{   

    if (topo_hdl->switches) {
        g_hash_table_foreach(topo_hdl->switches,
                             (GHFunc)iter_fn, arg);
    }
}


/**
 * lldp_port_traverse_all -
 *
 * Traverse through all the ports of a switch calling iter_fn for each port 
 */
void
lldp_port_traverse_all(lldp_switch_t *lldpsw, GHFunc iter_fn, void *arg)
{

    c_rd_lock(&lldpsw->lock);
    if (lldpsw->ports) {
        g_hash_table_foreach(lldpsw->ports, (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&lldpsw->lock);

    return;
}

/**
 * __lldp_port_traverse_all -
 *
 * Traverse through all the ports of a switch calling iter_fn for each port 
 * (Lockless version)
 */
static void
__lldp_port_traverse_all(lldp_switch_t *lldpsw, GHFunc iter_fn, void *arg)
{

    if (lldpsw->ports) {
        g_hash_table_foreach(lldpsw->ports, (GHFunc)iter_fn, arg);
    }

    return;
}

/**
 * __lldp_num_ports_in_switch -
 *
 * Return the number of ports in a switch 
 * (Lockless version)
 */
static unsigned int
__lldp_num_ports_in_switch(lldp_switch_t *lldpsw)
{
    if (lldpsw->ports) {
       return g_hash_table_size(lldpsw->ports);
    }

    return 0;
}

/**
 * lldp_port_find -
 *
 * Find and return a port in a switch 
 * Note it is assumed that a reference to switch is held prior to call
 */
lldp_port_t * 
lldp_port_find(lldp_switch_t *lldp_sw, uint16_t port_id)
{
    lldp_port_t *this_port = NULL;

    c_wr_lock(&lldp_sw->lock);

    if (!(this_port = g_hash_table_lookup(lldp_sw->ports, &port_id))){
        c_wr_unlock(&lldp_sw->lock);
        return NULL;
    }

    c_wr_unlock(&lldp_sw->lock);

    return this_port;
}

/**
 * __lldp_port_find -
 *
 * Find and return a port in a switch 
 * (lockless version - switch lock to held during call)
 */
lldp_port_t * 
__lldp_port_find(lldp_switch_t *lldp_sw, uint16_t port_id)
{
    lldp_port_t *this_port = NULL;

    if (!(this_port = g_hash_table_lookup(lldp_sw->ports, &port_id))){
        return NULL;
    }

    return this_port;
}


/**
 * lldp_embed_neigh_info_in_service -
 *
 * Embed neigh info in a service request
 */
static void
lldp_embed_neigh_info_in_service(void *key UNUSED, void *sw_arg, void *uarg)
{
	lldp_port_t *port = (lldp_port_t *)sw_arg;
    struct c_ofp_port_neigh *port_neigh = *(struct c_ofp_port_neigh **)(uarg);

    memset(port_neigh, 0, sizeof(*port_neigh));
    port_neigh->port_no = htons(port->port_no);
	if (port->status == LLDP_PORT_STATUS_NEIGHBOR) {
        port_neigh->neigh_present = htons(COFP_NEIGH_SWITCH);
        port_neigh->neigh_dpid = htonll(port->neighbor_dpid);
		port_neigh->neigh_port = htons(port->neighbor_port);
	}

    *(struct c_ofp_port_neigh **)(uarg) = (port_neigh + 1);
}

/**
 * lldp_service_neigh_request -
 *
 * Handle a neigh service request
 */
struct cbuf *
lldp_service_neigh_request(uint64_t dpid, uint32_t xid)
{
    lldp_switch_t *lldpsw;
    size_t num_ports;
    struct c_ofp_auxapp_cmd *cofp_auc;
    struct c_ofp_switch_neigh *cofp_sn;
    void *neigh_port_data;
    struct cbuf *b;
    
    lldpsw = fetch_and_retain_switch(dpid);
    if (!lldpsw){
        c_log_err("%s: switch(0x%llx) does not exist", FN, 
                  (unsigned long long)dpid);
        return NULL;
    }

    c_rd_lock(&lldpsw->lock);

    num_ports = __lldp_num_ports_in_switch(lldpsw); 
    b = of_prep_msg(sizeof(struct c_ofp_auxapp_cmd) + 
                    sizeof(struct c_ofp_switch_neigh) +
                    (num_ports * sizeof(struct c_ofp_port_neigh)), 
                    C_OFPT_AUX_CMD, xid);

    cofp_auc = (void *)(b->data);
    cofp_auc->cmd_code = htonl(C_AUX_CMD_TR_NEIGH_STATUS);
    cofp_sn = (void *)(cofp_auc->data);
    cofp_sn->switch_id.datapath_id = htonll(dpid);
    neigh_port_data = cofp_sn->data;

    __lldp_port_traverse_all(lldpsw, lldp_embed_neigh_info_in_service, 
                             (void *)(&neigh_port_data));

    c_rd_unlock(&lldpsw->lock);

    lldp_switch_unref(lldpsw);

    return b;
}


/**
 * lldp_port_connect_to_neigh -
 *
 * Connect switches at one end
 * This has to be called with switch lock(write) held
 */
static int
lldp_port_connect_to_neigh(lldp_switch_t *this_switch, lldp_port_t *this_port, 
                           uint64_t other_id, uint16_t other_port_id, time_t ttl)
{
    lldp_neigh_t *neighbor;

    /* usual switch and port struct access*/
    if (!this_switch || !this_port){
        c_log_err("%s: Null switch or port args", FN);
        return -1;
    }

    if (this_port->status == LLDP_PORT_STATUS_NEIGHBOR && 
        this_port->neighbor_dpid == other_id &&
        this_port->neighbor_port == other_port_id) {

        /* If everything remains the same just refresh the timestamp */
        this_port->ttl = ttl;

        //c_log_debug("%s: Refreshed 0x%llx %hu <-> 0x%llx %hu",
        //            FN, this_switch->dpid, this_port->port_no,
        //            (unsigned long long)other_id, other_port_id);

        return 0;
    }

    /* Mark port as connected, and fill in neighbor info */
    this_port->status = LLDP_PORT_STATUS_NEIGHBOR;
    this_port->neighbor_dpid = other_id;
    this_port->neighbor_port = other_port_id;
    this_port->ttl = ttl;

    /* populate neighbor lookup table */
    if ((neighbor = g_hash_table_lookup(this_switch->neighbors, 
                                        &this_port->neighbor_dpid))) {
        /*
         * Neighbor switch is already connected by other port 
         * (just to prevent duplicate)
         */
        neighbor->ports = g_slist_remove_all(neighbor->ports, this_port); 
    } else {
        /* new neighbor */
        neighbor = malloc(sizeof(lldp_neigh_t));
        if (!neighbor){
            c_log_err("%s: failed to alloc port_list", FN);
            return -1;
        }
        neighbor->other_dpid = this_port->neighbor_dpid;
        neighbor->ports = NULL;

        g_hash_table_insert(this_switch->neighbors,
                            &neighbor->other_dpid, neighbor);
    }

    /* add this port to the list of ports */
    neighbor->ports = g_slist_append(neighbor->ports, this_port); 

    c_log_debug("%s:switch %llx port %u <-> switch %llx port %u ", 
                FN, (unsigned long long)this_switch->dpid, this_port->port_no,
                (unsigned long long)other_id, other_port_id);

    tr_invoke_routing(topo_hdl->tr);

    return 0;
}

/**
 * lldp_port_disconnect_to_neigh -
 *
 * Destroy switch connections at one end or full pair
 * This has to be called with switch lock(write) held
 */
void
lldp_port_disconnect_to_neigh(lldp_switch_t *this_switch, 
                              lldp_port_t *this_port,
                              uint16_t port_id, 
                              bool need_lock,
                              bool tear_pair)
{
    lldp_neigh_t *neighbor;

    /* usual switch/port retrieval*/
    if (!this_switch){
        c_log_err("%s: NUll switch arg", FN);
        return;
    }

    /* To prevent any race condition */
    assert(!this_port || !need_lock);

    if (need_lock)
        c_wr_lock(&this_switch->lock);

    if (!this_port) {
        if (!(this_port = g_hash_table_lookup(this_switch->ports, &port_id))){
            c_log_err("%s: unknown port %hx for switch %llx" ,FN, 
                      port_id, (unsigned long long)this_switch->dpid);
            goto out_err;
        }
    }

    if (this_port->status != LLDP_PORT_STATUS_NEIGHBOR){
        c_log_debug("%s: Port %u of switch %llx has no neigh",
                    FN, this_port->port_no, 
                    (unsigned long long)this_switch->dpid);
        goto out_err;
    }   

    if (this_switch->neighbors && 
        (neighbor = g_hash_table_lookup(this_switch->neighbors, 
                                        &this_port->neighbor_dpid))) {
        g_hash_table_remove(this_switch->neighbors, &this_port->neighbor_dpid);
    }

    /* mark port as 'disconnected' */
    this_port->status = LLDP_PORT_STATUS_INIT;

    c_log_debug("%s: port %hx of switch %llx -> marked no neigh" ,FN, 
                this_port->port_no, (unsigned long long)this_switch->dpid);

    if (need_lock) c_wr_unlock(&this_switch->lock);

    if (tear_pair) {
        if (!(this_switch = fetch_and_retain_switch(this_port->neighbor_dpid))) {
            c_log_err("%s: Unknown switch %llx" ,FN,
                      (unsigned long long)this_port->neighbor_dpid);
            return;
        }

        c_wr_lock(&this_switch->lock);
        if (!(this_port =  __lldp_port_find(this_switch, 
                                            this_port->neighbor_port))) {
            c_log_err("%s: unknown port %hx for switch %llx" ,FN,
                      this_port->neighbor_port, 
                      (unsigned long long)this_switch->dpid);
            c_wr_unlock(&this_switch->lock);
            return;
        }

        lldp_port_disconnect_to_neigh(this_switch,
                                      this_port,
                                      this_port->neighbor_port,
                                      false, false);
        c_wr_unlock(&this_switch->lock);
        lldp_switch_unref(this_switch);
    }

    tr_invoke_routing(topo_hdl->tr);

    return;

out_err:
    if (need_lock) c_wr_unlock(&this_switch->lock);
    return;
}

void
lldp_traverse_all_neigh_ports(lldp_neigh_t *neigh, GFunc iter_fn, void *u_arg)
{
    g_slist_foreach(neigh->ports, iter_fn, u_arg);
}

/**
 * connect_lldp_switch_neigh_pair -
 *
 * Connect two ports making each switch as neighbors
 */
static int
connect_lldp_switch_neigh_pair(uint64_t switch_id, 
                               uint16_t port_id,
                               uint64_t neigh_switch_id, 
                               uint16_t neigh_port_id, 
                               time_t ttl)
{
    lldp_switch_t *lldp_switch;
    lldp_port_t *lldp_port;

    if (!(lldp_switch = fetch_and_retain_switch(switch_id))) {
        c_log_err("%s: No switch 0x%llx found", 
                  FN, (unsigned long long)switch_id);
        return -1;
    }

    c_wr_lock(&lldp_switch->lock);
    if (!(lldp_port = __lldp_port_find(lldp_switch, port_id))) {
        c_log_err("%s: port %hu 0x%llx not found", 
                  FN, port_id, (unsigned long long)switch_id);
        goto err_out;
    }

    if (lldp_port_connect_to_neigh(lldp_switch, lldp_port, 
                                   neigh_switch_id, neigh_port_id, ttl)){
        goto err_out;
    }

    c_wr_unlock(&lldp_switch->lock);
    lldp_switch_unref(lldp_switch); 

    return 0;

err_out:
    c_wr_unlock(&lldp_switch->lock);
    lldp_switch_unref(lldp_switch);

    return -1;
}

/**
 * lldp_switch_add -
 *
 * Switch add event Handler
 */
int
lldp_switch_add(void *app_arg, c_ofp_switch_add_t *ofp_sa)
{
    uint64_t dpid = ntohll(ofp_sa->datapath_id);
    lldp_switch_t *new_switch;
    struct ofp_phy_port *port;
    uint16_t i;
    uint16_t num_port;
    struct flow fl;      /* Flow entry for lldp packer handler */
    uint32_t wildcards = OFPFW_ALL;

    c_wr_lock(&topo_hdl->switch_lock);

    if (g_hash_table_lookup(topo_hdl->switches,&dpid)){
        c_wr_unlock(&topo_hdl->switch_lock);
        c_log_err("%s: switch (0x%llx) already exists", FN, 
                  (unsigned long long)dpid);
        return -1;
    }

    if (!(new_switch = calloc(1, sizeof(*new_switch)))) {
        c_wr_unlock(&topo_hdl->switch_lock);
        c_log_err("%s: lldp_switch alloc failed", FN);
        return -1;
    }

    new_switch->dpid = dpid;
    new_switch->alias_id = C_GET_ALIAS_IN_SWADD(ofp_sa);
    if (lldp_add_switch_to_imap(topo_hdl, new_switch) < 0) {
        c_wr_unlock(&topo_hdl->switch_lock);
        c_log_err("%s: lldp_switch imap add failed", FN);
        goto err_free;
    }

    new_switch->ports = g_hash_table_new_full(portid_hash_func, 
                                              portid_equal_func, 
                                              NULL, NULL);
    if (!new_switch->ports){
        c_wr_unlock(&topo_hdl->switch_lock);
        c_log_err("%s: Error in ports table alloc", FN);
        goto err_putalias;
    }

    new_switch->neighbors = g_hash_table_new_full(dpid_hash_func, 
                                                  dpid_equal_func, 
                                                  NULL, 
                                                  lldp_neigh_portlist_destroy);
    if (!new_switch->neighbors){
        c_wr_unlock(&topo_hdl->switch_lock);
        c_log_err("%s: Error in neighbors table alloc", FN);
        goto err_free_ports;
    }

    c_rw_lock_init(&new_switch->lock);
    lldp_switch_ref(new_switch);

    num_port = ( ntohs((ofp_sa->header).length) - 
                sizeof(c_ofp_switch_add_t) ) / sizeof(struct ofp_phy_port);

    for (i = 0; i < num_port; i++){
        port = &((struct ofp_phy_port *) &(ofp_sa[1]))[i];
        lldp_port_add(app_arg, new_switch, port, false);
    }


    g_hash_table_insert(topo_hdl->switches, &new_switch->dpid, new_switch);

    if (new_switch->alias_id > topo_hdl->max_sw_alias) { 
        topo_hdl->max_sw_alias = new_switch->alias_id;
    }

    c_wr_unlock(&topo_hdl->switch_lock);

    /* Clear all entries for this switch */
    mul_app_send_flow_del(MUL_TR_SERVICE_NAME, NULL, dpid, &fl,
                          OFPFW_ALL, OFPP_NONE, 0, C_FL_ENT_NOCACHE);

    /* Add Flow to receive LLDP Packet type */
    memset(&fl, 0, sizeof(fl));
    wildcards &= ~(OFPFW_DL_TYPE);
    fl.dl_type = htons(0x88cc);


    mul_app_send_flow_add(MUL_TR_SERVICE_NAME, app_arg, dpid, &fl, (uint32_t)-1,
                          NULL, 0, 0, 0, wildcards, C_FL_PRIO_DFL,
                          C_FL_ENT_LOCAL);

    return 0;

err_free_ports:
    g_hash_table_destroy(new_switch->ports);
err_putalias:
    lldp_del_switch_from_imap(topo_hdl, new_switch);
err_free:
    free(new_switch);
    return -1;
}

/**
 * lldp_max_alias_finder -
 *
 * Max switch alias finder helper routine 
 */
static void
lldp_max_alias_finder(void *key UNUSED, void *sw_arg, void *uarg)
{
    lldp_switch_t *sw = (lldp_switch_t *)sw_arg;
    topo_hdl_t *hdl = uarg;

    if (sw->alias_id > hdl->max_sw_alias) {
        hdl->max_sw_alias = sw->alias_id;
    }

}

/**
 * __lldp_max_aliasid_reset -
 *
 * Reset the max switch alias 
 */
static void
__lldp_max_aliasid_reset(topo_hdl_t *hdl)
{
    hdl->max_sw_alias = -1;
    __lldp_switch_traverse_all(topo_hdl, lldp_max_alias_finder, topo_hdl);
}

/**
 * lldp_switch_delete -
 *
 * Switch delete event handler
 */
void
lldp_switch_delete(uint64_t dpid)
{
    c_wr_lock(&topo_hdl->switch_lock);

    /* rest of deleting handled by destroy callback */
    g_hash_table_remove(topo_hdl->switches, &dpid);

    __lldp_max_aliasid_reset(topo_hdl);

    c_wr_unlock(&topo_hdl->switch_lock);

    c_log_debug("%s: switch (0x%lld) removed.",FN,(unsigned long long)dpid);
}

/**
 * lldp_packet_handler -
 *
 * LLDP Packet Handler
 */
int
lldp_packet_handler(uint64_t receiver_id, uint16_t receiver_port, lldp_pkt_t *pkt)
{

    uint64_t sender_id;
    uint16_t sender_port;
    //lldp_sent_pkt_t pkt_info;
    time_t ttl; /* connection must be refreshed after ttl */

    /* check pkt validity */
    if (pkt->chassis_tlv_type != LLDP_CHASSIS_ID_TLV ||
        pkt->chassis_tlv_subtype != LLDP_CHASSIS_ID_LOCALLY_ASSIGNED ||
        pkt->port_tlv_type != LLDP_PORT_ID_TLV ||
        pkt->port_tlv_subtype != LLDP_PORT_ID_LOCALLY_ASSIGNED ||
        pkt->ttl_tlv_type != LLDP_TTL_TLV ||
        pkt->end_of_lldpdu_tlv_type != LLDP_END_OF_LLDPDU_TLV) {
        c_log_debug("%s: invalid packet marked as lldp packet",FN);
        return -1;
    }

    /* retrieve sender info */
    sender_id = ntohll(pkt->chassis_tlv_id);
    sender_port = ntohs(pkt->port_tlv_id);

    /* Validation passed! Safe to connect two switches */
    ttl = time(NULL) + ntohs(pkt->ttl_tlv_ttl);

    //c_log_debug("%s:switch %llx port %u <-> switch %llx port %u ttl(%us)", 
    //            FN, (unsigned long long) sender_id, sender_port,
    //            (unsigned long long)receiver_id, receiver_port, 
    //            ntohs(pkt->ttl_tlv_ttl));

    return connect_lldp_switch_neigh_pair(receiver_id, receiver_port, 
                                          sender_id, sender_port, ttl);
}

/**
 * lldp_port_add -
 *
 * Adds new port to specified switch
 */
int
lldp_port_add(void *app_arg, lldp_switch_t *this_switch, 
              struct ofp_phy_port *port_info, bool need_lock)
{
    uint32_t config_mask;
    uint32_t state_mask;
    lldp_port_t *new_port;

    uint16_t port_no = ntohs(port_info->port_no);

    if (port_no > OFPP_MAX){
        /* ignore control ports */
        return 0;
    }

    c_log_debug("%s: adding %u to switch 0x%llx", FN, port_no, 
                (unsigned long long)this_switch->dpid);

    if (need_lock) {
        c_wr_lock(&this_switch->lock);
    }

    if (__lldp_port_find(this_switch, port_no)) { 
        /* port with specified port id already exists */
        c_log_err("%s: switch 0x%llx port 0x%hx already exists",
                  FN, (unsigned long long)this_switch->dpid, port_no);
        goto err_out;
    }

    /* prepare lldp_port_t entry*/
    new_port = calloc(1, sizeof(lldp_port_t));
    if (!new_port) {
        c_log_err("%s: failed to alloc port 0x%hx to switch 0x%llx",
                  FN, port_no, (unsigned long long)this_switch->dpid);
        goto err_out;
    }
    new_port->lldp_sw = this_switch;
    new_port->config = ntohl(port_info->config);
    new_port->state = ntohl(port_info->state);
    new_port->status = LLDP_PORT_STATUS_INIT;
    new_port->port_no = port_no;
    memcpy(new_port->hw_addr,port_info->hw_addr,OFP_ETH_ALEN);

    /* add port to switch entry */
    g_hash_table_insert(this_switch->ports, &(new_port->port_no), new_port);

    config_mask = ntohl(port_info->config);
    state_mask = ntohl(port_info->state);

    /* if port is connected to something send lldp packet */
    if (!(config_mask & OFPPC_PORT_DOWN) && !(state_mask & OFPPS_LINK_DOWN)) {
        lldp_tx(app_arg, this_switch, new_port);
    } else {
        c_log_debug("%s:Port %u of switch %llx is down", 
                    FN, port_no, (unsigned long long)this_switch->dpid);
    }

    if (need_lock) {
        c_wr_unlock(&this_switch->lock);
    }

    return 0;

err_out:
    if (need_lock) {
        c_wr_unlock(&this_switch->lock);
    }

    return -1;
}

/**
 * lldp_port_add_with_dpid -
 *
 * Adds new port to specified switch given switch's dpid
 */
static void
lldp_port_add_with_dpid(void *app_arg, uint64_t dpid,
                        struct ofp_phy_port *port_info) 
{
    lldp_switch_t *lldp_sw;

    if(!(lldp_sw = fetch_and_retain_switch(dpid))) {
        c_log_err("%s: No switch 0x%llx found", FN, dpid);
    }

    lldp_port_add(app_arg, lldp_sw, port_info, true);

    lldp_switch_unref(lldp_sw);
    
}

/**
 * lldp_port_mod -
 *
 * PORT_MOD event handler
 */
static int
lldp_port_mod(void *app_arg, uint64_t switch_id, c_ofp_port_status_t *ofp_psts)
{
    lldp_switch_t *this_switch = NULL;
    lldp_port_t *this_port = NULL;
    struct ofp_phy_port *ofpp = &ofp_psts->desc;
    uint32_t config_mask, state_mask;
    uint16_t port_no;

    port_no = ntohs(ofp_psts->desc.port_no);
    if (port_no > OFPP_MAX){
        /* ignore control ports */
        return 0;
    }

    config_mask = ntohl(ofp_psts->config_mask);
    state_mask  = ntohl(ofp_psts->state_mask);

    if (!config_mask || !state_mask) {
        return 0;
    }

    if (!(this_switch = fetch_and_retain_switch(switch_id))) {
        c_log_err("%s: Switch-id 0x%llx not found", FN, switch_id);
        return -1;
    }

    c_wr_lock(&this_switch->lock);
    if (!(this_port = __lldp_port_find(this_switch, port_no))) {
        c_log_err("%s: Switch-id 0x%llx port %hu not found", 
                  FN, switch_id, port_no);
        c_wr_unlock(&this_switch->lock);
        lldp_switch_unref(this_switch);
        return -1;
    }

    this_port->state = ntohl(ofpp->state);
    this_port->config = ntohl(ofpp->config);

    if (this_port->config & OFPPC_PORT_DOWN ||
        this_port->state & OFPPS_LINK_DOWN) {

        /* The port was connected to some other switch,
         * but the port is administratively disabled or link is disconnected.
         */
        c_log_debug("%s: switch 0x%llx port(%u)->DOWN", 
                    FN, this_switch->dpid, port_no);

        lldp_port_disconnect_to_neigh(this_switch, this_port, 0, false, true); 

    } else {
        c_log_debug("%s: switch 0x%llx port(%u)->UP", 
                    FN, this_switch->dpid, port_no);

        lldp_tx(app_arg, this_switch, this_port);
    }

    c_wr_unlock(&this_switch->lock);
    lldp_switch_unref(this_switch);

    return 0;
}

/**
 * lldp_port_delete -
 *
 * PORT_STATUS - PORT_DELETE event handler
 */
static int
lldp_port_delete(uint64_t switch_id, struct ofp_phy_port *port_info)
{
    lldp_switch_t *this_switch;
    lldp_port_t *this_port;
    uint16_t port_no = ntohs(port_info->port_no);

    if (port_no > OFPP_MAX){
        /* ignore control ports */
        return 0;
    }

    /* get switch/port */
    this_switch = fetch_and_retain_switch(switch_id);
    c_wr_lock(&this_switch->lock);
    if (!(this_port = g_hash_table_lookup(this_switch->ports,&port_no))){
        c_wr_unlock(&this_switch->lock);
        lldp_switch_unref(this_switch);
        c_log_debug("%s: port %hx not found (switch 0x%llx)", 
                    FN, port_no, (unsigned long long) switch_id);
        return -1;
    }

    lldp_port_disconnect_to_neigh(this_switch, this_port, 0, false, true);

    /* delete port */
    g_hash_table_remove(this_switch->ports, &port_no);

    free(this_port);

    c_wr_unlock(&this_switch->lock);
    lldp_switch_unref(this_switch);

    return 0;
}


/**
 * lldp_port_status_handler -
 *
 * PORT_STATUS event handler
 */
void
lldp_port_status_handler(void *app_arg, c_ofp_port_status_t *port_stat)
{
    uint64_t receiver_id = ntohll(port_stat->datapath_id);

    switch (port_stat->reason){
    case OFPPR_ADD:
        lldp_port_add_with_dpid(app_arg, receiver_id, &port_stat->desc);
        break;
    case OFPPR_MODIFY:
        lldp_port_mod(app_arg, receiver_id, port_stat);
        break;
    case OFPPR_DELETE:
        lldp_port_delete(receiver_id, &port_stat->desc);
        break;
    default:
        c_log_err("%s: unknown reason %d", FN, port_stat->reason);
        break;
    }
}


/**
 * lldp_cleanall_switches -
 *
 * Delete all switch and related info
 */
void 
lldp_cleanall_switches(tr_struct_t *tr)
{
    topo_hdl_t *topo_hdl = tr->topo_hdl;
    g_hash_table_remove_all(topo_hdl->switches);
}

/**
 * lldp_create_packet -
 *
 * Generates LLDP_PACKET with source switch id/port into specified buffer
 */
static void
lldp_create_packet(void *src_addr, uint64_t srcId, uint16_t srcPort, 
                   lldp_pkt_t *buffer)
{
    uint8_t dest_addr[OFP_ETH_ALEN] = {0x01,0x80,0xc2,0x00,0x00,0x0e};

    memcpy(buffer->eth_head.dest_addr,dest_addr,OFP_ETH_ALEN);
    memcpy(buffer->eth_head.src_addr,src_addr,OFP_ETH_ALEN);
    buffer->eth_head.ethertype = htons(0x88cc);
    buffer->chassis_tlv_type = LLDP_CHASSIS_ID_TLV;
    buffer->chassis_tlv_length = sizeof(uint64_t) + 1;
    buffer->chassis_tlv_subtype = LLDP_CHASSIS_ID_LOCALLY_ASSIGNED;
    buffer->chassis_tlv_id = htonll(srcId);
    buffer->port_tlv_type = LLDP_PORT_ID_TLV;
    buffer->port_tlv_length = sizeof(uint16_t) + 1;
    buffer->port_tlv_subtype = LLDP_PORT_ID_LOCALLY_ASSIGNED;
    buffer->port_tlv_id = htons(srcPort);
    buffer->ttl_tlv_type = LLDP_TTL_TLV;
    buffer->ttl_tlv_length = 2;
    buffer->ttl_tlv_ttl = htons(LLDP_DEFAULT_TTL);
    buffer->end_of_lldpdu_tlv_type = LLDP_END_OF_LLDPDU_TLV;
    buffer->end_of_lldpdu_tlv_length = 0;
}

/**
 * lldp_tx -
 *
 * Send lldp packet out from specified switch id and port
 */
void
lldp_tx(void *app_arg, lldp_switch_t *lldp_switch, lldp_port_t *lldp_port)
{
    struct of_pkt_out_params params;
    struct ofp_action_output op_act;
    lldp_pkt_t lldp_data;
    uint8_t debug_hwaddr_buf[LLDP_HWADDR_DEBUG_STRING_LEN];

    assert(lldp_switch && lldp_port);

    /* create lldp packet */
    lldp_create_packet(lldp_port->hw_addr, lldp_switch->dpid, 
                       lldp_port->port_no, &lldp_data);

    conv_hwaddr(lldp_port->hw_addr, debug_hwaddr_buf);

    /* prepare required params for mul_app_send_pkt_out */
    params.buffer_id = (uint32_t)(-1);
    params.in_port = OFPP_NONE;
    params.action_list = &op_act;
    of_make_action_output((char **)&params.action_list, sizeof(op_act), 
                          lldp_port->port_no);
    params.action_len = sizeof(op_act);
    params.data_len = sizeof(lldp_pkt_t);
    params.data = &lldp_data;

    /* tx the packet */
    mul_app_send_pkt_out(app_arg, lldp_switch->dpid, &params);

}

/**
 * __lldp_per_port_timer -
 *
 * Per port timer
 */
static void
__lldp_per_port_timer(UNUSED void *key, void *value, void *time_arg)
{
    time_t curr_time = *(time_t *)time_arg;
    lldp_port_t *this_port = (lldp_port_t *)value;
    lldp_switch_t *this_switch = this_port->lldp_sw;

    if (this_port->status == LLDP_PORT_STATUS_NEIGHBOR) {

        /* link expired ? */
         if (this_port->ttl <= curr_time) {
            c_log_debug("%s:switch 0x%llx port %u <-> "
                        "switch 0x%llx port %u expired",
                        FN, (unsigned long long) this_switch->dpid, 
                        this_port->port_no, 
                        (unsigned long long)this_port->neighbor_dpid, 
                        this_port->neighbor_port);

            lldp_port_disconnect_to_neigh(this_switch, this_port, 0, false, true);
            return;
        }
    } 

    if(!this_port->next_probe || this_port->next_probe <= curr_time) {
        //c_log_debug("Probe switch 0x%llx port %u <-> "
        //            "switch 0x%llx port %u",
        //            (unsigned long long) this_switch->dpid, 
        //            this_port->port_no,
        //            (unsigned long long)this_port->neighbor_dpid,
        //            this_port->neighbor_port);
        this_port->next_probe = curr_time + LLDP_PROBE_PORT_INTERVAL;
        lldp_tx(NULL, this_switch, this_port);
    }

}  


/**
 * lldp_per_switch_timer -
 *
 * Check if any ports in a switch is expired. (check_time > ttl)
 */
static void
lldp_per_switch_timer(void *key UNUSED, void *value, void *arg)
{
    lldp_switch_t *this_switch = (lldp_switch_t *)value;

    /** 
     * This function should be protected by topo_hdl readlock
     * and no switch should be freed.
     */
    c_wr_lock(&this_switch->lock);

    if (this_switch->ports){
        g_hash_table_foreach(this_switch->ports, __lldp_per_port_timer,
                             arg);
    }

    c_wr_unlock(&this_switch->lock);
}

/**
 * lldp_update_timer -
 *
 * Main Housekeep Timer
 */
static void
lldp_update_timer(evutil_socket_t fd UNUSED, short event UNUSED, void *arg)
{

    topo_hdl_t *hdl = arg;
    struct timeval tv = { LLDP_UPDATE_INTVL_SEC , LLDP_UPDATE_INTVL_USEC };
    time_t check_time = time(NULL);

    c_rd_lock(&topo_hdl->switch_lock);
    g_hash_table_foreach(topo_hdl->switches, lldp_per_switch_timer, &check_time);
    c_rd_unlock(&topo_hdl->switch_lock);

    if (hdl->tr->rt.rt_trigger ||
        hdl->tr->rt.rt_next_trigger_ts <= check_time) {

        hdl->tr->rt.rt_trigger = false;
        c_wr_lock(&topo_hdl->switch_lock);
        __tr_invoke_routing(hdl->tr);
        c_wr_unlock(&topo_hdl->switch_lock);
        hdl->tr->rt.rt_next_trigger_ts = check_time + RT_PERIODIC_TRIGGER_TS;        
    }

    /* next event */
    evtimer_add(hdl->lldp_update_event, &tv);

}

/**
 * mul_lldp_init -
 *
 * LLDP module initialization routine 
 */
int
mul_lldp_init(tr_struct_t *tr)
{
    struct event_base *base = tr->app_ctx;
    struct timeval update_tv = { LLDP_UPDATE_INTVL_INIT_SEC,
                                 LLDP_UPDATE_INTVL_USEC };
    topo_hdl_t *hdl = NULL;

    c_log_debug("%s", FN);

    hdl = calloc(1, sizeof(topo_hdl_t));
    if (!hdl) {
        c_log_err("%s: alloc failed", FN);
        return -1;
    }

    lldp_init_sw_imap(hdl);

    c_rw_lock_init(&hdl->switch_lock);
    c_rw_lock_init(&hdl->pkt_lock);
    hdl->tr = tr; 
    hdl->switches = g_hash_table_new_full(dpid_hash_func,
                                          dpid_equal_func,
                                          NULL, lldp_switch_remove);
    hdl->lldp_update_event = evtimer_new(base, lldp_update_timer, (void *)hdl);
    evtimer_add(hdl->lldp_update_event, &update_tv);

    topo_hdl = hdl;
    tr->topo_hdl = hdl;

    return 0;
}
