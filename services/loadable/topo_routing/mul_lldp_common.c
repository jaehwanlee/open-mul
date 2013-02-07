/*  mul_lldp_common.c: Mul lldp common functions 
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

extern topo_hdl_t *topo_hdl;

/**
 * lldp_neigh_portlist_destroy -
 *
 * Destroy all neigh port lists
 */
void
lldp_neigh_portlist_destroy(void *key)
{
    lldp_neigh_t *neighbour = (lldp_neigh_t *)key;
    if (neighbour->ports) {
        g_slist_free(neighbour->ports);
        neighbour->ports = NULL;
    }
    free(neighbour);
}

/* 
 * lldp_per_port_remove -
 *
 * To be used only in lldp_switch_unref
 */
static void
lldp_per_port_remove(UNUSED void *key, void *value, void *switch_arg)
{
    lldp_switch_t *lldp_switch = switch_arg;
    lldp_port_t *port = (lldp_port_t *)value;

    c_wr_lock(&lldp_switch->lock);
    if (port->status == LLDP_PORT_STATUS_NEIGHBOR) {
        lldp_port_disconnect_to_neigh(lldp_switch, port, 0, false, false);
    }

    c_wr_unlock(&lldp_switch->lock);

    free(port);
}

/**
 * lldp_switch_unref - 
 *
 * Decrement ref count of switch. Destroy switch entry if ref count = 0 
 */
void
lldp_switch_unref(lldp_switch_t *lldp_switch)
{
    atomic_dec(&lldp_switch->ref, 1);

    //c_log_debug("%s: switch 0x%llx ref = %u", FN, 
    //               (unsigned long long) lldp_switch->dpid, 
    //               (unsigned int)atomic_read(&lldp_switch->ref)); 

    if (atomic_read(&lldp_switch->ref) == 0){
        /* safe to free switch */

        lldp_del_switch_from_imap(topo_hdl, lldp_switch);

        //if (lldp_switch->neighbors) {
        //    g_hash_table_destroy(lldp_switch->neighbors);
        //    lldp_switch->neighbors = NULL;
        //}

        if (lldp_switch->ports){
            /* destroy all ports */
            g_hash_table_foreach(lldp_switch->ports, lldp_per_port_remove, 
                                 lldp_switch);
            g_hash_table_destroy(lldp_switch->ports);
        }

        c_rw_lock_destroy(&lldp_switch->lock);

        c_log_debug("lldp (0x%llx) freed",(unsigned long long)lldp_switch->dpid);

        free(lldp_switch);
    }
}

/**
 * fetch_and_retain_switch - 
 *
 * Fetch and get reference to a switch 
 */
lldp_switch_t *
fetch_and_retain_switch(uint64_t dpid)
{
    lldp_switch_t *this_switch;
    c_rd_lock(&topo_hdl->switch_lock);

    this_switch = g_hash_table_lookup(topo_hdl->switches,&dpid);

    if (this_switch)
        lldp_switch_ref(this_switch);
        /*c_log_debug("%s: switch 0x%llx ref = %u", FN, dpid, 
                      (unsigned int) atomic_read(&this_switch->ref)); */
    c_rd_unlock(&topo_hdl->switch_lock);

    return this_switch;
}

/**
 * lldp_init_sw_imap -
 *
 * Initialize switch index map
 */ 
int
lldp_init_sw_imap(topo_hdl_t *topo)
{
    assert(topo);

    if (!topo->sw_imap) {
        topo->sw_imap = calloc(1, sizeof(lldp_alias_swmap_elem_t) * 
                               MAX_SWITCHES_PER_CLUSTER);
    } else {
        c_log_err("%s: Switch iMap already allocated", FN);
        return -1;
    }

    assert(topo->sw_imap);

    topo->max_sw_alias = -1;

    return 0;
}

/**
 * lldp_add_switch_to_imap -
 *
 * Add a switch to switch index map
 */ 
int
lldp_add_switch_to_imap(topo_hdl_t *topo, lldp_switch_t *sw)
{
    lldp_alias_swmap_elem_t *map_elem = NULL;

    assert(topo && topo->sw_imap); 

    if (sw->alias_id < 0 || sw->alias_id >= MAX_SWITCHES_PER_CLUSTER) {
        c_log_err("%s: Can't add to imap alias-id(%d) out of range", 
                  FN, sw->alias_id);
        return -1;
    }

    map_elem = (lldp_alias_swmap_elem_t *)(topo->sw_imap) + sw->alias_id;

    if (map_elem->lldp_sw)  {
        c_log_err("%s: id (%d) -> (%p)", FN,  sw->alias_id, map_elem->lldp_sw);
        return -1;
    }

    map_elem->lldp_sw = sw;

    return 0;
}


/**
 * lldp_del_switch_from_imap -
 *
 * Delete a switch from switch index map
 */ 
void
lldp_del_switch_from_imap(topo_hdl_t *topo, lldp_switch_t *sw)
{
    lldp_alias_swmap_elem_t *map_elem = NULL;

    assert(topo && topo->sw_imap); 

    if (sw->alias_id < 0 || sw->alias_id >= MAX_SWITCHES_PER_CLUSTER) {
        c_log_err("%s: Can't add to imap alias-id(%d) out of range", 
                  FN, sw->alias_id);
        return;
    }

    map_elem = (lldp_alias_swmap_elem_t *)(topo->sw_imap) + sw->alias_id;

    map_elem->lldp_sw = NULL;


   c_log_err("%s: id (%d) -> (%p)", FN,  sw->alias_id, map_elem->lldp_sw);
}
