/*
 *  mul_fabric_switches.c: Fabric switch  manager 
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
 * fab_portid_hash_func -
 * 
 * Hash  function for a port
 */
static unsigned int
fab_portid_hash_func(const void* key)
{
    return *((uint16_t *)key);
}

/**
 * fab_portid_eq_func -
 * 
 * Determine if two ports are equal
 */
static int
fab_portid_eq_func(const void *key1, const void *key2)
{
    uint16_t idA = *((uint16_t *)key1);
    uint16_t idB = *((uint16_t *)key2);

    return idA == idB;
}

/**
 * __fab_switch_find_with_dpid -
 * 
 * Find a switch given the dpid 
 */
fab_switch_t *
__fab_switch_find_with_dpid(fab_struct_t *ctx, uint64_t dpid)
{
    fab_switch_t *fab_sw;
    int i = 0;

    for (; i < MAX_SWITCHES_PER_CLUSTER; i++) {
        fab_sw = (((fab_switch_t *)(ctx->sw_list)) + i);
        if (!fab_sw->valid) {
            continue;
        }

        if (fab_sw->dpid == dpid) return fab_sw;
    } 
    
    return NULL;
}

/**
 * __fab_switch_find -
 *
 * Find a switch given the alias 
 */
fab_switch_t *
__fab_switch_find(fab_struct_t *ctx, int alias)
{
    fab_switch_t *fab_sw;

    if (alias < 0 || alias >= MAX_SWITCHES_PER_CLUSTER) {
        c_log_err("%s: Switch alias id (%d) out of bound", FN, alias);
        return NULL;
    }

    fab_sw = (((fab_switch_t *)(ctx->sw_list)) + alias);

    if (!fab_sw->valid) {
        return NULL;
    }

    return fab_sw;
}

/**
 * __fab_port_add -
 *
 * Add a port to a switch 
 */
int
__fab_port_add(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t *port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return -1;
    }

    if (port_no > OFPP_MAX){
        return -1;
    }

    port = fab_zalloc(sizeof(fab_port_t));
    port->port_no = port_no;

    if (g_hash_table_lookup(sw->port_htbl, port)) {
        c_log_err("%s: Sw(0x%llx) port (%u) already present",
                  FN, sw->dpid, port_no);
        fab_free(port);
        return -1;
    }

    g_hash_table_insert(sw->port_htbl, port, port);

    c_log_debug("%s:switch (0x%llx) port(%d) added", FN, sw->dpid, port_no); 

    return 0;
}

/**
 * __fab_port_delete -
 *
 * Delete a port to a switch
 */
int
__fab_port_delete(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t *port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return -1;
    }

    port = fab_zalloc(sizeof(fab_port_t));
    port->port_no = port_no;

    g_hash_table_remove(sw->port_htbl, port);

    return 0;
}

/**
 * __fab_port_delete_all -
 *
 * Delete all ports on a switch
 */
void
__fab_port_delete_all(fab_struct_t *ctx UNUSED, fab_switch_t *sw)
{
    g_hash_table_destroy(sw->port_htbl);
}

/**
 * __fab_port_valid  -
 *
 * Check if a port is valid on a switch 
 */
bool
__fab_port_valid(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return -1;
    }

    memset(&port, 0, sizeof(port));
    port.port_no = port_no;

    if (g_hash_table_lookup(sw->port_htbl, &port)) {
        return true;
    }

    return false;
}

/**
 * __fab_switch_add -
 *
 * Add a switch
 */
int
__fab_switch_add(fab_struct_t *ctx, uint64_t dpid, int alias)
{
    fab_switch_t *fab_sw; 

    if (alias < 0 || alias >= MAX_SWITCHES_PER_CLUSTER) {
        c_log_err("%s: Switch alias id (%d) out of bound", FN, alias);
        return -1;
    }


    fab_sw = (((fab_switch_t *)(ctx->sw_list)) + alias);

    if (fab_sw->valid) {
        if (fab_sw->dpid == dpid ||
            fab_sw->alias == alias) {
            c_log_err("%s: Switch already added (0x%llx:%d)\n", 
                      FN, dpid, alias);
            return -EEXIST;
        }

        fab_switch_delete_notifier(ctx, alias, true);
    }

    fab_sw->alias = alias;
    fab_sw->dpid = dpid;
    fab_sw->valid = true;

    fab_sw->port_htbl = g_hash_table_new_full(fab_portid_hash_func,
                                              fab_portid_eq_func,
                                              NULL, fab_free);
    if (!fab_sw->port_htbl){
        c_log_err("%s: Error in ports table alloc", FN);
        return -1;
    }

    c_log_debug("%s:switch (0x%llx) added", FN, dpid); 

    return 0;
}

/**
 * __fab_switch_del -
 *
 * Delete a switch
 */
int
__fab_switch_del(fab_struct_t *ctx, int alias)
{
    fab_switch_t *fab_sw; 

    if (alias < 0 || alias >= MAX_SWITCHES_PER_CLUSTER) {
        c_log_err("%s: Switch alias id (%d) out of bound", FN, alias);
        return -1;
    }

    fab_sw = (((fab_switch_t *)(ctx->sw_list)) + alias);

    if (!fab_sw->valid) {
        c_log_err("%s: Switch(alias %d) already deleted", 
                  FN, alias);
        return -1;
    }

    g_hash_table_destroy(fab_sw->port_htbl);

    c_log_debug("%s:switch (0x%llx) deleted", FN, fab_sw->dpid); 

    memset(fab_sw, 0, sizeof(*fab_sw));

    return 0;
}

/**
 * fab_switches_reset -
 *
 * Reset all the switches struct 
 */
void
fab_switches_reset(fab_struct_t *ctx, 
                   void (*deact_hosts_fn)(fab_struct_t *ctx,
                                          uint64_t dpid))
{
    int alias = 0;
    fab_switch_t *fab_sw;

    c_wr_lock(&ctx->lock);
    for (; alias < MAX_SWITCHES_PER_CLUSTER; alias++) {
        fab_sw = (((fab_switch_t *)(ctx->sw_list)) + alias);

        if (!fab_sw->valid) continue;
    
        deact_hosts_fn(ctx, fab_sw->dpid);

        g_hash_table_destroy(fab_sw->port_htbl);
        memset(fab_sw, 0, sizeof(*fab_sw));
    } 

    c_wr_unlock(&ctx->lock);

    c_log_debug("%s: ", FN);
}

/**
 * fab_switches_init -
 *
 * Initialize the switches struct 
 */
int
fab_switches_init(fab_struct_t *fab_ctx)
{
    assert(fab_ctx);

    if (!fab_ctx->sw_list) {
        fab_ctx->sw_list = fab_zalloc(sizeof(fab_switch_t) *
                                      MAX_SWITCHES_PER_CLUSTER);
    } else {
        c_log_err("%s: Switch iMap already allocated", FN);
        return -1;
    }

    assert(fab_ctx->sw_list);

    return 0;
}
