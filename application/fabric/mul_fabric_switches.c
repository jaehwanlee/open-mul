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
 * fab_port_add -
 *
 * Add a port to a switch 
 */
int
fab_port_add(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no, 
               uint32_t config, uint32_t state)
{
    fab_port_t *port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return -1;
    }

    if (port_no > OFPP_MAX && port_no != OFPP_LOCAL){
        return -1;
    }

    port = fab_zalloc(sizeof(fab_port_t));
    port->port_no = port_no;
    port->config = config;
    port->state = state;

    c_wr_lock(&sw->lock);
    if (g_hash_table_lookup(sw->port_htbl, port)) {
        c_log_err("%s: Sw(0x%llx) port (%u) already present",
                  FN, (unsigned long long)(sw->dpid), port_no);
        c_wr_unlock(&sw->lock);
        fab_free(port);
        return -1;
    }

    g_hash_table_insert(sw->port_htbl, port, port);
    c_wr_unlock(&sw->lock);

    c_log_debug("%s:switch (0x%llx) port(%d) added",
                FN, (unsigned long long)(sw->dpid), port_no); 

    return 0;
}

/**
 * fab_port_delete -
 *
 * Delete a port to a switch
 */
int
fab_port_delete(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t *port;

    c_wr_lock(&sw->lock);

    port = __fab_port_find(ctx, sw, port_no);
    if (!port) {
        c_log_err("%s failed", FN);
        c_wr_unlock(&sw->lock);
        return -1;
    }

    fab_port_host_dead_marker(port, NULL, NULL);
    if (!g_hash_table_remove(sw->port_htbl, port)) {
        c_log_err("Failed to delete port 0x%llx:%hu",
                  (unsigned long long)sw->dpid, port_no);
    }

    c_wr_unlock(&sw->lock);

    return 0;
}

/**
 * fab_port_update  -
 *
 * Update flags of a port 
 */
void
fab_port_update(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no,
                  uint32_t config, uint32_t state)
{
    fab_port_t lkup_port;
    fab_port_t *port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = port_no;

    c_wr_lock(&sw->lock);
    if ((port = g_hash_table_lookup(sw->port_htbl, &lkup_port))) {
        port->config = config;
        port->state = state;
    }

    c_wr_unlock(&sw->lock);

    return;
}
 

/**
 * fab_port_valid  -
 *
 * Check if a port is valid on a switch 
 */
bool
fab_port_valid(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return false;
    }

    memset(&port, 0, sizeof(port));
    port.port_no = port_no;

    c_rd_lock(&sw->lock);
    if (g_hash_table_lookup(sw->port_htbl, &port)) {
        c_rd_unlock(&sw->lock);
        return true;
    }

    c_rd_unlock(&sw->lock);
    return false;
}

/**
 * __fab_port_find  -
 *
 * Get a port is valid on a switch 
 */
fab_port_t *
__fab_port_find(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t lkup_port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return NULL;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = port_no;

    return (fab_port_t *)(g_hash_table_lookup(sw->port_htbl, &lkup_port));
}


/**
 * fab_port_up  -
 *
 * Check if a port is up/running on a switch 
 */
bool
fab_port_up(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no)
{
    fab_port_t lkup_port;
    fab_port_t *port;

    if (!sw) {
        c_log_err("%s: Null switch", FN);
        return false;
    }

    memset(&lkup_port, 0, sizeof(lkup_port));
    lkup_port.port_no = port_no;

    c_rd_lock(&sw->lock);
    if ((port = g_hash_table_lookup(sw->port_htbl, &lkup_port)) &&
        !(port->config & OFPPC_PORT_DOWN) && 
        !(port->state & OFPPS_LINK_DOWN)) {
        c_rd_unlock(&sw->lock);
        return true;
    }

    c_rd_unlock(&sw->lock);

    return false;
}


/**
 * fab_traverse_all_switch_ports - 
 *
 * Loop through all switch ports and call iter_fn for each 
 */
static void
fab_traverse_all_switch_ports(fab_switch_t *fab_sw, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_sw->lock);
    if (fab_sw->port_htbl) {
        g_hash_table_foreach(fab_sw->port_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&fab_sw->lock);
}

/**
 * fab_port_host_dead_marker_cmn -
 *
 */
static void
fab_port_host_dead_marker_cmn(fab_port_t *port, bool locked)
{
    struct flow fl;
    fab_host_t *host = port->host;

    if (port->host) {
        memset(&fl, 0, sizeof(fl));
        fl.nw_src = htonl(host->hkey.host_ip);
        fab_add_tenant_id(&fl, NULL, fab_tnid_to_tid(host->hkey.tn_id));
        memcpy(fl.dl_src, host->hkey.host_mac, 6);
        fab_host_delete(fab_ctx, &fl, locked, true, false);
        fab_host_put(port->host);
    }

    port->host = NULL;

}

/**
 * fab_port_host_dead_marker -
 *
 * Mark a host as dead whose port is not up or deleted 
 */
void
fab_port_host_dead_marker(void *p_arg, void *v_arg UNUSED, void *arg UNUSED)
{
    fab_port_t *port = p_arg;

    c_log_err("%s: port del marker %hu", FN, port->port_no);
    fab_port_host_dead_marker_cmn(port, false);
}

/**
 * __fab_port_host_dead_marker -
 *
 * Mark a host as dead whose port is not up or deleted 
 */
static void
__fab_port_host_dead_marker(void *p_arg, void *v_arg UNUSED, void *arg UNUSED)
{
    fab_port_t *port = p_arg;

    c_log_err("%s: port del marker %hu", FN, port->port_no);
    fab_port_host_dead_marker_cmn(port, true);
}


/**
 * fab_dpid_hash_func - 
 *
 */
unsigned int
fab_dpid_hash_func(const void *p)
{
    fab_switch_t *sw = (fab_switch_t*) p;

    return (unsigned int)(sw->dpid);
}

/**
 * fab_dpid_eq_func - 
 *
 */
int
fab_dpid_eq_func(const void *p1, const void *p2)
{
    const fab_switch_t *sw1 = (fab_switch_t *) p1;
    const fab_switch_t *sw2 = (fab_switch_t *) p2;

    if (sw1->dpid == sw2->dpid) {
        return 1; /* TRUE */
    } else {
        return 0; /* FALSE */
    }
}

/**
 * fab_switch_put - 
 * @switch : switch pointer 
 *
 * Remove a reference to a switch 
 */
void
fab_switch_put(void *sw_arg)
{
    fab_switch_t *fab_sw = sw_arg;
    if (!atomic_read(&fab_sw->ref)) {
        c_log_debug("%s: switch Destroyed 0x%llx", FN, 
                    (unsigned long long)fab_sw->dpid);
        fab_traverse_all_switch_ports(fab_sw, fab_port_host_dead_marker, NULL);
        g_hash_table_destroy(fab_sw->port_htbl);
        fab_free(fab_sw);
    } else {
        atomic_dec(&fab_sw->ref, 1);
    }
}

/**
 * fab_switch_put_locked - 
 * @switch : switch pointer 
 *
 * Remove a reference to a switch while global lock is held
 */
void
fab_switch_put_locked(void *sw_arg)
{
    fab_switch_t *fab_sw = sw_arg;
    if (!atomic_read(&fab_sw->ref)) {
        c_log_debug("%s: switch Destroyed 0x%llx", FN, 
                    (unsigned long long)fab_sw->dpid);
        fab_traverse_all_switch_ports(fab_sw, __fab_port_host_dead_marker, NULL);
        g_hash_table_destroy(fab_sw->port_htbl);
        fab_free(fab_sw);
    } else {
        atomic_dec(&fab_sw->ref, 1);
    }
}



/**
 * fab_switch_get - 
 * @fab_ctx : main ctx struct
 * @dpid : datapath_id 
 *
 * Get a reference to a switch 
 */
fab_switch_t *
fab_switch_get(fab_struct_t *fab_ctx, uint64_t dpid)
{
    fab_switch_t *fab_sw = NULL;
    fab_switch_t fab_lkup_sw;

    fab_lkup_sw.dpid = dpid;

    c_rd_lock(&fab_ctx->lock);
    fab_sw = g_hash_table_lookup(fab_ctx->switch_htbl, &fab_lkup_sw);
    if (fab_sw) {
        atomic_inc(&fab_sw->ref, 1);
    }
    c_rd_unlock(&fab_ctx->lock);

    return fab_sw;
}

/**
 * __fab_switch_get - 
 * @fab_ctx : main ctx struct
 * @dpid : datapath_id 
 *
 * Get a reference to a switch lockless
 */
fab_switch_t *
__fab_switch_get(fab_struct_t *fab_ctx, uint64_t dpid)
{
    fab_switch_t *fab_sw = NULL;
    fab_switch_t fab_lkup_sw;

    fab_lkup_sw.dpid = dpid;

    fab_sw = g_hash_table_lookup(fab_ctx->switch_htbl, &fab_lkup_sw);
    if (fab_sw) {
        atomic_inc(&fab_sw->ref, 1);
    }

    return fab_sw;
}

/**
 * __fab_switch_get_with_alias - 
 * @fab_ctx : main ctx struct
 * @alias : alias_id 
 *
 * Get a reference to a switch 
 */
fab_switch_t *
__fab_switch_get_with_alias(fab_struct_t *fab_ctx, int alias)
{
    fab_switch_t *fab_sw = NULL;

    fab_sw = fab_ctx->sw_list[alias];
    if (fab_sw) {
        atomic_inc(&fab_sw->ref, 1);
    }

    return fab_sw;
}

/**
 * fab_switch_get_with_alias - 
 * @fab_ctx : main ctx struct
 * @alias : alias_id 
 *
 * Get a reference to a switch 
 */
fab_switch_t *
fab_switch_get_with_alias(fab_struct_t *fab_ctx, int alias)
{
    fab_switch_t *fab_sw = NULL;

    c_rd_lock(&fab_ctx->lock);
    fab_sw = __fab_switch_get_with_alias(fab_ctx, alias);
    c_rd_unlock(&fab_ctx->lock);

    return fab_sw;
}


/**
 * __fab_switch_del_imap -
 *
 */
static void
__fab_switch_del_imap(fab_struct_t *fab_ctx, fab_switch_t *fab_sw)
{
    fab_ctx->sw_list[fab_sw->alias] = NULL;    
}

/**
 * __fab_switch_del_all_imap -
 *
 */
static void
__fab_switch_del_imap_notifier(void *sw_arg, void *v_arg UNUSED, void *arg)
{
    fab_switch_t *fab_sw = sw_arg;
    fab_struct_t *fab_ctx = arg;

    __fab_switch_del_imap(fab_ctx, fab_sw);
}

/**
 * fab_switch_del -
 *
 * Delete a switch
 */
int
fab_switch_del(fab_struct_t *fab_ctx, uint64_t dpid)
{
    fab_switch_t *fab_sw; 
    fab_switch_t fab_lkup_sw;

    fab_lkup_sw.dpid = dpid;

    c_wr_lock(&fab_ctx->lock);
    fab_sw = g_hash_table_lookup(fab_ctx->switch_htbl, &fab_lkup_sw);
    if (!fab_sw) {
        c_wr_unlock(&fab_ctx->lock);
        c_log_err("%s: 0x%llx del failed", FN, (unsigned long long)dpid);
        return -1;
        
    }

    __fab_switch_del_imap(fab_ctx, fab_sw);
    g_hash_table_remove(fab_ctx->switch_htbl, fab_sw);
    c_wr_unlock(&fab_ctx->lock);

    c_log_debug("%s:switch (0x%llx) deleted",
                FN, (unsigned long long)(dpid)); 

    return 0;
}

static void
__fab_switch_add_imap(fab_struct_t *fab_ctx, fab_switch_t *fab_sw)
{
    fab_ctx->sw_list[fab_sw->alias] = fab_sw;    
}

/**
 * fab_switch_add -
 *
 * Add a switch
 */
int
fab_switch_add(fab_struct_t *fab_ctx, uint64_t dpid, int alias)
{
    fab_switch_t *fab_sw; 

    fab_sw = fab_zalloc(sizeof(*fab_sw));

    fab_sw->dpid = dpid;
    fab_sw->alias = alias;
    c_rw_lock_init(&fab_sw->lock);

    c_wr_lock(&fab_ctx->lock);
    if (g_hash_table_lookup(fab_ctx->switch_htbl, fab_sw)) {
        c_wr_unlock(&fab_ctx->lock);
        c_log_err("%s: 0x%llx already present", FN, (unsigned long long)dpid);
        return -1;
    }

    fab_sw->port_htbl = g_hash_table_new_full(fab_portid_hash_func,
                                              fab_portid_eq_func,
                                              NULL, fab_free);
    if (!fab_sw->port_htbl) {
        c_wr_unlock(&fab_ctx->lock);
        c_log_err("%s: port htbl alloc failed", FN);
        fab_free(fab_sw);
        return -1;
    }
    g_hash_table_insert(fab_ctx->switch_htbl, fab_sw, fab_sw);
    __fab_switch_add_imap(fab_ctx, fab_sw); 
    c_wr_unlock(&fab_ctx->lock);

    c_log_debug("%s:switch (0x%llx) added",
                FN, (unsigned long long)(dpid)); 

    return 0;
}


/**
 * fab_traverse_all_switch -
 *
 * Loop through all switch and call iter_fn for each
 */
static void
__fab_traverse_all_switch(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    if (fab_ctx->switch_htbl) {
        g_hash_table_foreach(fab_ctx->switch_htbl,
                             (GHFunc)iter_fn, arg);
    }
}

/**
 * fab_switches_reset -
 *
 * Reset all the switches struct 
 */
void
fab_switches_reset(fab_struct_t *ctx) 
{
    c_wr_lock(&ctx->lock);
    __fab_traverse_all_switch(ctx, __fab_switch_del_imap_notifier, ctx);
    g_hash_table_destroy(ctx->switch_htbl);
    ctx->switch_htbl = NULL;
    c_wr_unlock(&ctx->lock);

    fab_switches_init(ctx);

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

    fab_ctx->switch_htbl = g_hash_table_new_full(fab_dpid_hash_func,
                                              fab_dpid_eq_func,
                                              NULL, fab_switch_put_locked);
    assert(fab_ctx->switch_htbl);

    if (!fab_ctx->sw_list) {
        fab_ctx->sw_list = fab_zalloc(sizeof(void *) *
                                      MAX_SWITCHES_PER_CLUSTER);
    } else {
        c_log_err("%s: Switch iMap already allocated", FN);
        return -1;
    }

    assert(fab_ctx->sw_list);

    return 0;
}

