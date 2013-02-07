/*
 *  mul_fabric_host.c: Fabric host manager
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
 * fab_dump_single_host -
 *  
 * Dump a single host 
 */
char *
fab_dump_single_host(fab_host_t *host)
{
    char     *pbuf = calloc(1, HOST_PBUF_SZ);
    int      len = 0;

    len += snprintf(pbuf+len, HOST_PBUF_SZ-len-1,
                    "Tenant %4hu, Network %4hu, host-ip 0x%-8x,host-mac "
                    "%02x:%02x:%02x:%02x:%02x:%02x on switch "
                    "0x%016llx %4d port %4hu (%s) (%s)\r\n",
                    fab_tnid_to_tid(host->hkey.tn_id),
                    fab_tnid_to_nid(host->hkey.tn_id),
                    host->hkey.host_ip,
                    host->hkey.host_mac[0], host->hkey.host_mac[1],
                    host->hkey.host_mac[2], host->hkey.host_mac[3],
                    host->hkey.host_mac[4], host->hkey.host_mac[5],
                    host->sw.swid, host->sw.alias, host->sw.port,
                    host->dfl_gw?"dfl-gw":"non-gw",
                    host->dead ? "dead":"alive");
    assert(len < HOST_PBUF_SZ-1);

    return pbuf;
}

/**
 * fab_dump_single_host_to_flow -
 *
 * Dump a single host to a flow struct
 */
void
fab_dump_single_host_to_flow(fab_host_t *host, struct flow *fl,
                             uint64_t *dpid)
{

    *dpid = host->sw.swid;
    fl->in_port = htons(host->sw.port);
    fab_add_tenant_id(fl, NULL, fab_tnid_to_tid(host->hkey.tn_id));
    fab_add_network_id(fl, fab_tnid_to_nid(host->hkey.tn_id));
    fl->nw_src = htonl(host->hkey.host_ip);
    memcpy(fl->dl_src, host->hkey.host_mac, 6);
    fl->FL_DFL_GW = host->dfl_gw;
}

/**
 * fab_tenant_nw_hash_fn -
 * @key : Key pointer which is tenant network
 *
 * Hash function for a tenant network 
 */
unsigned int                     
fab_tenant_nw_hash_func(const void *key)
{
    const fab_tenant_net_t *tenant_nw = key;

    return tenant_nw->tn_id;
}   

/**
 * fab_tenant_nw_equal_fn -
 * @key1 : Key pointer which is tenant network
 * @key2 : Key pointer which is tenant network
 *
 * Check and return true if two tenant networks are equal 
 */
int 
fab_tenant_nw_equal_func(const void *key1, const void *key2)
{       
    const fab_tenant_net_t *t1 = key1;
    const fab_tenant_net_t *t2 = key2;

    return t1->tn_id == t2->tn_id;
}  

/**
 * fab_tenant_nw_put -
 * @tenant_nw : Tenant network pointer
 *
 * Remove reference to a tenant network 
 */
static void
fab_tenant_nw_put(fab_tenant_net_t *tenant_nw)
{
    if(!atomic_read(&tenant_nw->ref)) {
        free(tenant_nw);
    } else {
        atomic_dec(&tenant_nw->ref, 1);
    }
}

/**
 * __fab_host_per_tenant_nw_delete -
 * @harg : Host arg 
 * @carg : Context pointer arg 
 *
 * Delete a host in a tenant network
 */
static void
__fab_host_per_tenant_nw_delete(void *harg, void *carg UNUSED)
{
    fab_host_t *host = harg;

    __fab_host_delete(host);
}
    
/**
 * __fab_tenant_nw_loop_all_hosts - 
 * @tenant_nw  : Tenant network pointer 
 * @iter_fn    : Iteration callback for each host of a tenant 
 * @u_data     : User arg to be passed to iter_fn 
 *
 * Loop over all hosts of a tenant and invoke callback for each
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__fab_tenant_nw_loop_all_hosts(fab_tenant_net_t *tenant_nw, GFunc iter_fn,
                               void *u_data)
{
    if (tenant_nw->host_list) {
        g_slist_foreach(tenant_nw->host_list,
                        (GFunc)iter_fn, u_data);
    }
}

/**
 * __fab_tenant_nw_delete - 
 * @tenant_nw  : Tenant network pointer 
 *
 * Delete a tenant network from fabric. Also, deletes associated hosts
 * and host routes. 
 * NOTE - lockless version and assumes fab_ctx lock as held
 */
void
__fab_tenant_nw_delete(void *ten_nw)
{
    __fab_tenant_nw_loop_all_hosts(ten_nw,
                                   __fab_host_per_tenant_nw_delete,
                                   NULL);
    fab_tenant_nw_put((fab_tenant_net_t *)ten_nw);
}

/**
 * fab_tenant_nw_delete - 
 * @tenant  : Tenant pointer 
 *
 * Locked version of __fab_tenant_delete
 */
void
fab_tenant_nw_delete(fab_tenant_net_t *ten_nw)
{
    c_wr_lock(&fab_ctx->lock);

    g_hash_table_remove(fab_ctx->tenant_net_htbl, ten_nw);

    c_wr_unlock(&fab_ctx->lock);
}

/**
 * fab_host_unref - 
 * @host : Host pointer 
 *
 * Remove a reference to a host 
 */
static void
fab_host_unref(fab_host_t *host)
{
    fab_tenant_net_t *ten_nw = host->tenant_nw;
    if (!atomic_read(&host->ref)) {
        c_log_debug("%s: Host Destroyed (TNID %u: ip(0x%x) "
                  "mac(%02x:%02x:%02x:%02x:%02x:%02x:",
                  FN, host->hkey.tn_id, host->hkey.host_ip,
                  host->hkey.host_mac[0], host->hkey.host_mac[1],
                  host->hkey.host_mac[2], host->hkey.host_mac[3],
                  host->hkey.host_mac[4], host->hkey.host_mac[5]);
        ten_nw->host_list = g_slist_remove(ten_nw->host_list, host);
        fab_tenant_nw_put(ten_nw);
        fab_free(host);
    } else {
        atomic_dec(&host->ref, 1);
    }
}

/**
 * fab_loop_all_hosts - 
 * @fab_ctx : fabric context pointer 
 * @iter_fn : iteration function for each host 
 * @arg : arg to be passed to iter_fn 
 *
 * Loop through all known hosts and call iter_fn for each
 * NOTE - This function can only be used as long as iter_fn
 * does not require any global list manipulations eg host add/del etc. 
 */
void
fab_loop_all_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_ctx->lock);
    if (fab_ctx->host_htbl) {
        g_hash_table_foreach(fab_ctx->host_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&fab_ctx->lock);
}

/**
 * fab_loop_inactive_all_hosts - 
 * @fab_ctx : fabric context pointer 
 * @iter_fn : iteration function for each host 
 * @arg : arg to be passed to iter_fn 
 *
 * Loop through all known hosts and call iter_fn for each
 * NOTE - This function can only be used as long as iter_fn
 * does not require any global list manipulations eg host add/del etc. 
 */
void
fab_loop_all_inactive_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_rd_lock(&fab_ctx->lock);
    if (fab_ctx->inact_host_htbl) {
        g_hash_table_foreach(fab_ctx->inact_host_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_rd_unlock(&fab_ctx->lock);
}


/**
 * fab_loop_all_hosts_wr -
 * @fab_ctx : fabric context pointer
 * @iter_fn : iteration function for each host
 * @arg : arg to be passed to iter_fn
 *
 * Loop through all known hosts and call iter_fn for each for writing
 * any global list manipulations eg host add/del etc.
 */
void
fab_loop_all_hosts_wr(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg)
{
    c_wr_lock(&fab_ctx->lock);
    if (fab_ctx->host_htbl) {
        g_hash_table_foreach(fab_ctx->host_htbl,
                             (GHFunc)iter_fn, arg);
    }
    c_wr_unlock(&fab_ctx->lock);
}

/**
 * fab_host_get - 
 * @host: fabric host pointer
 *
 * Refer host and increment ref-count
 */
void
fab_host_get(fab_host_t *host)
{
    atomic_inc(&host->ref, 1);
}

/**
 * fab_host_put - 
 * @host: fabric host pointer
 *
 * De-refer host's ref-count
 */
void
fab_host_put(fab_host_t *host)
{
    fab_host_unref(host);
}

/**
 * fab_host_put_locked - 
 * @host: fabric host pointer
 *
 * Locked version of fab_host_put()
 */
void
fab_host_put_locked(fab_host_t *host)
{
    c_wr_lock(&fab_ctx->lock);
    fab_host_unref(host);
    c_wr_unlock(&fab_ctx->lock);
}

/**
 * fab_host_hash_func - 
 * @key: fabric host hash key 
 *
 * Derive a hash val froma host key 
 */
unsigned int                     
fab_host_hash_func(const void *key)
{
    const fab_host_t *host = key;

    return hash_bytes(host, sizeof(fab_hkey_t), 1);
}   

/**
 * fab_host_equal_func - 
 * @key1: fabric host1 hash key 
 * @key2: fabric host2 hash key 
 *
 * Deduce if two hosts are equal
 */
int 
fab_host_equal_func(const void *key1, const void *key2)
{       
    return !memcmp(key1, key2, sizeof(fab_hkey_t) - 6);
}  

/**
 * __fab_host_delete - 
 * @data: host pointer 
 *
 * Delete a fabric host. wrapper over fab_host_put 
 * NOTE - Unlocked version and assumes fab_ctx lock held
 */
void
__fab_host_delete(void *data)
{
    fab_host_put((fab_host_t *)data);
} 

/**
 * fab_host_create -
 *
 * Allocate and initialize a host struct  
 */
static fab_host_t *
fab_host_create(uint64_t dpid, uint16_t sw_alias, struct flow *fl)
{
    fab_host_t *host;

    host = fab_zalloc(sizeof(fab_host_t));

    c_rw_lock_init(&host->lock);
    host->sw.swid = dpid;
    host->sw.alias = sw_alias;
    host->sw.port = ntohs(fl->in_port);
    FAB_MK_TEN_NET_ID(host->hkey.tn_id, 
                      fab_extract_tenant_id(fl), 
                      fab_extract_network_id(fl)); 
    host->hkey.host_ip = ntohl(fl->nw_src);
    memcpy(host->hkey.host_mac, fl->dl_src, 6);
    host->dfl_gw = fl->FL_DFL_GW;

    return host;
}

/**
 * fab_host_cmp_association -
 *
 * Check if two hosts have same associated switch and port
 */
static bool 
fab_host_cmp_association(fab_host_t *host1, fab_host_t *host2)
{
    if (host1->sw.swid == host2->sw.swid &&
        host1->sw.alias == host2->sw.alias &&
        host1->sw.port == host2->sw.port && 
        host1->dfl_gw == host2->dfl_gw) {
        return true;
    }

    return false;
}

/**
 * fab_host_delete - 
 * @fab_ctx: fab context pointer 
 * @dpid : switch dpid to the connected host
 * @sw_alias : switch alias id to the connected host
 * @fl : flow defining a host 
 * @locked : flag to specify whether fab_ctx is already held or not
 *
 * Delete a fabric host 
 */
int
fab_host_delete(fab_struct_t *fab_ctx, struct flow *fl, 
                bool locked, bool inactive) 
{
    fab_host_t *lkup_host, *host;
    char *host_pstr;
    
    lkup_host = fab_host_create(0, 0, fl);

    if (!locked) c_wr_lock(&fab_ctx->lock);

    if (!(host = g_hash_table_lookup(fab_ctx->host_htbl, lkup_host))) {
        if (!inactive &&
            (host = g_hash_table_lookup(fab_ctx->inact_host_htbl, lkup_host))) {
            host_pstr = fab_dump_single_host(host);
            c_log_err("%s: Inactive Host deleted %s", FN, host_pstr);
            free(host_pstr);

            host->tenant_nw->host_list =
                g_slist_remove(host->tenant_nw->host_list, host);
            g_hash_table_remove(fab_ctx->inact_host_htbl, host);
        } else {
            c_log_err("%s: No such host or already inactive", FN);
        }

        if (!locked) c_wr_unlock(&fab_ctx->lock);
        return -1;
    }

    host->dead = true;
    __fab_host_route_delete(host, NULL, fab_ctx);
    __fab_del_pending_routes_tofro_host(fab_ctx, host);

    if (inactive) {
        fab_host_get(host); /* Dont free up the host */
        host_pstr = fab_dump_single_host(host);
        c_log_err("%s: Host Active->Inactve %s", FN, host_pstr);
        free(host_pstr);
        g_hash_table_insert(fab_ctx->inact_host_htbl, host, host);
    }
        
    host->tenant_nw->host_list =
            g_slist_remove(host->tenant_nw->host_list, host);

    g_hash_table_remove(fab_ctx->host_htbl, host);

    if (!inactive) {
        host_pstr = fab_dump_single_host(lkup_host);
        c_log_err("%s: Host Deleted %s", FN, host_pstr);
        free(host_pstr);
    }

    if (!locked) c_wr_unlock(&fab_ctx->lock);

    return 0;
} 

/**
 * fab_host_on_switch - 
 *
 * Returns true if switch connected to this host
 */
static int
fab_host_on_switch(void *h_arg, void *v_arg UNUSED, void *u_arg)
{
    fab_host_t *host = h_arg;
    uint64_t dpid = *(uint64_t *)u_arg;

    if (host->sw.swid == dpid)  return true;

    return false;
}

/**
 * __fab_delete_all_hosts_on_switch -
 * @fab_ctx : fabric context pointer
 * @dpid  : dpid 
 *
 * Delete all hosts connected to a switch
 */
void
__fab_delete_all_hosts_on_switch(fab_struct_t *fab_ctx, uint64_t dpid)
{
    fab_host_t *host;
    struct flow fl;

    while ((host = g_hash_table_find(fab_ctx->host_htbl, fab_host_on_switch,
                                     &dpid))) {
        memset(&fl, 0, sizeof(fl));
        fl.nw_src = htonl(host->hkey.host_ip);
        fab_add_tenant_id(&fl, NULL, fab_tnid_to_tid(host->hkey.tn_id)); 
        memcpy(fl.dl_src, host->hkey.host_mac, 6);
        fab_host_delete(fab_ctx, &fl, true, true);
    } 
}

/**
 * __fab_activate_all_hosts_on_switch -
 * @fab_ctx : fabric context pointer
 * @dpid  : dpid 
 *
 * Activate all inactive hosts that were connected to a switch
 */
void
__fab_activate_all_hosts_on_switch(fab_struct_t *fab_ctx, uint64_t dpid)
{
    fab_host_t *host;
    struct flow fl;

    while ((host = g_hash_table_find(fab_ctx->inact_host_htbl, fab_host_on_switch,
                                     &dpid))) {
        memset(&fl, 0, sizeof(fl));
        fl.nw_src = htonl(host->hkey.host_ip);
        fl.in_port = htons(host->sw.port);
        fl.FL_DFL_GW = host->dfl_gw;
        fab_add_tenant_id(&fl, NULL, fab_tnid_to_tid(host->hkey.tn_id));
        memcpy(fl.dl_src, host->hkey.host_mac, 6);

        c_wr_unlock(&fab_ctx->lock);
        /* FIXME - There is chance of deadlock if fab_host_add fails 
         * which should  not in any way but this needs fix
         */
        fab_host_add(fab_ctx, dpid, &fl);
        c_wr_lock(&fab_ctx->lock);
    } 
}


/**
 * fab_host_add - 
 * @fab_ctx: fab context pointer 
 * @dpid : switch dpid to the connected host
 * @fl : flow defining a host 
 *
 * Add a fabric host 
 */
int
fab_host_add(fab_struct_t *fab_ctx, uint64_t dpid, 
             struct flow *fl)
{
    fab_switch_t *sw;
    fab_host_t *host = NULL, *exist_host = NULL;
    fab_tenant_net_t *tenant_nw = NULL;
    bool install_route_pair = true;
    char *host_pstr;

    c_wr_lock(&fab_ctx->lock);

    sw = __fab_switch_find_with_dpid(fab_ctx, dpid);
    if (!sw) {
        c_log_err("%s: Switch(0x%llx) not found", FN, dpid);
        c_wr_unlock(&fab_ctx->lock);
        return -1;
    } else if (!__fab_port_valid(fab_ctx, sw, ntohs(fl->in_port))) {
        c_log_err("%s: Port(%hu) on Switch(0x%llx) not found", FN, 
                  ntohs(fl->in_port), dpid);
        c_wr_unlock(&fab_ctx->lock);
        return -1;
    }

    host = fab_host_create(dpid, sw->alias, fl);

    if ((exist_host = g_hash_table_lookup(fab_ctx->inact_host_htbl, host))) {
        host_pstr = fab_dump_single_host(host);
        c_log_err("%s: Known Host inactive->active %s", FN, host_pstr);
        free(host_pstr);

        exist_host->tenant_nw->host_list = 
            g_slist_remove(exist_host->tenant_nw->host_list, exist_host);
        g_hash_table_remove(fab_ctx->inact_host_htbl, exist_host);
        ///fab_host_put(exist_host);
    }

    assert(fab_ctx->host_htbl);
    if ((exist_host = g_hash_table_lookup(fab_ctx->host_htbl, host))) {
        
        if (fab_host_cmp_association(exist_host, host)) { 
            host_pstr = fab_dump_single_host(host);
            c_log_err("%s: Known Host %s", FN, host_pstr);
            free(host_pstr);
            c_wr_unlock(&fab_ctx->lock);
            return -1;
        }

        c_log_err("%s: Known host but modified\n", FN);

        fab_host_delete(fab_ctx, fl, true, false);
    }

    assert(fab_ctx->tenant_net_htbl);
    if (!(tenant_nw = g_hash_table_lookup(fab_ctx->tenant_net_htbl, 
                                       &(host->hkey.tn_id)))) {
        tenant_nw = fab_zalloc(sizeof(fab_tenant_net_t));

        tenant_nw->tn_id = host->hkey.tn_id;
        g_hash_table_insert(fab_ctx->tenant_net_htbl, tenant_nw, tenant_nw);
    }

    atomic_inc(&tenant_nw->ref, 1);
    host->tenant_nw = tenant_nw;
    g_hash_table_insert(fab_ctx->host_htbl, host, host);
    tenant_nw->host_list = g_slist_append(tenant_nw->host_list, host);

    __fab_routes_tofro_host_add(host, &install_route_pair);

    host_pstr = fab_dump_single_host(host);
    c_log_err("%s: Host Added %s", FN, host_pstr);
    free(host_pstr);

    c_wr_unlock(&fab_ctx->lock);

    return 0;
}

/**
 * fab_learn_host - 
 * @opq: opaque pointer 
 * @fab_ctx : fab context pointer 
 * @pin : packet in struct pointer
 *
 * Learn a new host on fabric 
 */
void
fab_learn_host(void *opq UNUSED, fab_struct_t *fab_ctx UNUSED, 
               c_ofp_packet_in_t *pin UNUSED)
{
    /* FIXME - get tenant nid from port */
    //return fab_host_add(fab_ctx, ntohll(pin->datapath_id), 
    //                    &pin->fl);
}
