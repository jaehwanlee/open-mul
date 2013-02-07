/*
 *  mul_fabric.h: Mul fabric application headers
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
#ifndef __MUL_FABRIC_H__
#define __MUL_FABRIC_H__

#define FAB_APP_NAME "mul-fabric"

#define FAB_UNK_BUFFER_ID (0xffffffff)

/* Fabric app timer intervals */
#define FAB_TIMER_SEC_INT (1)
#define FAB_TIMER_USEC_INT (0)

#define FAB_MAX_PENDING_LOOPS (10)

/* Fabric switch to which a host is connected */
struct fab_host_sw
{
    uint64_t    swid;
    uint32_t    alias;
    uint16_t    port;
};
typedef struct fab_host_sw fab_host_sw_t;

/* Fabric connected host */
struct fab_hkey
{
    uint32_t    host_ip; 
    uint32_t    tn_id;  
    uint8_t     host_mac[6]; 
};
typedef struct fab_hkey fab_hkey_t;

struct fab_tenant_net
{
    uint32_t    tn_id;
    c_atomic_t  ref;
    GSList      *host_list;
};
typedef struct fab_tenant_net fab_tenant_net_t;

struct fab_host
{
    fab_hkey_t       hkey;  /* Don't move this field */
    c_atomic_t       ref;
    c_rw_lock_t      lock;
    fab_host_sw_t    sw;
    fab_tenant_net_t *tenant_nw;    
    GSList           *host_routes;
    bool             dead;
    bool             dfl_gw;
};
typedef struct fab_host fab_host_t;

struct fab_route
{
    fab_host_t *src;
    fab_host_t *dst;
#define FAB_ROUTE_DIRTY 0x1
#define FAB_ROUTE_STATIC 0x2
#define FAB_ROUTE_TIMED 0x4
#define FAB_ROUTE_DEAD 0x8
#define FAB_ROUTE_SAME_SWITCH 0x10
    uint8_t flags;
    uint16_t prio;
#define FAB_ROUTE_RETRY_INIT_TS (1)
#define FAB_ROUTE_RETRY_TS (4)
    time_t expiry_ts;
    uint32_t rt_wildcards;
    struct flow rt_flow;
    GSList *iroute;
};
typedef struct fab_route fab_route_t;

struct fab_switch
{
    uint64_t dpid;
    int      alias;
    bool     valid;
    GHashTable *port_htbl;
};
typedef struct fab_switch fab_switch_t;

struct fab_port
{
    uint16_t port_no;
    uint16_t pad;
    uint32_t tnid;
};
typedef struct fab_port fab_port_t;

/* Main fabric context struct holding all info */
struct fab_struct {
    c_rw_lock_t   lock;
    void          *base;
    GHashTable    *host_htbl;
    GHashTable    *inact_host_htbl;
    GHashTable    *tenant_net_htbl;
    void          *sw_list;
    struct event  *fab_timer_event;

    bool          rt_recalc_pending;
    bool          rt_scan_all_pending;
#define FAB_RT_RECALC_TS 2
    time_t        rt_recalc_ts;
    GSList        *rt_pending_list;

    mul_service_t *fab_cli_service; /* Fabric cli Service */
    mul_service_t *route_service; /* Routing Service Instance */
};
typedef struct fab_struct fab_struct_t;

char *fab_dump_single_host(fab_host_t *host);
void fab_dump_single_host_to_flow(fab_host_t *host, struct flow *fl,
                                  uint64_t *dpid);
void fab_host_get(fab_host_t *host);
void fab_host_put(fab_host_t *host);
void fab_host_put_locked(fab_host_t *host);
unsigned int fab_host_hash_func(const void *key);
int fab_host_equal_func(const void *key1, const void *key2);
int fab_host_delete(fab_struct_t *fab_ctx, struct flow *fl, bool locked,
                    bool inactive); 
void __fab_host_delete(void *host);
void __fab_delete_all_hosts_on_switch(fab_struct_t *fab_ctx, uint64_t dpid);
void __fab_activate_all_hosts_on_switch(fab_struct_t *fab_ctx, uint64_t dpid);
int fab_host_add(fab_struct_t *fab_ctx, uint64_t dpid, struct flow *fl);
void fab_learn_host(void *opq UNUSED, fab_struct_t *fab_ctx,
                    c_ofp_packet_in_t *pin);
void __fab_tenant_nw_delete(void *data);
void fab_tenant_nw_delete(fab_tenant_net_t *tenant);
int fab_tenant_nw_equal_func(const void *key1, const void *key2);
unsigned int fab_tenant_nw_hash_func(const void *key);
void __fab_tenant_nw_loop_all_hosts(fab_tenant_net_t *tenant, GFunc iter_fn,
                                    void *u_data);
void fab_loop_all_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg);
void fab_loop_all_hosts_wr(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg);
void fab_loop_all_inactive_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg);


void fab_route_per_sec_timer(fab_struct_t *fab_ctx);
void __fab_routes_tofro_host_add(void *host, void *fab_ctx);
void __fab_host_route_delete(void *host, void *v, void *fab_ctx);
void fab_reset_all_routes(fab_struct_t *fab_ctx);
void fab_add_all_routes(fab_struct_t *fab_ctx);
void fab_delete_routes_with_port(fab_struct_t *fab_ctx, int sw_alias,
                                 uint16_t port_no);
void fab_loop_all_host_routes(fab_host_t *host, GFunc iter_fn, void *u_data);
void fab_flush_pending_routes(fab_struct_t *fab_ctx);
void fab_dump_single_pending_route(void *route, void *arg);
void __fab_loop_all_pending_routes(fab_struct_t *fab_ctx, GFunc iter_fn, 
                                   void *u_data);
void __fab_del_pending_routes_tofro_host(fab_struct_t *fab_ctx, fab_host_t *host);

void fab_add_arp_tap_per_switch(void *opq, uint64_t dpid);
void fab_arp_rcv(void *opq, fab_struct_t *fab_ctx UNUSED, c_ofp_packet_in_t *pin);

fab_switch_t *__fab_switch_find_with_dpid(fab_struct_t *ctx, uint64_t dpid);
fab_switch_t *__fab_switch_find(fab_struct_t *ctx, int alias);
void __fab_port_delete_all(fab_struct_t *ctx UNUSED, fab_switch_t *sw);
int __fab_port_add(fab_struct_t *ctx, fab_switch_t *sw, uint16_t port_no);
int __fab_port_delete(fab_struct_t *ctx, fab_switch_t *sw, uint16_t port_no);
bool __fab_port_valid(fab_struct_t *ctx, fab_switch_t *sw, uint16_t port_no);
int __fab_switch_add(fab_struct_t *ctx, uint64_t dpid, int alias);
int __fab_switch_del(fab_struct_t *ctx, int alias);
void fab_switches_reset(fab_struct_t *ctx,
                        void (*deact_hosts_fn)(fab_struct_t *ctx,
                                               uint64_t dpid));
int fab_switches_init(fab_struct_t *fab_ctx);

void fabric_vty_init(void *arg);

void fab_switch_delete_notifier(fab_struct_t *fab_ctx, int sw_alias, 
                                bool locked);
void fabric_module_init(void *ctx);
void fabric_module_vty_init(void *arg);

#endif
