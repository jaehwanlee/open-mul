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

#define CONFIG_HAVE_PROXY_ARP 1

#define FAB_UNK_BUFFER_ID (0xffffffff)

/* Fabric app timer intervals */
#define FAB_TIMER_SEC_INT (1)
#define FAB_TIMER_USEC_INT (0)

#define FAB_MAX_PENDING_LOOPS (10)

/* Fabric switch to which a host is connected */
struct fab_host_sw
{
    uint64_t    swid;
#define FAB_INV_SW_ALIAS (0xffffffff)
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
    bool             no_scan;
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
    uint64_t    dpid;
    int         alias;
    bool        valid;
    c_atomic_t  ref;
    c_rw_lock_t lock;
    GHashTable *port_htbl;
};
typedef struct fab_switch fab_switch_t;

struct fab_port
{
    uint16_t port_no;
    uint16_t pad;
    uint32_t tnid;
    uint32_t config;
    uint32_t state;
    fab_host_t *host;
};
typedef struct fab_port fab_port_t;

struct fab_host_service_arg
{
	bool add;
	mul_service_t *serv;
	void (*send_cb)(mul_service_t *s, struct cbuf *b);
};

/* Main fabric context struct holding all info */
struct fab_struct {
    c_rw_lock_t   lock;
    void          *base;
    GHashTable    *host_htbl;
    GHashTable    *inact_host_htbl;
    GHashTable    *tenant_net_htbl;
    GHashTable    *switch_htbl;
    void          **sw_list;
    struct event  *fab_timer_event;

    bool          use_ecmp;
    bool          rt_recalc_pending;
    bool          rt_scan_all_pending;
#define FAB_RT_RECALC_TS 2
    time_t        rt_recalc_ts;
    GSList        *rt_pending_list;

	uint32_t	  ha_state;

    mul_service_t *fab_cli_service; /* Fabric cli Service */
    mul_service_t *route_service;   /* Routing Service Instance */
    mul_service_t *fab_cli_client;  /* Fabric cli service client */
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
                    bool deactivate, bool ha_sync); 
int fab_host_delete_inactive(fab_struct_t *fab_ctx, fab_host_t *lkup_host,
                    bool locked);
void __fab_host_delete(void *host);
void __fab_activate_all_hosts_on_switch(fab_struct_t *fab_ctx, uint64_t dpid);
void fab_activate_all_hosts_on_switch_port(fab_struct_t *fab_ctx, uint64_t dpid,
                                        uint16_t port);
int fab_host_add(fab_struct_t *fab_ctx, uint64_t dpid, struct flow *fl,
                 bool always_add);
int __fab_host_add(fab_struct_t *fab_ctx, uint64_t dpid, struct flow *fl,
                   bool always_add);
int fab_host_add_inactive(fab_struct_t *fab_ctx, fab_host_t *host, bool locked);
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
void __fab_loop_all_inactive_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg);
void __fab_loop_all_hosts(fab_struct_t *fab_ctx, GHFunc iter_fn, void *arg);


GSList *fab_route_get(void *rt_service, int src_sw, int dst_sw,
                      fab_route_t *froute);
void fab_route_per_sec_timer(fab_struct_t *fab_ctx);
void __fab_routes_tofro_host_add(void *host, void *key_arg, void *fab_ctx);
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
void fab_add_dhcp_tap_per_switch(void *opq, uint64_t dpid);
void fab_arp_rcv(void *opq, fab_struct_t *fab_ctx , c_ofp_packet_in_t *pin);
void fab_dhcp_rcv(void *opq, fab_struct_t *fab_ctx , c_ofp_packet_in_t *pin);


void fab_port_host_dead_marker(void *p_arg, void *v_arg UNUSED, void *arg UNUSED);
unsigned int fab_dpid_hash_func(const void *p);
int fab_dpid_eq_func(const void *p1, const void *p2);
int  fab_port_add(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no,
                  uint32_t config, uint32_t state);
int  fab_port_delete(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no);
void fab_port_update(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no,
                     uint32_t config, uint32_t state);
bool fab_port_valid(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no);
bool fab_port_up(fab_struct_t *ctx UNUSED, fab_switch_t *sw, uint16_t port_no);
fab_port_t *__fab_port_find(fab_struct_t *ctx UNUSED, fab_switch_t *sw,
                            uint16_t port_no);
void fab_switch_put(void *sw_arg);
void fab_switch_put_locked(void *sw_arg);
fab_switch_t *fab_switch_get(fab_struct_t *fab_ctx, uint64_t dpid);
fab_switch_t *fab_switch_get_with_alias(fab_struct_t *fab_ctx, int alias);
fab_switch_t *__fab_switch_get_with_alias(fab_struct_t *fab_ctx, int alias);
fab_switch_t *__fab_switch_get(fab_struct_t *fab_ctx, uint64_t dpid);
int fab_switch_del(fab_struct_t *ctx, uint64_t dpid);
int fab_switch_add(fab_struct_t *ctx, uint64_t dpid, int alias);
int fab_switches_init(fab_struct_t *fab_ctx);
void fab_switches_reset(fab_struct_t *ctx);
void fabric_service_send_host_info(void *host, void *v_arg, void *iter_arg); 

void fabric_vty_init(void *arg);

void fab_switch_delete_notifier(fab_struct_t *fab_ctx, int sw_alias, 
                                bool locked);
void fabric_module_init(void *ctx);
void fabric_module_vty_init(void *arg);

#endif
