/*  mul_lldp_common.h: Mul lldp app common headers 
 *  Copyright (C) 2012, Dipjyoti Saikia<dipjyoti.saikia@gmail.com> 
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

#ifndef __MUL_LLDP_COMMON_H__
#define __MUL_LLDP_COMMON_H__ 

/* Main global entry struct */
struct topo_hdl_ {
    struct event *lldp_update_event;  /* ptr to link expiration check event */
    GHashTable   *switches;           /* Switch lookup table */
    c_rw_lock_t  switch_lock;         /* rwlock for switch table */
    c_rw_lock_t  pkt_lock;            /* rwlock for outstanding packet table */
    void         *sw_imap;            /* Direct Index map with switch id alias  */ 
    int          max_sw_alias;

    tr_struct_t  *tr;
};

/* struct to represent outstanding lldp pkt */
struct lldp_sent_pkt_ {
    uint64_t    sender_id;
    uint16_t    port_id;
    //uint8_t   ttl;
    uint8_t     checked; /* whether entry has gone through check event once or not*/
};

/* struct for each registered switch */
struct lldp_switch_ {
    c_rw_lock_t lock; /* one lock since both hashtable must be modified concurrently */
    c_atomic_t  ref;   /* reference counting */
    uint64_t    dpid; /* switch id */
    int         alias_id; /* Alias canonical id */
    GHashTable  *ports; /* table of ports - lookup lldp_port_t by portid */
    GHashTable  *neighbors; /* table of neighbors - lookup port_list by neighbor id */
};

enum lldp_port_status {
    LLDP_PORT_STATUS_INIT,     /* Disconnected Links */
    LLDP_PORT_STATUS_NEIGHBOR, /* Connection to other switch */
    LLDP_PORT_STATUS_EXTERNAL  /* Connection to unmanaged party */
};

/* struct for each port in a switch */
struct lldp_port_ {
    uint16_t    port_no;
    uint8_t     status; /* one of LLDP_PORT_STATUS_ flags */
    uint32_t    config; /* one of OFPPC_ flags */
    uint32_t    state;  /* one of OFPPS_ flags */

    /* fields below are only valid if status == LLDP_PORT_STATUS_NEIGHBOR */
    uint16_t    neighbor_port; /* port # of switch at other end*/
    uint64_t    neighbor_dpid; /* switch id of switch at other end */
    uint8_t     hw_addr[OFP_ETH_ALEN]; /* MAC Address of the port */
    time_t      ttl; /* TTL before link expiration. */
    time_t      next_probe; /* TTL before link expiration. */
    struct lldp_switch_ *lldp_sw; /* Back pointer to switch */
};

struct lldp_alias_swmap_elem_
{
    struct lldp_switch_ *lldp_sw;
};
typedef struct lldp_alias_swmap_elem_ lldp_alias_swmap_elem_t;

struct lldp_neigh_ {
    uint64_t    other_dpid;
    GSList      *ports;
};

typedef struct topo_rt_info_ topo_rt_info_t;
typedef struct topo_hdl_ topo_hdl_t;
typedef struct lldp_switch_ lldp_switch_t;
typedef struct lldp_port_ lldp_port_t;
typedef struct lldp_neigh_ lldp_neigh_t;
typedef struct lldp_sent_pkt_ lldp_sent_pkt_t;

static inline void
lldp_switch_ref(lldp_switch_t *lldp_switch)
{
    atomic_inc(&lldp_switch->ref,1);
}

static inline void
lldp_sw_rd_lock(topo_hdl_t *hdl)
{
    c_rd_lock(&hdl->switch_lock);
}

static inline void
lldp_sw_rd_unlock(topo_hdl_t *hdl)
{
    c_rd_unlock(&hdl->switch_lock);
}

static inline void
lldp_sw_wr_unlock(topo_hdl_t *hdl)
{
    c_wr_unlock(&hdl->switch_lock);
}

static inline int
lldp_sw_wr_trylock(topo_hdl_t *hdl)
{
    return c_wr_trylock(&hdl->switch_lock);
}

static inline lldp_switch_t *
lldp_get_switch_from_imap(topo_hdl_t *topo, int idx)
{
    return ((lldp_alias_swmap_elem_t *)(topo->sw_imap) + idx)->lldp_sw;
}

struct cbuf *lldp_service_neigh_request(uint64_t dpid, uint32_t xid);
void lldp_switch_traverse_all(topo_hdl_t *topo_hdl, GHFunc iter_fn, void *arg);
int lldp_switch_add(void *app_arg, c_ofp_switch_add_t *ofp_sa);
void lldp_switch_delete(uint64_t dpid);
void lldp_port_traverse_all(lldp_switch_t *lldpsw, GHFunc iter_fn, void *arg);
int lldp_port_add(void *app_arg, lldp_switch_t *sw, struct ofp_phy_port *port_info, 
                  bool need_lock);
int lldp_packet_handler(uint64_t receiver_id, uint16_t receiver_port, lldp_pkt_t *pkt);
void lldp_port_status_handler(void *app_arg, c_ofp_port_status_t *port_stat);
int mul_lldp_init(tr_struct_t *tr);
lldp_port_t *lldp_port_find(lldp_switch_t *lldp_sw, uint16_t port_id);
lldp_port_t *__lldp_port_find(lldp_switch_t *lldp_sw, uint16_t port_id);
lldp_switch_t *fetch_and_retain_switch(uint64_t dpid);
void lldp_neigh_portlist_destroy(void *key);
void lldp_switch_unref(lldp_switch_t *lldp_switch);
void lldp_traverse_all_neigh_ports(lldp_neigh_t *neigh, GFunc iter_fn, void *u_arg);
void lldp_cleanall_switches(tr_struct_t *tr);
int lldp_init_sw_imap(topo_hdl_t *topo);
int lldp_add_switch_to_imap(topo_hdl_t *topo, lldp_switch_t *sw);
void lldp_del_switch_from_imap(topo_hdl_t *topo, lldp_switch_t *sw);
void lldp_port_disconnect_to_neigh(lldp_switch_t *this_switch, 
                              lldp_port_t *this_port,
                              uint16_t port_id, bool need_lock, bool tear_pair);
void lldp_tx(void *app_arg, lldp_switch_t *lldp_switch, 
             lldp_port_t *lldp_port);
int __lldp_get_num_switches(topo_hdl_t *topo);
int __lldp_get_max_switch_alias(topo_hdl_t *topo);
void __lldp_init_neigh_pair_adjacencies(tr_neigh_query_arg_t *arg);

#endif /* LLDP_COMMON_H_ */
