/*
 *  l2switch.h: L2switch application headers
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
#ifndef __L2SW_H__
#define __L2SW_H__

#define L2SW_APP_NAME "mul-l2sw"

#define L2FDB_ITIMEO_DFL (60) 
#define L2FDB_HTIMEO_DFL (0) 

#define L2SW_UNK_BUFFER_ID (0xffffffff)

static inline bool is_zero_ether_addr(const uint8_t *addr)
{
    return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}

static inline bool is_multicast_ether_addr(const uint8_t *addr)
{
    return 0x01 & addr[0];
}

static inline bool is_local_ether_addr(const uint8_t *addr)
{
    return 0x02 & addr[0];
}

static inline bool is_broadcast_ether_addr(const uint8_t *addr)
{
    return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

static inline bool is_unicast_ether_addr(const uint8_t *addr)
{
    return !is_multicast_ether_addr(addr);
}

struct l2fdb_ent_
{
    uint8_t  mac_da[OFP_ETH_ALEN];
    uint16_t lrn_port;
};
typedef struct l2fdb_ent_ l2fdb_ent_t;

struct l2port_ 
{    
    uint16_t port_no;
    uint32_t config;
    uint32_t state;
};
typedef struct l2port_ l2port_t;

struct l2sw_
{
    c_rw_lock_t lock;
    c_atomic_t  ref;
    uint64_t    swid;
    GSList      *port_list;
    GHashTable  *l2fdb_htbl;
};

typedef struct l2sw_ l2sw_t;

struct l2sw_hdl_ {
    c_rw_lock_t   lock;
    void          *base;
    GHashTable   *l2sw_htbl;
    struct event *l2sw_timer_event;
};

typedef struct l2sw_hdl_ l2sw_hdl_t;

struct l2sw_fdb_port_args
{
    l2sw_t   *sw;
    uint16_t port;
};

void l2sw_module_init(void *ctx);
void l2sw_module_vty_init(void *arg);

#endif
