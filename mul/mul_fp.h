/*
 *  mul_fp.c: MUL fastpath headers for L2, L3 or other known profiles.
 *
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

#ifndef __MUL_FP_H__
#define __MUL_FP_H__

#define C_L2FDB_SZ (1048576)
#define C_FDB_ENT_PER_BKT 3

struct c_l2fdb_ent
{
    uint8_t  mac[OFP_ETH_ALEN];
    uint16_t port;
    uint16_t valid;
    uint64_t timestamp;
};
typedef struct c_l2fdb_ent c_l2fdb_ent_t;

struct c_l2fdb_bkt
{
    struct c_l2fdb_ent fdb_ent[C_FDB_ENT_PER_BKT];
    uint8_t  pad[16];
};
typedef struct c_l2fdb_bkt c_l2fdb_bkt_t;

//OFP_ASSERT(sizeof(struct c_ofp_port_status)== 64);

static inline unsigned int
c_l2fdb_key(const void *arg)
{
    const uint8_t *p = arg;
    unsigned int idx;

    idx = (p[4] << 24) |  (p[3] << 16) | p[2] << 8 | p[1];
    return idx % C_L2FDB_SZ;
}

static inline unsigned int
c_l2fdb_equal(const void *p1, const void *p2)
{
    return !memcmp(p1, p2, OFP_ETH_ALEN);
}

static inline void
c_l2fdb_ent_init(c_l2fdb_ent_t *ent, uint8_t *mac, uint16_t port)
{

    memcpy(ent->mac, mac, OFP_ETH_ALEN);
    ent->port = port;
    ent->timestamp = g_get_monotonic_time();
    ent->valid = 1;
}


#endif
