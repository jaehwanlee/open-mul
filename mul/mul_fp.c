/*
 *  mul_fp.c: MUL fastpath forwarding implementation for L2, L3 or 
 *            other known profiles.
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

#include "mul.h"
#include "mul_fp.h"

static int
c_l2fdb_learn(c_switch_t *sw, uint8_t *mac, uint16_t port)
{
    c_l2fdb_bkt_t  *bkt = sw->app_flow_tbl;
    unsigned int   bkt_idx = c_l2fdb_key(mac);
    unsigned int   idx = 0;
    c_l2fdb_ent_t  *ent, *emp_ent = NULL;;
    
    bkt += bkt_idx;

    while(idx < C_FDB_ENT_PER_BKT) {
        ent = &bkt->fdb_ent[idx++];

        if (!emp_ent && !ent->valid) {
            emp_ent = ent;
            continue;
        } 

        if (ent->valid && c_l2fdb_equal(mac, ent->mac)) {
            /* FIXME : Delete it from h/w if installed */
            ent->port = port;    
            return 0;
        }
    } 

    if (emp_ent)  {
        c_l2fdb_ent_init(emp_ent, mac, port);
        return 0;
    }

    /* FIXME : Add chaining and LRU phase out */
    c_log_err("%s: Cant add entry. Full(%u)", FN, idx);
    return -1;
}

static inline c_l2fdb_ent_t * 
c_l2fdb_lookup(c_switch_t *sw, uint8_t *mac)
{
    c_l2fdb_bkt_t  *bkt = sw->app_flow_tbl;
    unsigned int   bkt_idx = c_l2fdb_key(mac);
    unsigned int   idx = 0;
    c_l2fdb_ent_t  *ent;

    bkt += bkt_idx;

    while(idx < C_FDB_ENT_PER_BKT) {
        ent = &bkt->fdb_ent[idx++];
        if (ent->valid && c_l2fdb_equal(mac, ent->mac)) {
            return ent;
        } 
    }

    return NULL;
}

int 
c_l2fdb_init(c_switch_t *sw)
{
    sw->app_flow_tbl = calloc(1, sizeof(struct c_l2fdb_bkt) * C_L2FDB_SZ);
    assert(sw->app_flow_tbl);

    return 0;
}

void
c_l2fdb_destroy(c_switch_t *sw)
{
    c_wr_lock(&sw->lock);

    if (sw->app_flow_tbl) free(sw->app_flow_tbl);
    sw->app_flow_tbl = NULL;

    c_wr_unlock(&sw->lock);
}

/* 
 * c_l2_lrn_fwd - This is fast code which is supposed to know l2sw module's
 * learning and forwarding behaviour. Since it runs as a part of core controller                 
 * it can easily take advantage of controller's threaded features and run
 * in-thread-context. It offloads forwarding functions from the module itself.
 * (FIXME - This is not yet implemented fully. It will functionally work
 *  but there may be holes)
 */
int __fastpath
c_l2_lrn_fwd(c_switch_t *sw, struct cbuf *b UNUSED, void *data, size_t pkt_len, 
             struct flow *in_flow, uint16_t in_port)
{
    struct ofp_packet_in *opi __aligned = (void *)(b->data);
    struct of_pkt_out_params parms;
    struct ofp_action_output op_act;
    c_l2fdb_ent_t *ent;

    if (unlikely(!sw->app_flow_tbl)) {
        c_log_warn("%s: L2 fdb tbl not found", FN);
        return -1;
    }

#ifdef L2_INVALID_ADDR_CHK 
    if (is_zero_ether_addr(in_flow->dl_src) ||
        is_zero_ether_addr(in_flow->dl_dst) ||
        is_multicast_ether_addr(in_flow->dl_src) ||
        is_broadcast_ether_addr(in_flow->dl_src)) {
        c_log_debug("%s: Invalid src/dst mac addr", FN);
        return -1;
    }
#endif

    op_act.type = htons(OFPAT_OUTPUT);
    op_act.len  = htons(sizeof(op_act));

    c_wr_lock(&sw->lock);
    c_l2fdb_learn(sw, in_flow->dl_src, in_port);

    if ((ent = c_l2fdb_lookup(sw, in_flow->dl_dst))) {
        op_act.port = htons(ent->port);
        of_send_flow_add_nocache(sw, in_flow, ntohl(opi->buffer_id),
                                 &op_act, sizeof(op_act), 60, 0, 
                                 htonl(OFPFW_ALL & ~(OFPFW_DL_DST)), 
                                 C_FL_PRIO_DFL);
    }

    if (ent && (opi->buffer_id != (uint32_t)(-1))) {
        c_wr_unlock(&sw->lock);
        return 0;
    }

    parms.buffer_id = ntohl(opi->buffer_id);
    parms.action_len = sizeof(op_act);
    parms.action_list  = &op_act;
    parms.in_port = in_port;
    parms.data = data;
    parms.data_len = parms.buffer_id == (uint32_t)(-1)? 0 : pkt_len;

    op_act.port = ent ? htons(ent->port) : htons(OFPP_ALL);
    c_wr_unlock(&sw->lock);

    of_send_pkt_out(sw, &parms);

    return 0;
}

int 
c_l2_port_status(c_switch_t *sw UNUSED, uint32_t cfg UNUSED, uint32_t state UNUSED)
{
    /* Nothing to do for now */
    return 0;
}
