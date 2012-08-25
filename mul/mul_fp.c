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


static void
c_l2fdb_ent_free(void *arg)
{
    free(arg);
}

static unsigned int
c_l2fdb_key(const void *p)
{
    const struct flow *fl = p;

    return hash_bytes(fl->dl_dst, OFP_ETH_ALEN, 1);
}

static int
c_l2fdb_equal(const void *p1, const void *p2)
{
    const struct flow *fl_1 = p1;
    const struct flow *fl_2 = p2;

    return !memcmp(fl_1->dl_dst, fl_2->dl_dst, OFP_ETH_ALEN);
}

static void
c_l2_fdb_destroy(void *sw_arg UNUSED, void *tbl_arg)
{
    c_flow_tbl_t *tbl = tbl_arg;

    if (tbl && tbl->exm_fl_hash_tbl) 
        g_hash_table_destroy(tbl->exm_fl_hash_tbl);

}

static int 
c_l2_fdb_init(c_switch_t *sw)
{
    c_flow_tbl_t *tbl = &sw->app_flow_tbl;

    tbl->c_fl_tbl_type = C_TBL_EXM;
    tbl->hw_tbl_idx = C_TBL_HW_IDX_DFL;
    tbl->dtor = c_l2_fdb_destroy;
    tbl->exm_fl_hash_tbl = g_hash_table_new_full(c_l2fdb_key,
                                                 c_l2fdb_equal,
                                                 NULL,
                                                 c_l2fdb_ent_free);
    return 0;
}

static inline void 
c_l2fdb_learn(c_switch_t *sw, uint8_t *mac, uint16_t port)
{
    struct flow  fl;
    c_fl_entry_t *ent;
    struct ofp_action_output *op_act;
    c_flow_tbl_t *tbl = &sw->app_flow_tbl;

    memcpy(&fl.dl_dst, mac, OFP_ETH_ALEN);
    ent = g_hash_table_lookup(tbl->exm_fl_hash_tbl, &fl);
    if (ent) {
        return;
    }

    ent = malloc(sizeof(*ent) + sizeof(*op_act));
    assert(ent);

    op_act = (void *)(ent + 1);
    ent->actions = (void *)op_act;
    ent->action_len =  sizeof(*op_act);
    op_act->type = htons(OFPAT_OUTPUT);
    op_act->len  = htons(sizeof(op_act));
    op_act->port = htons(port);

    g_hash_table_insert(tbl->exm_fl_hash_tbl, &fl, ent); 
}

static inline c_fl_entry_t *
c_l2fdb_lookup(c_switch_t *sw, struct flow *fl)
{
    c_fl_entry_t *ent;
    c_flow_tbl_t *tbl = &sw->app_flow_tbl;
    
    ent = g_hash_table_lookup(tbl->exm_fl_hash_tbl, fl);

    return ent;
}


/* 
 * c_l2_lrn_fwd - This is fast code which is supposed to know l2sw module's
 * learning and forwarding behaviour. Since it runs as a part of core controller                 
 * it can easily take advantage of controller's threaded features and run
 * in-thread-context. It offloads forwarding functions from the module itself.
 * (FIXME - This is not yet implemented fully. It will functionally work
 *  but there will be gaps in learning)
 */
int __fastpath
c_l2_lrn_fwd(c_switch_t *sw, struct cbuf *b UNUSED, void *data, size_t pkt_len, 
             struct flow *in_flow, uint16_t in_port)
{
    struct ofp_packet_in *opi __aligned = (void *)(b->data);
    struct of_pkt_out_params parms;
    struct ofp_action_output op_act, *p_act = NULL;
    c_fl_entry_t *ent;

    if (unlikely(!sw->app_flow_tbl.exm_fl_hash_tbl)) {
        c_l2_fdb_init(sw);
    }

    c_l2fdb_learn(sw, in_flow->dl_src, in_port);

#if 0
    if ((ent = c_l2fdb_lookup(sw, in_flow))) {
        of_send_flow_add_nocache(sw, &ent->fl,  ntohl(opi->buffer_id),
                                 ent->actions, ent->action_len, 60, 0, 
                                 htonl(OFPFW_ALL & ~(OFPFW_DL_DST)), 
                                 C_FL_PRIO_DFL);
        p_act = (void *)(ent->actions);
    }

    if (ent && opi->buffer_id == (uint32_t)(-1)) {
        return 0;
    }

    parms.buffer_id = ntohl(opi->buffer_id);
    parms.action_len = sizeof(op_act);
    parms.action_list  = &op_act;
    parms.in_port = in_port;
    parms.data = data;
    parms.data_len = parms.buffer_id == (uint32_t)(-1)? 0 : pkt_len;

    op_act.type = htons(OFPAT_OUTPUT);
    op_act.len  = htons(sizeof(op_act));
    op_act.port = p_act ? p_act->port : htons(OFPP_ALL);

    of_send_pkt_out(sw, &parms);
#endif

    return 0;
}

int 
c_l2_port_status(c_switch_t *sw UNUSED, uint32_t cfg UNUSED, uint32_t state UNUSED)
{
    /* Nothing to do for now */
    return 0;
}
