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
    struct ofp_action_output op_act;
    struct flow flow;
    uint32_t wildcards = OFPFW_ALL;

    op_act.type = htons(OFPAT_OUTPUT);
    op_act.len  = htons(sizeof(op_act));
    op_act.port = htons(OFPP_ALL);

    parms.buffer_id = ntohl(opi->buffer_id);
    parms.action_len = sizeof(op_act);
    parms.action_list  = &op_act;
    parms.in_port = in_port;
    parms.data = data;
    parms.data_len = pkt_len;

    of_send_pkt_out(sw, &parms);

    op_act.port = htons(in_port);

    memset(&flow, 0, sizeof(flow));
    memcpy(&flow.dl_dst, in_flow->dl_src, OFP_ETH_ALEN);

    wildcards &= ~(OFPFW_DL_DST);
    of_send_flow_add_nocache(sw, &flow, (uint32_t)(-1),
                             &op_act, sizeof(op_act),
                             60, 0, htonl(wildcards), C_FL_PRIO_DFL);  

    return 0;
}


int 
c_l2_port_status(c_switch_t *sw UNUSED, uint32_t cfg UNUSED, uint32_t state UNUSED)
{
    /* Nothing to do for now */
    return 0;
}
