/*
 *  mul_of_msg.c: MUL openflow message handling 
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

#include "mul_common.h"
#include "random.h"

size_t
of_make_action_output(char **pbuf, size_t bufroom, uint16_t oport)
{
    struct ofp_action_output *op_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*op_act));
        bufroom = sizeof(*op_act);
        assert(*pbuf);
    }

    assert(sizeof(*op_act) <= bufroom);
    
    op_act = (void *)(*pbuf);

    op_act->type = htons(OFPAT_OUTPUT);
    op_act->len  = htons(sizeof(*op_act));
    op_act->port = htons(oport);

    return (sizeof(*op_act));
}

size_t
of_make_action_set_vid(char **pbuf, size_t bufroom, uint16_t vid)
{
    struct ofp_action_vlan_vid *vid_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*vid_act));
        bufroom = sizeof(*vid_act);
        assert(*pbuf);
    }

    assert(sizeof(*vid_act) <= bufroom);
    
    vid_act = (void *)(*pbuf);

    vid_act->type = htons(OFPAT_SET_VLAN_VID);
    vid_act->len  = htons(sizeof(*vid_act));
    vid_act->vlan_vid = htons(vid);

    return (sizeof(*vid_act));
}

size_t
of_make_action_set_dmac(char **pbuf, size_t bufroom, uint8_t *dmac)
{
    struct ofp_action_dl_addr *dmac_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*dmac_act));
        bufroom = sizeof(*dmac_act);
        assert(*pbuf);
    }

    assert(sizeof(*dmac_act) <= bufroom);
    
    dmac_act = (void *)(*pbuf);

    dmac_act->type = htons(OFPAT_SET_DL_DST);
    dmac_act->len  = htons(sizeof(*dmac_act));
    memcpy(dmac_act->dl_addr, dmac, OFP_ETH_ALEN);

    return (sizeof(*dmac_act));
}

char *
of_dump_wildcards(uint32_t wildcards)
{
    uint32_t                 nw_dst_mask, nw_src_mask;   
    char                     *pbuf;
    size_t                   len = 0;
    uint32_t                 ip_wc;
#define OF_DUMP_WC_SZ 4096 
    pbuf = calloc(1, OF_DUMP_WC_SZ);
    assert(pbuf);

    wildcards = ntohl(wildcards);

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = ip_wc >= 32 ? 0 : 
                           make_inet_mask(32-ip_wc); 

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = ip_wc >= 32 ? 0 : 
                           make_inet_mask(32-ip_wc);
    
    /* Reduce this to a line please.... */
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "Wildcards:\r\n");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "smac", (wildcards & OFPFW_DL_SRC) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "dmac", (wildcards & OFPFW_DL_DST) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "eth-type", (wildcards & OFPFW_DL_TYPE) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "vlan-id", (wildcards & OFPFW_DL_VLAN) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "vlan-pcp", (wildcards & OFPFW_DL_VLAN_PCP) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: 0x%08x\r\n",
                    "dst-ip-mask", nw_dst_mask);
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: 0x%08x\r\n",
                    "src-ip-mask", nw_src_mask);
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "ip-proto", (wildcards & OFPFW_NW_PROTO) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "src-port", (wildcards & OFPFW_TP_SRC) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "dst-port", (wildcards & OFPFW_TP_DST) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);
    len += snprintf(pbuf+len, OF_DUMP_WC_SZ-len-1, "%-10s: %s\r\n",
                    "in-port", (wildcards & OFPFW_IN_PORT) ? "*" : "exact");
    assert(len < OF_DUMP_WC_SZ-1);

    return pbuf;
}


char *
of_dump_actions(void *actions, size_t action_len)
{
    char                     *pbuf;
    size_t                   len = 0, parsed_len = 0;
    uint16_t                 act_type;
    struct ofp_action_header *hdr;
#define OF_DUMP_ACT_SZ 4096 
    pbuf = calloc(1, OF_DUMP_ACT_SZ);
    assert(pbuf);

    len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, "Actions: ");
    assert(len < OF_DUMP_ACT_SZ-1); 

    if (!action_len) {
        len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, "None (Drop)");
        assert(len < OF_DUMP_ACT_SZ-1);
        return pbuf;
    }

    while (action_len) {
        hdr =  (struct ofp_action_header *)actions;
        act_type = ntohs(hdr->type);
        switch (act_type) {
        case OFPAT_OUTPUT:
            {
                struct ofp_action_output *op_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, 
                                "%s-Port 0x%x ", 
                                "output", ntohs(op_act->port));    
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*op_act);
                break;
            }
        case OFPAT_SET_VLAN_VID:
            {
                struct ofp_action_vlan_vid *vid_act = (void *)hdr;    
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "%s-vid 0x%04x ",
                                "set-vid", ntohs(vid_act->vlan_vid));
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*vid_act);
                break;
                                 
            } 
        case OFPAT_SET_DL_DST:
            {
                struct ofp_action_dl_addr *dmac_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "%s-%02x:%02x:%02x:%02x:%02x:%02x ",
                                "set-dmac", dmac_act->dl_addr[0], dmac_act->dl_addr[1], 
                                dmac_act->dl_addr[2], dmac_act->dl_addr[3], 
                                dmac_act->dl_addr[4], dmac_act->dl_addr[5]);
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*dmac_act);
                break;
            }
        default:
            {
                c_log_err("%s:unhandled action %u", FN, act_type);
                free(pbuf);
                return NULL;
            }
        }

        action_len -= parsed_len;
        actions = ((uint8_t *)actions + parsed_len);
    }

    return pbuf;
}

int
of_validate_actions(void *actions, size_t action_len)
{
    size_t                   parsed_len = 0;
    uint16_t                 act_type;
    struct ofp_action_header *hdr;

    while (action_len) {
        hdr =  (struct ofp_action_header *)actions;
        act_type = ntohs(hdr->type);
        switch (act_type) {
        case OFPAT_OUTPUT:
            {
                struct ofp_action_output *op_act UNUSED = (void *)hdr;
                parsed_len = sizeof(*op_act);
                break;
            }
        case OFPAT_SET_VLAN_VID:
            {
                struct ofp_action_vlan_vid *vid_act UNUSED = (void *)hdr;    
                parsed_len = sizeof(*vid_act);
                break;
                                 
            } 
        case OFPAT_SET_DL_DST:
            {
                struct ofp_action_dl_addr *dmac_act UNUSED = (void *)hdr;
                parsed_len = sizeof(*dmac_act);
                break;
            }
        default:
            {
                c_log_err("%s:unhandled action %u", FN, act_type);
                return -1;
            }
        }

        action_len -= parsed_len;
        actions = ((uint8_t *)actions + parsed_len);
    }

    return 0;
}

static inline uint32_t
of_alloc_xid(void)
{
    return random_uint32();
}

void * __fastpath
of_prep_msg(size_t len, uint8_t type, uint32_t xid)
{
    struct cbuf *b;
    struct ofp_header *h;

    b = alloc_cbuf(len);
    h = cbuf_put(b, len);

    h->version = OFP_VERSION;
    h->type = type;
    h->length = htons(len);

    if (xid) {
        h->xid = xid;
    } else {
        h->xid = of_alloc_xid();
    }

    memset(h + 1, 0, len - sizeof(*h));

    return b;
}

struct cbuf * __fastpath
of_prep_flow_mod(uint16_t command, const struct flow *flow, 
                 size_t actions_len, uint32_t wildcards)
{
    struct ofp_flow_mod *ofm;
    size_t len = sizeof *ofm + actions_len;
    struct cbuf *b;

    b = alloc_cbuf(len);
    ofm = cbuf_put(b, len);

    memset(ofm, 0, len);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(len);
    ofm->match.wildcards = wildcards;
    ofm->match.in_port = flow->in_port;
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofm->match.nw_src = flow->nw_src;
    ofm->match.nw_dst = flow->nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst;
    ofm->command = htons(command);

    return b;
}

struct cbuf * __fastpath
of_prep_flow_add_msg(const struct flow *flow, uint32_t buffer_id,
                     void *actions, size_t actions_len, 
                     uint16_t i_timeo, uint16_t h_timeo, 
                     uint32_t wildcards, uint16_t prio)
{
    struct cbuf *b = of_prep_flow_mod(OFPFC_MODIFY_STRICT, flow, actions_len, wildcards);
    struct ofp_flow_mod *ofm = (void *)(b->data);
    struct ofp_action_header *ofp_actions;

    ofm->idle_timeout = htons(i_timeo);
    ofm->hard_timeout = htons(h_timeo);
    ofm->priority = htons(prio);
    ofm->buffer_id = htonl(buffer_id);
    ofp_actions = (void *)(ofm + 1);
    memcpy(ofp_actions, actions, actions_len);

    return b;
}

struct cbuf *
of_prep_flow_del_msg(const struct flow *flow, uint32_t wildcards, 
                     uint16_t oport, bool strict)
{
    struct cbuf *b = of_prep_flow_mod(strict ? OFPFC_DELETE_STRICT:OFPFC_DELETE, flow, 
                                      0, wildcards);
    struct ofp_flow_mod *ofm = (void *)(b->data);

    ofm->out_port = htons(oport?:OFPP_NONE);
    return b;
}

void * __fastpath
of_prep_pkt_out_msg(struct of_pkt_out_params *parms)
{
    uint8_t               tot_len;
    struct ofp_packet_out *out;
    struct cbuf           *b;
    void                  *data;

    tot_len = sizeof(struct ofp_packet_out) + parms->action_len
                + parms->data_len;

    b = of_prep_msg(tot_len, OFPT_PACKET_OUT, (unsigned long)parms->data);

    out = (void *)b->data;
    out->buffer_id = htonl(parms->buffer_id);
    out->in_port   = htons(parms->in_port);
    out->actions_len = htons(parms->action_len);

    data = (uint8_t *)out->actions + parms->action_len;
    /* Hate it !! */
    memcpy(out->actions, parms->action_list, parms->action_len);
    memcpy(data, parms->data, parms->data_len);

    return b;
}
