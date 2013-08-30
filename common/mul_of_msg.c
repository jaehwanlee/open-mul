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
of_make_action_strip_vlan(char **pbuf, size_t bufroom)
{
    struct ofp_action_header *vid_strip_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*vid_strip_act));
        bufroom = sizeof(*vid_strip_act);
        assert(*pbuf);
    }

    assert(sizeof(*vid_strip_act) <= bufroom);
    
    vid_strip_act = (void *)(*pbuf);

    vid_strip_act->type = htons(OFPAT_STRIP_VLAN);
    vid_strip_act->len  = htons(sizeof(*vid_strip_act));

    return (sizeof(*vid_strip_act));
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

size_t
of_make_action_set_smac(char **pbuf, size_t bufroom, uint8_t *smac)
{
    struct ofp_action_dl_addr *smac_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*smac_act));
        bufroom = sizeof(*smac_act);
        assert(*pbuf);
    }

    assert(sizeof(*smac_act) <= bufroom);
    
    smac_act = (void *)(*pbuf);

    smac_act->type = htons(OFPAT_SET_DL_SRC);
    smac_act->len  = htons(sizeof(*smac_act));
    memcpy(smac_act->dl_addr, smac, OFP_ETH_ALEN);

    return (sizeof(*smac_act));
}

size_t
of_make_action_set_vlan_pcp(char **pbuf, size_t bufroom, uint8_t vlan_pcp)
{
    struct ofp_action_vlan_pcp *vpcp_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*vpcp_act));
        bufroom = sizeof(*vpcp_act);
        assert(*pbuf);
    }

    assert(sizeof(*vpcp_act) <= bufroom);

    vpcp_act = (void *)(*pbuf);

    vpcp_act->type = htons(OFPAT_SET_VLAN_PCP);
    vpcp_act->len = htons(sizeof(*vpcp_act));
    vpcp_act->vlan_pcp = (vlan_pcp & 0x7);

    return (sizeof(*vpcp_act));
}

static size_t
of_make_action_set_nw_ip(char **pbuf, size_t bufroom, uint32_t ip, 
                         uint16_t type)
{
    struct ofp_action_nw_addr *nw_addr_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*nw_addr_act));
        bufroom = sizeof(*nw_addr_act);
        assert(*pbuf);
    }

    assert(sizeof(*nw_addr_act) <= bufroom);
    
    nw_addr_act = (void *)(*pbuf);

    nw_addr_act->type = htons(type);
    nw_addr_act->len  = htons(sizeof(*nw_addr_act));
    nw_addr_act->nw_addr = htonl(ip);

    return (sizeof(*nw_addr_act));
}

size_t
of_make_action_set_nw_saddr(char **pbuf, size_t bufroom, uint32_t nw_saddr) 
{
    return of_make_action_set_nw_ip(pbuf, bufroom, nw_saddr, OFPAT_SET_NW_SRC); 
}

size_t
of_make_action_set_nw_daddr(char **pbuf, size_t bufroom, uint32_t nw_daddr) 
{
    return of_make_action_set_nw_ip(pbuf, bufroom, nw_daddr, OFPAT_SET_NW_DST); 
}

size_t
of_make_action_set_nw_tos(char **pbuf, size_t bufroom, uint8_t tos) 
{
    struct ofp_action_nw_tos *nw_tos_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*nw_tos_act));
        bufroom = sizeof(*nw_tos_act);
        assert(*pbuf);
    }

    assert(sizeof(*nw_tos_act) <= bufroom);
    
    nw_tos_act = (void *)(*pbuf);

    nw_tos_act->type = htons(OFPAT_SET_NW_TOS);
    nw_tos_act->len  = htons(sizeof(*nw_tos_act));
    nw_tos_act->nw_tos = tos & ((0x1<<7) - 1);

    return (sizeof(*nw_tos_act));
}

static size_t
of_make_action_set_tp_port(char **pbuf, size_t bufroom, uint16_t port,
                           uint16_t type) 
{
    struct ofp_action_tp_port *tp_port_act;

    if (!(*pbuf)) {
        *pbuf = (void *)calloc(1, sizeof(*tp_port_act));
        bufroom = sizeof(*tp_port_act);
        assert(*pbuf);
    }

    assert(sizeof(*tp_port_act) <= bufroom);

    tp_port_act = (void *)(*pbuf);

    tp_port_act->type = htons(type);
    tp_port_act->len  = htons(sizeof(*tp_port_act));
    tp_port_act->tp_port = htons(port);

    return (sizeof(*tp_port_act));
}

size_t
of_make_action_set_tp_sport(char **pbuf, size_t bufroom, uint16_t port)
{
    return of_make_action_set_tp_port(pbuf, bufroom, port, OFPAT_SET_TP_SRC);
}


size_t
of_make_action_set_tp_dport(char **pbuf, size_t bufroom, uint16_t port)
{
    return of_make_action_set_tp_port(pbuf, bufroom, port, OFPAT_SET_TP_DST);
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
        len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, "None (Drop)\r\n");
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
        case OFPAT_SET_DL_SRC:
            {
                struct ofp_action_dl_addr *smac_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "set-smac "
                                "%02x:%02x:%02x:%02x:%02x:%02x ",
                                smac_act->dl_addr[0], smac_act->dl_addr[1],
                                smac_act->dl_addr[2], smac_act->dl_addr[3],
                                smac_act->dl_addr[4], smac_act->dl_addr[5]);
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*smac_act);
                break;
            }
        case OFPAT_SET_VLAN_PCP:
            {
                struct ofp_action_vlan_pcp *vpcp_act = (void *)hdr;
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "vlan-pcp %d ",
                                vpcp_act->vlan_pcp);
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*vpcp_act);
                break;
            }
        case OFPAT_STRIP_VLAN:
            {
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "strip-vlan ");
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(struct ofp_action_header);
                break;
            }
        case OFPAT_SET_NW_SRC:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                struct in_addr in_addr = { .s_addr = nw_addr_act->nw_addr };
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "nw-saddr %s ", inet_ntoa(in_addr));
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*nw_addr_act);
                break;
            }
        case OFPAT_SET_NW_DST:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                struct in_addr in_addr = { .s_addr = nw_addr_act->nw_addr };
                len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1,
                                "nw-daddr %s ", inet_ntoa(in_addr));
                assert(len < OF_DUMP_ACT_SZ-1);
                parsed_len = sizeof(*nw_addr_act);
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

    len += snprintf(pbuf+len, OF_DUMP_ACT_SZ-len-1, "\r\n");
    assert(len < OF_DUMP_ACT_SZ-1);

    return pbuf;
}


char *
of_dump_flow(struct flow *fl, uint32_t wildcards)   
{
#define FL_PBUF_SZ 4096
    char     *pbuf = calloc(1, FL_PBUF_SZ);
    int      len = 0;
    uint32_t nw_dst_mask, nw_src_mask;
    uint32_t dip_wc, sip_wc;
    struct in_addr in_addr;

    wildcards = ntohl(wildcards);
    dip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    nw_dst_mask = dip_wc >= 32 ? 0 :
                           make_inet_mask(32-dip_wc);

    sip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    nw_src_mask = sip_wc >= 32 ? 0 :
                           make_inet_mask(32-sip_wc);

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "Flow: ");
    assert(len < FL_PBUF_SZ-1);

    if (wildcards == OFPFW_ALL) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1, "All Fields Wildcards");
        assert(len < FL_PBUF_SZ-1);
        return pbuf;
    }

    if (!(wildcards & OFPFW_DL_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "smac", fl->dl_src[0], fl->dl_src[1], fl->dl_src[2],
                   fl->dl_src[3], fl->dl_src[4], fl->dl_src[5]);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                   "%s:%02x:%02x:%02x:%02x:%02x:%02x ",
                   "dmac", fl->dl_dst[0], fl->dl_dst[1], fl->dl_dst[2],
                   fl->dl_dst[3], fl->dl_dst[4], fl->dl_dst[5]);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "eth-type", ntohs(fl->dl_type));
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_DL_VLAN)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-id",  ntohs(fl->dl_vlan));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_DL_VLAN_PCP)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "vlan-pcp", fl->dl_vlan_pcp);
        assert(len < FL_PBUF_SZ-1);

    }
    if (nw_dst_mask) {
        in_addr.s_addr = fl->nw_dst & htonl(nw_dst_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:%s/%d ",
                     "dst-ip", inet_ntoa(in_addr),
                     dip_wc >= 32 ? 0 : 32 - dip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (nw_src_mask) {
        in_addr.s_addr = fl->nw_src & htonl(nw_src_mask);
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                     "%s:%s/%d ", 
                     "src-ip", inet_ntoa(in_addr),
                     sip_wc >= 32 ? 0 : 32-sip_wc);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_PROTO)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-proto", fl->nw_proto);
        assert(len < FL_PBUF_SZ-1);
    }
    if (!(wildcards & OFPFW_NW_TOS)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                     "ip-tos", fl->nw_tos);
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_SRC)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "src-port", ntohs(fl->tp_src));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_TP_DST)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "dst-port", ntohs(fl->tp_dst));
        assert(len < FL_PBUF_SZ-1);
    }

    if (!(wildcards & OFPFW_IN_PORT)) {
        len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "%s:0x%x ",
                    "in-port", ntohs(fl->in_port));
        assert(len < FL_PBUF_SZ-1);
    }

    len += snprintf(pbuf+len, FL_PBUF_SZ-len-1,
                    "\r\n");

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
                struct ofp_action_output *op_act = (void *)hdr;
                if (!ntohs(op_act->port)) {
                    return -1;
                }
                parsed_len = sizeof(*op_act);
                break;
            }
        case OFPAT_SET_VLAN_VID:
            {
                struct ofp_action_vlan_vid *vid_act = (void *)hdr;    
                parsed_len = sizeof(*vid_act);
                break;
                                 
            } 
        case OFPAT_SET_DL_DST:
        case OFPAT_SET_DL_SRC:
            {
                struct ofp_action_dl_addr *mac_act = (void *)hdr;
                parsed_len = sizeof(*mac_act);
                break;
            }
        case OFPAT_SET_VLAN_PCP:
            {
                struct ofp_action_vlan_pcp *vpcp_act = (void *)hdr;
                parsed_len = sizeof(*vpcp_act);
                break;

            }
        case OFPAT_STRIP_VLAN:
            {
                struct ofp_action_header *strip_vlan_act UNUSED = (void *)hdr;
                parsed_len = sizeof(*strip_vlan_act);
                break;
            }
        case OFPAT_SET_NW_SRC:
        case OFPAT_SET_NW_DST:
            {
                struct ofp_action_nw_addr *nw_addr_act = (void *)hdr;
                parsed_len = sizeof(*nw_addr_act);
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

int
of_flow_correction(struct flow *fl, uint32_t *wc)
{
    uint16_t eth_proto;
    uint32_t wildcards;
    uint32_t ip_wc;

    if (!fl || !wc) return -1;

    wildcards = ntohl(*wc);

    if (!(wildcards & OFPFW_IN_PORT) &&
        (!fl->in_port)) {
        return -1;    
    }

    ip_wc = ((wildcards & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_DST_MASK;
        wildcards |= OFPFW_NW_DST_ALL;
    }

    ip_wc = ((wildcards & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT);
    if (ip_wc >= 32) {
        wildcards &= ~OFPFW_NW_SRC_MASK;
        wildcards |= OFPFW_NW_SRC_ALL;
    }

    if (!(wildcards & OFPFW_DL_TYPE)) {
        eth_proto = ntohs(fl->dl_type);

        if (eth_proto == ETH_TYPE_ARP) {
            fl->nw_proto = 0;
            fl->nw_tos = 0;
            fl->tp_src = 0;
            fl->tp_dst = 0;
            wildcards |= OFPFW_NW_PROTO | OFPFW_NW_TOS |
                         OFPFW_TP_DST | OFPFW_TP_SRC;
        } else if (eth_proto == ETH_TYPE_IP) {
            if (wildcards & OFPFW_NW_PROTO) {
                fl->tp_src = 0;
                fl->tp_dst = 0;
                wildcards |= OFPFW_TP_DST | OFPFW_TP_SRC;
            }
        } else {
            fl->tp_src = 0;
            fl->tp_dst = 0;
            fl->nw_src = 0;
            fl->nw_dst = 0;
            fl->nw_tos = 0;
            fl->nw_proto = 0;
            wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                         OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
        }
    } else {
        fl->tp_src = 0;
        fl->tp_dst = 0;
        fl->nw_src = 0;
        fl->nw_dst = 0;
        fl->nw_tos = 0;
        fl->nw_proto = 0;
        wildcards |= OFPFW_NW_DST_ALL | OFPFW_NW_SRC_ALL | OFPFW_NW_PROTO |
                     OFPFW_NW_TOS | OFPFW_TP_DST | OFPFW_TP_SRC;
    }

    *wc = htonl(wildcards);

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
    size_t                tot_len;
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

struct cbuf * 
of_prep_flow_stat_msg(const struct flow *flow, uint32_t wildcards, 
                     uint8_t tbl_id, uint16_t oport)
{
    struct ofp_stats_request *osr;
    struct ofp_flow_stats_request *ofsr;
    size_t len = sizeof *osr + sizeof *ofsr;
    struct cbuf *b;

    b = of_prep_msg(len, OFPT_STATS_REQUEST, 0);
    osr = (void *)(b->data);

    osr->type = htons(OFPST_FLOW);

    ofsr = (void *)(osr->body);

    ofsr->table_id = tbl_id;
    ofsr->out_port = htons(oport?:OFPP_NONE);

    ofsr->match.wildcards = wildcards;
    ofsr->match.in_port = flow->in_port;
    memcpy(ofsr->match.dl_src, flow->dl_src, sizeof ofsr->match.dl_src);
    memcpy(ofsr->match.dl_dst, flow->dl_dst, sizeof ofsr->match.dl_dst);
    ofsr->match.dl_vlan = flow->dl_vlan;
    ofsr->match.dl_type = flow->dl_type;
    ofsr->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofsr->match.nw_src = flow->nw_src;
    ofsr->match.nw_dst = flow->nw_dst;
    ofsr->match.nw_proto = flow->nw_proto;
    ofsr->match.tp_src = flow->tp_src;
    ofsr->match.tp_dst = flow->tp_dst;
 
    return b;
}
