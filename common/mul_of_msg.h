/*
 *  mul_of_msg.h: MUL openflow message handling 
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
#ifndef __MUL_OF_MSG_H__
#define __MUL_OF_MSG_H__

#define OF_ALL_TABLES (0xff) 

static inline int
of_get_data_len(void *h)
{
    return ntohs(((struct ofp_header *)h)->length);
}

static inline bool 
of_hdr_valid(void *h_arg)
{
    struct ofp_header *h = h_arg;
    return ntohs(h->length) <= 4096 && h->version == 1 && h->type < OFPT_BARRIER_REPLY;
}

static inline bool
c_app_of_hdr_valid(void *h_arg)
{
    struct ofp_header *h = h_arg;
    return ntohs(h->length) <= 4096 && h->version == 1 &&
            ((h->type >= 0 && h->type <= C_OFPT_AUX_CMD));
}

struct of_flow_mod_params {
    void        *app_owner;
    struct flow *flow;
    void        *actions;
    size_t      action_len;
    uint32_t    wildcards;
    uint32_t    buffer_id;
    uint16_t    prio;
    uint16_t    itimeo; 
    uint16_t    htimeo;
    uint8_t     flags;
    uint8_t     tbl_idx;
};

struct of_pkt_out_params {
    uint32_t buffer_id;
    uint16_t in_port;
    uint16_t action_len;
    void     *action_list;
    void     *data;
    uint16_t data_len;
    uint8_t  pad[2];
};  

size_t of_make_action_output(char **pbuf, size_t bufroom, uint16_t oport);
size_t of_make_action_set_vid(char **pbuf, size_t bufroom, uint16_t vid);
size_t of_make_action_strip_vlan(char **pbuf, size_t bufroom);
size_t of_make_action_set_dmac(char **pbuf, size_t bufroom, uint8_t *dmac);
size_t of_make_action_set_nw_saddr(char **pbuf, size_t bufroom, uint32_t nw_saddr);
size_t of_make_action_set_nw_daddr(char **pbuf, size_t bufroom, uint32_t nw_saddr);
size_t of_make_action_set_vlan_pcp(char **pbuf, size_t bufroom, uint8_t vlan_pcp);
size_t of_make_action_set_smac(char **pbuf, size_t bufroom, uint8_t *smac);
size_t of_make_action_set_nw_tos(char **pbuf, size_t bufroom, uint8_t tos);
size_t of_make_action_set_tp_dport(char **pbuf, size_t bufroom, uint16_t port);
size_t of_make_action_set_tp_sport(char **pbuf, size_t bufroom, uint16_t port);
char *of_dump_actions(void *actions, size_t action_len);
char *of_dump_flow(struct flow *fl, uint32_t wildcards);
int of_flow_correction(struct flow *fl, uint32_t *wildcards);
int of_validate_actions(void *actions, size_t action_len);
char *of_dump_wildcards(uint32_t wildcards);
void *of_prep_msg(size_t len, uint8_t type, uint32_t xid);
struct cbuf *of_prep_flow_mod(uint16_t command, const struct flow *flow, 
                              size_t actions_len, uint32_t wildcards);  
struct cbuf *of_prep_flow_add_msg(const struct flow *flow, uint32_t buffer_id,
                                  void *actions, size_t actions_len, 
                                  uint16_t i_timeo, uint16_t h_timeo, 
                                  uint32_t wildcards, uint16_t prio);
struct cbuf *of_prep_flow_del_msg(const struct flow *flow, uint32_t wildcards,
                                  uint16_t oport, bool strict);
void *of_prep_pkt_out_msg(struct of_pkt_out_params *parms);
struct cbuf *of_prep_flow_stat_msg(const struct flow *flow, uint32_t wildcards,
                                   uint8_t tbl_id, uint16_t oport);


#endif
