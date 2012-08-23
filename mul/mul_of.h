/*
 *  mul_of.h: MUL openflow abstractions 
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
#ifndef __MUL_OF_H__
#define __MUL_OF_H__
    
#define OF_MAX_ACTION_LEN   1024

#define OF_PKT_NEXT_HDR(h_, tot, rem) ((void *)((uint8_t *)h_ + tot - rem))

typedef void (*ofp_handler_t)(c_switch_t *sw, struct cbuf *b);

struct of_handler {
    ofp_handler_t handler;
    size_t min_size;
};

#define OFP_HDR_SZ          sizeof(struct ofp_header)
#define NULL_OF_HANDLER     {NULL,sizeof(struct ofp_header)}
#define OF_UNK_MSG(h, type) (type > (sizeof(of_handlers)/sizeof(of_handlers[0])) \
                             || !h[type].handler)

#define RET_OF_MSG_HANDLER(sw, h, b, type, length)                              \
do {                                                                            \
    if (unlikely(length < h[type].min_size || OF_UNK_MSG(h, type))) {           \
        c_log_err("unexpected length(%u) or type(%u)", (unsigned)length, type); \
        return;                                                                 \
    }                                                                           \
    return h[type].handler(sw, (void *)b);                                      \
} while(0)


#define FL_NEED_HW_SYNC(parms) (((parms)->flags & C_FL_ENT_NOSYNC) || \
                                (parms)->flags & C_FL_ENT_CLONE) || \
                                ((parms)->flags & C_FL_ENT_LOCAL)? false : true;

#define FL_EXM_NEED_HW_SYNC(parms) ((parms)->flags & C_FL_ENT_NOSYNC || \
                                    (parms)->flags & C_FL_ENT_LOCAL) ? \
                                            false : true;

void            of_send_features_request(c_switch_t *sw);
void            of_send_echo_request(c_switch_t *sw);
void            of_send_hello(c_switch_t *sw);
void            of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms);
void            of_send_echo_reply(c_switch_t *sw, uint32_t xid);
void            __of_send_features_request(c_switch_t *sw);
void            __of_send_echo_request(c_switch_t *sw);
void            __of_send_hello(c_switch_t *sw);
void            __of_send_pkt_out(c_switch_t *sw, struct of_pkt_out_params *parms);
void            __of_send_echo_reply(c_switch_t *sw, uint32_t xid);
void            of_switch_recv_msg(void *sw_arg, struct cbuf *b);
void            of_switch_add(c_switch_t *sw);
void            of_switch_del(c_switch_t *sw);
void            of_switch_flow_tbl_delete(c_switch_t *sw);
int             of_flow_extract(uint8_t *pkt, struct flow *flow,
                            uint16_t in_port, size_t pkt_len);
void            of_flow_entry_put(c_fl_entry_t *ent);
int             of_flow_add(c_switch_t *sw, struct of_flow_mod_params *parms); 
int             of_flow_del(c_switch_t *sw, struct of_flow_mod_params *parms);
int             of_send_flow_add_nocache(c_switch_t *sw, struct flow *fl,
                            uint32_t buffer_id, void *actions,  
                            size_t action_len, uint16_t itimeo, 
                            uint16_t htimeo, uint32_t wildcards, uint16_t prio);
int             of_send_flow_del_nocache(c_switch_t *sw, struct flow *fl,
                             uint32_t wildcards, uint16_t oport, bool strict);
int             __of_send_flow_add_nocache(c_switch_t *sw, struct flow *fl,
                            uint32_t buffer_id, void *actions,  
                            size_t action_len, uint16_t itimeo, 
                            uint16_t htimeo, uint32_t wildcards, uint16_t prio);
int             __of_send_flow_del_nocache(c_switch_t *sw, struct flow *fl,
                             uint32_t wildcards, uint16_t oport, bool strict);
char            *of_dump_flow_all(struct flow *fl);
char            *of_dump_flow(struct flow *fl, uint32_t wildcards);
char            *of_dump_fl_app(c_fl_entry_t *ent);
typedef         void (*flow_parser_fn)(void *arg, c_fl_entry_t *ent); 
void            of_flow_traverse_tbl_all(c_switch_t *sw, void *u_arg, flow_parser_fn fn);
void            __of_per_switch_del_app_flow_ownership(c_switch_t *sw, void *app);
void            *of_switch_alloc(void *ctx);
c_switch_t      *of_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid);
c_switch_t      *__of_switch_get(ctrl_hdl_t *ctrl, uint64_t dpid);
void            of_switch_put(c_switch_t *sw);
void            of_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc dump_fn, void *arg);
void            __of_switch_traverse_all(ctrl_hdl_t *hdl, GHFunc dump_fn, void *arg);
int             of_dfl_fwd(struct c_switch *sw, struct cbuf *b, void *data,
                           size_t pkt_len, struct flow *fl, uint16_t in_port);
int             of_dfl_port_status(c_switch_t *sw, uint32_t cfg, uint32_t state);

int             of_ctrl_init(ctrl_hdl_t *c_hdl, size_t nthreads, size_t n_appthreads);


#endif
