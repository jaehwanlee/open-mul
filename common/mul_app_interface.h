/*
 *  mul_app_interface.h: MUL application interface public headers
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

#ifndef __MUL_APP_INTERFACE_H__
#define __MUL_APP_INTERFACE_H__

typedef void (*initcall_t)(void *);
extern initcall_t __start_modinit_sec, __stop_modinit_sec;
#define data_attr         __attribute__ ((section ("modinit_sec")))
#define module_init(x)   initcall_t _##x data_attr = x

extern initcall_t __start_modvtyinit_sec, __stop_modvtyinit_sec;
#define vty_attr         __attribute__ ((section ("modvtyinit_sec")))
#define module_vty_init(x)  initcall_t _##x vty_attr = x

#include "openflow.h"

/* Controller app event notifications */
typedef enum c_app_event {
    C_DP_REG,
    C_DP_UNREG,
    C_PACKET_IN,
    C_PORT_CHANGE,
    C_FLOW_REMOVED,
    C_EVENT_MAX
} c_app_event_t;
#define C_APP_ALL_EVENTS  ((1 << C_EVENT_MAX) - 1) 

#define C_OFP_VERSION             (0xfe)
#define C_OFPT_BASE               (0xc0)
#define C_OFPT_SWITCH_ADD         (OFPT_FEATURES_REPLY)
#define C_OFPT_PACKET_IN          (OFPT_PACKET_IN)
#define C_OFPT_PACKET_OUT         (OFPT_PACKET_OUT)
#define C_OFPT_PORT_STATUS        (OFPT_PORT_STATUS)
#define C_OFPT_SWITCH_DELETE      (C_OFPT_BASE)
#define C_OFPT_FLOW_MOD           (OFPT_FLOW_MOD)
#define C_OFPT_PACKET_IN          (OFPT_PACKET_IN)
#define C_OFPT_FLOW_REMOVED       (OFPT_FLOW_REMOVED)
#define C_OFPT_ERR_MSG            (OFPT_ERROR)
#define C_OFPT_REG_APP            (C_OFPT_BASE + 1)
#define C_OFPT_UNREG_APP          (C_OFPT_BASE + 2)
#define C_OFPT_RECONN_APP         (C_OFPT_BASE + 3)
#define C_OFPT_NOCONN_APP         (C_OFPT_BASE + 4)
#define C_OFPT_SET_FPOPS          (C_OFPT_BASE + 5)

struct c_ofp_switch_delete {
    struct ofp_header header;
    uint64_t          datapath_id;
};


struct c_ofp_port_status {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            config_mask;
    uint32_t            state_mask;
    uint8_t             reason;          /* One of OFPPR_*. */
    uint8_t             pad[7];          /* Align to 64-bits. */
    struct ofp_phy_port desc;
};
OFP_ASSERT(sizeof(struct c_ofp_port_status)==sizeof(struct ofp_port_status)+16);

struct flow {
    uint32_t            nw_src;            /* IP source address. */
    uint32_t            nw_dst;            /* IP destination address. */
    uint16_t            in_port;           /* Input switch port. */
    uint16_t            dl_vlan;           /* Input VLAN id. */
    uint16_t            dl_type;           /* Ethernet frame type. */
    uint16_t            tp_src;            /* TCP/UDP source port. */
    uint16_t            tp_dst;            /* TCP/UDP destination port. */
    uint8_t             dl_src[6];         /* Ethernet source address. */
    uint8_t             dl_dst[6];         /* Ethernet destination address. */
    uint8_t             dl_vlan_pcp;       /* Input VLAN priority. */
    uint8_t             nw_tos;            /* IPv4 DSCP. */
    uint8_t             nw_proto;          /* IP protocol. */
    uint8_t             pad[3];
};

struct c_ofp_packet_in {
    struct ofp_header header;
    uint64_t          datapath_id;    
    struct flow       fl;
    uint32_t          buffer_id;     /* ID assigned by datapath. */
    uint16_t          total_len;     /* Full length of frame. */
    uint16_t          in_port;       /* Port on which frame was received. */
    uint8_t           reason;        /* Reason packet is being sent (one of OFPR_*) */
    uint8_t           pad;
    uint8_t           data[0];       /* Ethernet frame, halfway through 32-bit word,
                                        so the IP header is 32-bit aligned.  The
                                        amount of data is inferred from the length
                                        field in the header.  Because of padding,
                                        offsetof(struct ofp_packet_in, data) ==
                                        sizeof(struct ofp_packet_in) - 2. */
};
OFP_ASSERT(sizeof(struct c_ofp_packet_in) == (sizeof(struct ofp_packet_in)+8+36));


struct c_ofp_flow_mod {
    struct ofp_header   header;
    uint64_t            datapath_id;

    struct flow         flow; 
#define C_FL_ENT_STATIC     (0x1) 
#define C_FL_ENT_CLONE      (0x2)
#define C_FL_ENT_LOCAL      (0x4)
#define C_FL_ENT_NOCACHE    (0x8)
#define C_FL_ENT_NOSYNC     (0x10)
    uint8_t             flags;
#define C_OFPC_ADD  0
#define C_OFPC_DEL  1
    uint8_t             command;
#define C_FL_PRIO_DFL 0
#define C_FL_PRIO_FWD 1
#define C_FL_PRIO_DRP 2
#define C_FL_PRIO_EXM 65535
    uint16_t            priority;
    uint32_t            wildcards;
    uint16_t            itimeo;
    uint16_t            htimeo;
    uint16_t            mod_flags;
    uint16_t            oport;
    uint32_t            buffer_id;
    struct ofp_action_header actions[0];
};

/* Flow removed (datapath -> controller). */
struct c_ofp_flow_removed {
    struct ofp_header   header;
    uint64_t            datapath_id;
    struct flow         flow;
    uint32_t            wildcards;      /* Wildcards */
    uint64_t            cookie;         /* Opaque controller-issued identifier.*/
    uint16_t            priority;       /* Priority level of flow entry. */
    uint8_t             reason;         /* One of OFPRR_*. */             
    uint8_t             pad[1];         /* Align to 32-bits. */           
    uint32_t            duration_sec;   /* Time flow was alive in seconds. */
    uint32_t            duration_nsec;  /* Time flow was alive in nanosecs beyond
                                           duration_sec. */               
    uint16_t            idle_timeout;   /* Idle timeout from original flow mod.*/
    uint8_t             pad2[2];        /* Align to 64-bits. */           
    uint64_t            packet_count;                                      
    uint64_t            byte_count;                                        
};  
OFP_ASSERT(sizeof(struct ofp_flow_removed) == 88);

struct c_ofp_packet_out {
    struct ofp_header   header;
    uint64_t            datapath_id;
    uint32_t            buffer_id;    
    uint16_t            in_port;
    uint16_t            actions_len; 
    struct ofp_action_header actions[0]; 
    /* uint8_t data[0]; */        /* Packet data.  The length is inferred
                                     from the length field in the header.
                                     (Only meaningful if buffer_id == -1.) */
};

struct c_ofp_register_app {
    struct ofp_header   header;
#define C_MAX_APP_STRLEN  64 
    char                app_name[C_MAX_APP_STRLEN];
#define C_APP_ALL_SW        0x01
#define C_APP_REMOTE        0x02
    uint32_t            app_flags;
    uint32_t            ev_mask;
    uint32_t            dpid;
    uint64_t            dpid_list[0];
};

struct c_ofp_unregister_app {
   struct ofp_header   header;
   char                app_name[C_MAX_APP_STRLEN];
  
};

struct c_ofp_set_fp_ops {
    struct ofp_header   header;
    uint64_t            datapath_id;
#define C_FP_TYPE_DFL 0
#define C_FP_TYPE_L2 1
    uint32_t            fp_type;
    uint8_t             pad[3];
}; 

#define C_OFP_ERR_CODE_BASE (100)

/* More bad request codes */
#define OFPBRC_BAD_DPID     (C_OFP_ERR_CODE_BASE)
#define OFPBRC_BAD_APP_REG  (C_OFP_ERR_CODE_BASE + 1)
#define OFPBRC_BAD_APP_UREG (C_OFP_ERR_CODE_BASE + 2)

/* More bad action codes */
#define OFPBAC_BAD_GENERIC  (C_OFP_ERR_CODE_BASE)  

/* More flow mod failed codes */
#define OFPFMFC_BAD_FLAG    (C_OFP_ERR_CODE_BASE)   
#define OFPFMFC_GENERIC     (C_OFP_ERR_CODE_BASE + 1)   

#define C_OFP_MAX_ERR_LEN 128

typedef struct c_ofp_switch_delete c_ofp_switch_delete_t;
typedef struct ofp_switch_features c_ofp_switch_add_t;
typedef struct c_ofp_packet_in c_ofp_packet_in_t;;
typedef struct c_ofp_port_status c_ofp_port_status_t;
typedef struct c_ofp_flow_mod c_ofp_flow_mod_t;
typedef struct c_ofp_packet_out c_ofp_packet_out_t; 
typedef struct c_ofp_register_app c_ofp_register_app_t;
typedef struct c_ofp_unregister_app c_ofp_unregister_app_t;
typedef struct c_ofp_set_fp_ops c_ofp_set_fp_ops_t;
typedef struct ofp_error_msg c_ofp_error_msg_t;

void mul_app_free_buf(void *b);
int mul_register_app(void *app, char *app_name, uint32_t app_flags,
                     uint32_t ev_mask, uint32_t n_dpid, uint64_t *dpid_list,
                     void  (*ev_cb)(void *app_arg, void *pkt_arg));
int mul_unregister_app(char *app_name);
int mul_app_command_handler(void *app_name,void *b);
int mul_app_send_flow_add(void *app_name, void *sw_arg, uint64_t dpid, struct flow *fl,
                          uint32_t buffer_id, void *actions, size_t action_len,
                          uint16_t itimeo, uint16_t htimeo, uint32_t wildcards,
                          uint16_t prio, uint8_t flag);
int mul_app_send_flow_del(void *app_name, void *sw_arg, uint64_t dpid,
                          struct flow *fl, uint32_t wildcards, 
                          uint16_t port, uint8_t flag);
void mul_app_send_pkt_out(void *sw_arg, uint64_t dpid, void *parms);

#endif
