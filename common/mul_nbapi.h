/*
 *  mul_nbapi.h: MUL nbapi message types 
 *  Copyright (C) 2012, Seokhwan Kong <seokhwan.kong@kulcloud.net>
 *                      Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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

#ifndef __MUL_NBAPI_H__
#define __MUL_NBAPI_H__

#define NB_SW_PORT_MAX             128 
#define NB_SW_MAX                  1024 
#define NB_FLOW_MAX                4096 
#define NB_ACTION_MAX              1
#define NB_STATE_MAX               16
#define NB_HOP_MAX                 32
#define NB_HOST_MAX                32
#define NB_BUFSIZE                 512
#define NB_MAX_PPS_SIZE            32
#define NB_MAX_BPS_SIZE            32
    
struct nb_port_ 
{    
    uint16_t                    port_no;
    uint32_t                    config;
    uint32_t                    state;
};
typedef struct nb_port_ nb_port_t;

struct nbapi_req_message {
    uint16_t                    type;
    uint16_t                    len;
};
typedef struct nbapi_req_message nbapi_req_message_t;

struct nbapi_resp_message {
    uint16_t                    type;
    uint16_t                    len;    
};
typedef struct nbapi_resp_message nbapi_resp_message_t;

struct nbapi_resp_config_status {
    nbapi_resp_message_t        header;
    uint16_t                    status;
    uint8_t                     pad1[2];
};
typedef struct nbapi_resp_config_status nbapi_resp_config_status_t;

struct nbapi_resp_simple_swinfo {
    uint64_t                    swid;    
    char                        state[NB_STATE_MAX]; 
    char                        conn_str[OFP_CONN_DESC_SZ];
    uint32_t                    port_len;
};
typedef struct nbapi_resp_simple_swinfo nbapi_resp_simple_swinfo_t;

struct nbapi_resp_swinfo {
    uint64_t                    dpid;   
    uint8_t                     port_len;
    nb_port_t                   ports[NB_SW_PORT_MAX];
};
typedef struct nbapi_resp_swinfo nbapi_resp_swinfo_t;

typedef struct nb_fl_entry_stats_
{   
    uint64_t                    byte_count;
    uint64_t                    pkt_count;
    uint8_t                     pps[NB_MAX_PPS_SIZE];
    uint8_t                     bps[NB_MAX_BPS_SIZE];
    uint64_t                    last_refresh;
}nb_fl_entry_stats_t;

struct nbapi_resp_flowinfo {
    struct flow                 fl;    
    nb_fl_entry_stats_t         fl_stats;
};
typedef struct nbapi_resp_flowinfo nbapi_resp_flowinfo_t;

struct nbapi_resp_show_of_switch {
    nbapi_resp_message_t        header;
    uint8_t                     switch_len;
    nbapi_resp_swinfo_t         switch_info[NB_SW_MAX];
};
typedef struct nbapi_resp_show_of_switch nbapi_resp_show_of_switch_t;

struct nbapi_resp_show_of_switch_all {
    nbapi_resp_message_t        header;
    uint8_t                     switch_len;
    nbapi_resp_simple_swinfo_t  switches[NB_SW_MAX];
};
typedef struct nbapi_resp_show_of_switch_all nbapi_resp_show_of_switch_all_t;

struct nbapi_resp_show_of_flow {
    nbapi_resp_message_t        header;
    uint8_t                     flow_len;
    uint8_t                     pad1[11];
    nbapi_resp_flowinfo_t       flows[NB_FLOW_MAX];
};
typedef struct nbapi_resp_show_of_flow nbapi_resp_show_of_flow_t;

struct nbapi_resp_lldp_port_info {
    uint16_t                    port_no;
    uint8_t                     status[16];
    uint64_t                    other_dpid;
    uint16_t                    other_portid;
};
typedef struct nbapi_resp_lldp_port_info nbapi_resp_lldp_port_info_t;

struct nbapi_resp_show_of_lldp {
    nbapi_resp_message_t header;
    uint32_t                    port_len;
    nbapi_resp_lldp_port_info_t ports[NB_SW_PORT_MAX];
};
typedef struct nbapi_resp_show_of_lldp nbapi_resp_show_of_lldp_t;

struct nbapi_resp_show_of_path_route {
    nbapi_resp_message_t        header;
    uint8_t                     hop_len;
    uint8_t                     pad1[11];
    rt_path_elem_t              hops[NB_HOP_MAX];
};
typedef struct nbapi_resp_show_of_path_route nbapi_resp_show_of_path_route_t;

struct nbapi_resp_fab_info {
    uint32_t                    sw_alias;
    uint16_t                    link;
};
typedef struct nbapi_resp_fab_info nbapi_resp_fab_info_t;

struct nbapi_resp_show_of_fab_route {
    nbapi_resp_message_t        header;
    uint8_t                     switch_len;
    uint8_t                     pad1[11];
    nbapi_resp_fab_info_t       fab[NB_SW_MAX];
};
typedef struct nbapi_resp_show_of_fab_route nbapi_resp_show_of_fab_route_t;

struct nbapi_resp_fsb_route_info {
    uint16_t                    tenant_id;
    uint32_t                    src_host_ip;     
    uint8_t                     src_host_mac[6];
    uint32_t                    dst_host_ip;     
    uint8_t                     dst_host_mac[6];
    uint8_t                     hop_len;    
    nbapi_resp_fab_info_t       fab[NB_SW_MAX];
};
typedef struct nbapi_resp_fsb_route_info nbapi_resp_fsb_route_info_t;


struct nbapi_resp_show_of_fab_route_all {
    nbapi_resp_message_t        header;
    uint8_t                     host_pair_len;
    uint8_t                     pad1[11];
    nbapi_resp_fsb_route_info_t pairs[NB_HOST_MAX];
};
typedef struct nbapi_resp_show_of_fab_route_all nbapi_resp_show_of_fab_route_all_t;

struct nbapi_resp_fsb_host_info {
    uint16_t                    tenant_id;
    uint32_t                    src_host_ip;     
    uint8_t                     src_host_mac[6];
    uint64_t                    swid;
    uint32_t                    alias;
    uint16_t                    port;
    uint8_t                     dfl_gw; // 1: default gw , 0 non gw
    uint8_t                     dead;   // 1: dead, 0 : alive   
};
typedef struct nbapi_resp_fsb_host_info nbapi_resp_fsb_host_info_t;


struct nbapi_resp_show_of_fab_host {
    nbapi_resp_message_t        header;
    uint8_t                     host_len;
    uint8_t                     pad1[11];
    nbapi_resp_fsb_host_info_t  hosts[NB_HOST_MAX];
};
typedef struct nbapi_resp_show_of_fab_host nbapi_resp_show_of_fab_host_t;


enum nbapi_msg_type_t {
    NB_SHOW_OF_SWITCH, 
    NB_SHOW_OF_SWITCH_DETAIL, 
    NB_SHOW_OF_SWITCH_FLOW,
    NB_CONFIG_OF_FLOW_ADD_EXM, 
    NB_CONFIG_OF_FLOW_DEL_EXM,
    NB_CONFIG_ACTION_OF_ADD_OUTPUT_ACTION,
    NB_CONFIG_ACTION_OF_ADD_SET_VID_ACTION,
    NB_CONFIG_ACTION_OF_ADD_SET_DMAC_ACTION,
    NB_CONFIG_ACTION_OF_COMMIT,
    NB_SHOW_OF_LLDP,
    NB_SHOW_OF_LLDP_NEIGH,
    NB_SHOW_OF_PATH_ROUTE,
    NB_SHOW_OF_FAB_ROUTE,
    NB_CONFIG_OF_FAB_HOST_NONGW,
    NB_CONFIG_OF_FAB_HOST_GW,
    NB_SHOW_OF_FAB_ROUTE_ALL,
    NB_CONFIG_OF_FAB_DEL_HOST,
    NB_SHOW_OF_FAB_HOST,
    NB_SHOW_OF_FAB_HOST_ALL_ACTIVE,  /* response structure same with SHOW_OF_FAB_HOST */
    NB_SHOW_OF_FAB_HOST_ALL_INACTIVE, /* response structure same with SHOW_OF_FAB_HOST */
    NB_CONFIG_OF_FAB_HOST_DEL,
    NB_CONFIG_OF_TR_MODE,
    NB_CONFIG_OF_FAB_MODE,
    NB_UNKNOWN
}; 
typedef enum nbapi_msg_type_t nbapi_msg_type;

#endif
