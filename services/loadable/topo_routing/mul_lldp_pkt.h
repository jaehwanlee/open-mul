/*  mul_lldp_pkt.h: Mul lldp packet definitions 
 *  Copyright (C) 2012, Dipjyoti Saikia<dipjyoti.saikia@gmail.com> 
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
#ifndef __LLDP_H__
#define __LLDP_H__

/* time before next update event */
#define LLDP_UPDATE_INTVL_SEC 2 
#define LLDP_UPDATE_INTVL_USEC 0
#define LLDP_UPDATE_INTVL_INIT_SEC (LLDP_UPDATE_INTVL_SEC)

/* time before next pkt_timer event */
#define LLDP_PKT_TIMER_INTVL_SEC 10
#define LLDP_PKT_TIMER_INTVL_USEC 0

/* default TTL = 20s */
#define LLDP_DEFAULT_TTL 20 
#define LLDP_PROBE_PORT_INTERVAL (2) 

/* 802.1AB-2005 LLDP support code */
enum lldp_tlv_type{
    /* start of mandatory TLV */
    LLDP_END_OF_LLDPDU_TLV = 0,
    LLDP_CHASSIS_ID_TLV = 1,
    LLDP_PORT_ID_TLV = 2,
    LLDP_TTL_TLV = 3,
    /* end of mandatory TLV */
    /* start of optional TLV */ /*NOT USED */
    LLDP_PORT_DESC_TLV = 4,
    LLDP_SYSTEM_NAME_TLV = 5,
    LLDP_SYSTEM_DESC_TLV = 6,
    LLDP_SYSTEM_CAPABILITY_TLV = 7,
    LLDP_MGMT_ADDR_TLV = 8
    /* end of optional TLV */
};

enum lldp_chassis_id_subtype {
    LLDP_CHASSIS_ID_LOCALLY_ASSIGNED = 7
};

enum lldp_port_id_subtype {
    LLDP_PORT_ID_LOCALLY_ASSIGNED = 7
};

struct ethernet2_header
{
	uint8_t dest_addr[OFP_ETH_ALEN];
	uint8_t src_addr[OFP_ETH_ALEN];
	uint16_t ethertype;
};

/* hard coded lldp packet layout */
struct lldp_pkt_ {
	struct ethernet2_header eth_head;
	unsigned chassis_tlv_type : 7;
	unsigned chassis_tlv_length : 9;
	uint8_t chassis_tlv_subtype;
	uint64_t chassis_tlv_id;
	unsigned port_tlv_type : 7;
	unsigned port_tlv_length : 9;
	uint8_t port_tlv_subtype;
	uint16_t port_tlv_id;
	unsigned ttl_tlv_type : 7;
	unsigned ttl_tlv_length : 9;
	uint16_t ttl_tlv_ttl;
	unsigned end_of_lldpdu_tlv_type : 7;
	unsigned end_of_lldpdu_tlv_length : 9;
} __attribute__ ((packed));

typedef struct lldp_pkt_ lldp_pkt_t;

#endif
