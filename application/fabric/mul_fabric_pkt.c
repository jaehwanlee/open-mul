/*
 *  mul_fabric_arp.c: Fabric proxy arping
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
#include "mul_fabric_common.h"

extern fab_struct_t *fab_ctx;

uint8_t fab_mac[ETH_ADDR_LEN] = { 0x0a, 0x0b, 0x0c, 0x0d, 0xe, 0xff }; 

void
fab_add_arp_tap_per_switch(void *opq UNUSED, uint64_t dpid UNUSED)
{
}

void
fab_arp_rcv(void *opq UNUSED, fab_struct_t *fab_ctx UNUSED, c_ofp_packet_in_t *pin UNUSED)
{
}
