/*
 *  mul_packet.h : MUL common packet types 
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

#ifndef __MUL_PACKET_H__
#define __MUL_PACKET_H__

static inline bool is_zero_ether_addr(const uint8_t *addr)
{
    return !(addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]);
}

static inline bool is_multicast_ether_addr(const uint8_t *addr)
{
    return 0x01 & addr[0];
}

static inline bool is_local_ether_addr(const uint8_t *addr)
{
    return 0x02 & addr[0];
}

static inline bool is_broadcast_ether_addr(const uint8_t *addr)
{
    return (addr[0] & addr[1] & addr[2] & addr[3] & addr[4] & addr[5]) == 0xff;
}

static inline bool is_unicast_ether_addr(const uint8_t *addr)
{
    return !is_multicast_ether_addr(addr);
}

#endif
