/*  mul_lldp_debug.h: Mul lldp debug defines 
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
#ifndef LLDP_DEBUG_H_
#define LLDP_DEBUG_H_

#define LLDP_HWADDR_DEBUG_STRING_LEN 19

void conv_hwaddr(uint8_t *hwaddr, void *string_buffer);
void dump_switch(lldp_switch_t *this_switch);
void dump_port(void *key UNUSED, void *value, void *user_data);


#endif /* LLDP_DEBUG_H_ */
