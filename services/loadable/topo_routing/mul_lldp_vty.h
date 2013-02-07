/*  mul_lldp_vty.h: Mul lldp vty definitions 
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

#ifndef __LLDP_VTY_H__
#define __LLDP_VTY_H__

void
lldp_vty_init(void *arg UNUSED);

/* helper : converts numeric port status into String */
static inline const char *
lldp_get_port_status_string(uint8_t lldp_port_status)
{
	switch(lldp_port_status){
	case LLDP_PORT_STATUS_INIT: return "LINK INIT";
	case LLDP_PORT_STATUS_NEIGHBOR: return "SWITCH";
	case LLDP_PORT_STATUS_EXTERNAL: return "EXT. LINK";
	}

	return "INVALID";
}

#endif
