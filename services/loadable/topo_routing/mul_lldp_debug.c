/*  mul_lldp_debug.c: Mul lldp debug functions 
 *  Copyright (C) 2012, Dipyoti Saikia <dipjyoti.saikia@gmail.com> 
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

#include "mul_tr.h"

/* converts MAC address into readable format */
void conv_hwaddr(uint8_t *hwaddr, void *string_buffer)
{
	sprintf(string_buffer,"%02X-%02X-%02X-%02X-%02X-%02X",hwaddr[0],hwaddr[1],hwaddr[2],hwaddr[3],hwaddr[4],hwaddr[5]);
}

/* display information of switch */
void dump_switch(lldp_switch_t *this_switch)
{
	c_log_debug("switch 0x%llx: ", (unsigned long long)this_switch->dpid);
	g_hash_table_foreach(this_switch->ports,dump_port,&this_switch->dpid);
}
/* display information of port */
void dump_port(void *key UNUSED, void *value, void *user_data)
{
	char hwaddr_str[LLDP_HWADDR_DEBUG_STRING_LEN];
	lldp_port_t *this_port = (lldp_port_t *) value;
	uint64_t dpid = *(uint64_t *)user_data;

	conv_hwaddr(this_port->hw_addr,hwaddr_str);

	c_log_debug("switch 0x%llx port %hu: hwaddr=%s config=%d state=%d port_status=%d", (unsigned long long)dpid, this_port->port_no, hwaddr_str, this_port->config, this_port->state, this_port->status);
}
