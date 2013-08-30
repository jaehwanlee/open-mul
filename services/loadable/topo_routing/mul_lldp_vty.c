/*  mul_lldp_vty.c: Mul lldp vty implementation 
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
#include "mul_tr.h"
#include "mul_vty.h"

extern topo_hdl_t *topo_hdl;

static void
show_lldp_switch_summary(void *key UNUSED, void *sw_arg, void *uarg)
{
	lldp_switch_t *lldpsw = (lldp_switch_t *)sw_arg;
	struct vty    *vty    = (struct vty *)uarg;

	/* temp vars */
	uint64_t   dpid;
	uint32_t port_count;
	uint32_t neighbor_count;
	//uint32_t external_count;

	c_rd_lock(&lldpsw->lock);
	dpid = lldpsw->dpid;
	port_count = g_hash_table_size(lldpsw->ports);
	neighbor_count = g_hash_table_size(lldpsw->ports);
	c_rd_unlock(&lldpsw->lock);

	/* dpid, # ports, # neighbors */
	vty_out (vty,"0x%10llx | %12d | %10u | %u%s", (unsigned long long)dpid, 
             lldpsw->alias_id, port_count, neighbor_count, VTY_NEWLINE);
}

/* show lldp switch all commmand. Shows summary information for all registered switches */
DEFUN (show_lldp_switch_all,
		show_lldp_switch_all_cmd,
		"show lldp switch all",
		SHOW_STR
		"LLDP\n"
		"Summary information for all switches\n"
)
{
	vty_out (vty,
			"-------------------------------------------"
			"----------------------------------%s",
			VTY_NEWLINE);
	vty_out (vty,"%12s | %12s | %10s | %s%s","switch-id", "alias-id", "# ports","# neighbors",VTY_NEWLINE);
	vty_out (vty,
			"-------------------------------------------"
			"-----------------------------------------%s",
			VTY_NEWLINE);

	lldp_switch_traverse_all(topo_hdl, show_lldp_switch_summary, vty);

	vty_out (vty,
			"-------------------------------------------"
			"----------------------------------%s%s",
			VTY_NEWLINE,VTY_NEWLINE);

	return CMD_SUCCESS;
}

static void
show_lldp_port_info(void *key UNUSED, void *sw_arg, void *uarg)
{
	lldp_port_t *port = (lldp_port_t *)sw_arg;
	struct vty  *vty  = (struct vty *)uarg;

	/* temp vars */
	uint16_t port_no;
	uint8_t lldp_port_status;
	uint64_t other_dpid;
	uint16_t other_portid;

	const char *status_str;

	port_no = port->port_no;
	lldp_port_status = port->status;
	status_str = lldp_get_port_status_string(lldp_port_status);
	if (lldp_port_status == LLDP_PORT_STATUS_NEIGHBOR){
		/* Connected to other switch */
		other_dpid = port->neighbor_dpid;
		other_portid = port->neighbor_port;
		/* port #, Status, Neighbor Switch ID, Neighbor Switch Port */
		vty_out (vty,"%12u | %10s | 0x%10llx | %u%s",port_no,status_str,(unsigned long long)other_dpid,other_portid,VTY_NEWLINE);
	}
	else {
		/* port #, Status */
		vty_out (vty,"%12u | %10s | 0x%10s | %s%s",port_no,status_str,"","",VTY_NEWLINE);
	}
}

/* Detailed information for one switch.
 * Lists all the port, their status, and neighbors (if any)
 */
DEFUN (show_lldp_switch_detail,
		show_lldp_switch_detail_cmd,
		"show lldp switch X detail",
		SHOW_STR
		"LLDP Switch Detail\n"
		"Detailed information for the switch"
)
{
	uint64_t switchId;
	lldp_switch_t *lldpsw;

	switchId = strtoull(argv[0], NULL, 16);

	lldpsw = fetch_and_retain_switch(switchId);
	if (!lldpsw){
		vty_out(vty,"switch(0x%llx) does not exist",(unsigned long long)switchId);
		return CMD_WARNING;
	}

	vty_out (vty,
			"-------------------------------------------"
			"----------------------------------%s",
			VTY_NEWLINE);
	vty_out (vty,"%12s | %10s | %10s | %s%s","port #","status","neighbor #","neighbor port #",VTY_NEWLINE);
	vty_out (vty,
			"-------------------------------------------"
			"----------------------------------%s",
			VTY_NEWLINE);

	lldp_port_traverse_all(lldpsw,show_lldp_port_info,vty);
	vty_out (vty,
			"-------------------------------------------"
			"----------------------------------%s%s",
			VTY_NEWLINE, VTY_NEWLINE);

	lldp_switch_unref(lldpsw);
	return CMD_SUCCESS;
}

/* install two available commands */
void
lldp_vty_init(void *arg UNUSED)
{
	/* commands work only after "enable" command in the beginning */
	c_log_debug("%s: installing vty command", FN);
	install_element(ENABLE_NODE, &show_lldp_switch_all_cmd);
	install_element(ENABLE_NODE, &show_lldp_switch_detail_cmd);
}


