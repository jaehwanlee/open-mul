/*
 *  mul_vty.c: MUL vty implementation 
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
#include "mul.h"
#include "mul_vty.h"

int c_vty_thread_run(void *arg);

char              *vty_addr = NULL;
int               vty_port  = C_VTY_PORT;
extern ctrl_hdl_t ctrl_hdl;

static const char *of_switch_states[] = {
    "connected",
    "negotiation",
    "registered",
    "dead",
     NULL,
};

static void
ofp_capabilities_tostr(char *string, uint32_t capabilities)
{
    if (capabilities == 0) {
        strcpy(string, "No capabilities\n");
        return;
    }
    if (capabilities & OFPC_FLOW_STATS) {
        strcat(string, "FLOW_STATS ");
    }
    if (capabilities & OFPC_TABLE_STATS) {
        strcat(string, "TABLE_STATS ");
    }
    if (capabilities & OFPC_PORT_STATS) {
        strcat(string, "PORT_STATS ");
    }
    if (capabilities & OFPC_STP) {
        strcat(string, "STP ");
    }
    if (capabilities & OFPC_IP_REASM) {
        strcat(string, "IP_REASM ");
    }
    if (capabilities & OFPC_QUEUE_STATS) {
        strcat(string, "QUEUE_STATS ");
    }
    if (capabilities & OFPC_ARP_MATCH_IP) {
        strcat(string, "ARP_MATCH_IP");
    }
}

static void UNUSED
ofp_port_features_tostr(char *string, uint32_t features)
{
    if (features == 0) {
        strcpy(string, "Unsupported\n");
        return;
    }
    if (features & OFPPF_10MB_HD) {
        strcat(string, "10MB-HD ");
    }
    if (features & OFPPF_10MB_FD) {
        strcat(string, "10MB-FD ");
    }
    if (features & OFPPF_100MB_HD) {
        strcat(string, "100MB-HD ");
    }
    if (features & OFPPF_100MB_FD) {
        strcat(string, "100MB-FD ");
    }
    if (features & OFPPF_1GB_HD) {
        strcat(string, "1GB-HD ");
    }
    if (features & OFPPF_1GB_FD) {
        strcat(string, "1GB-FD ");
    }
    if (features & OFPPF_10GB_FD) {
        strcat(string, "10GB-FD ");
    }
    if (features & OFPPF_COPPER) {
        strcat(string, "COPPER ");
    }
    if (features & OFPPF_FIBER) {
        strcat(string, "FIBER ");
    }
    if (features & OFPPF_AUTONEG) {
        strcat(string, "AUTO_NEG ");
    }
    if (features & OFPPF_PAUSE) {
        strcat(string, "AUTO_PAUSE ");
    }
    if (features & OFPPF_PAUSE_ASYM) {
        strcat(string, "AUTO_PAUSE_ASYM ");
    }
}

static void
ofp_port_config_tostr(char *string, uint32_t config)
{
    if (config & OFPPC_PORT_DOWN) {
        strcat(string, " PORT_DOWN");
    } else {
        strcat(string, " PORT_UP");
    }
}

static void
of_show_switch_info(void *k, void *v UNUSED, void *arg)
{
    c_switch_t  *sw = k;
    struct      vty *vty = arg;


    vty_out (vty, "0x%012llx    %-11s %-26s %-8d %s",
             sw->datapath_id,
             of_switch_states[sw->switch_state],
             sw->conn.conn_str,
             sw->n_ports,
             VTY_NEWLINE);
}


DEFUN (show_of_switch,
       show_of_switch_cmd,
       "show of-switch all",
       SHOW_STR
       "Openflow switches\n"
       "Summary information for all")
{

    vty_out (vty,
            "%sSwitch-DP-id    |   State     |  "
            "Peer                 | Ports%s",
            VTY_NEWLINE, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    of_switch_traverse_all(&ctrl_hdl, of_show_switch_info, vty);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    return CMD_SUCCESS;
}


DEFUN (show_of_switch_detail,
       show_of_switch_detail_cmd,
       "show of-switch X detail",
       SHOW_STR
       "Openflow switches\n"
       "Datapath-id in 0xXXX format\n"
       "Detailed information\n")
{
    uint64_t                     dp_id;
    c_switch_t                  *sw;
    const struct ofp_phy_port   *p_info;
    char                         string[OFP_PRINT_MAX_STRLEN];
    uint32_t                     i;

    dp_id = strtoull(argv[0], NULL, 16);

    sw = of_switch_get(&ctrl_hdl, dp_id);

    if (!sw) {
        return CMD_SUCCESS;
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);
    vty_out (vty, "Datapath-id : 0x%llx%s", (unsigned long long)dp_id, VTY_NEWLINE);
    vty_out (vty, "OFP-Version : 0x%d%s", sw->version, VTY_NEWLINE);
    vty_out (vty, "Buffers     : %d%s", sw->n_buffers, VTY_NEWLINE);
    vty_out (vty, "Tables      : %d%s", sw->n_tables, VTY_NEWLINE);
    vty_out (vty, "Actions     : 0x%x%s", sw->actions, VTY_NEWLINE);

    memset(string, 0, OFP_PRINT_MAX_STRLEN);
    ofp_capabilities_tostr(string, sw->capabilities);

    vty_out (vty, "Capabilities: 0x%x(%s)%s", sw->capabilities,
            string, VTY_NEWLINE);
    vty_out (vty, "Num Ports   : %d%s", sw->n_ports, VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
    vty_out (vty, "                              Port info%s",
            VTY_NEWLINE);
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    for (i = 0; i < OFSW_MAX_PORTS; i ++) {
        if (sw->ports[i].valid) {
            p_info = &sw->ports[i].p_info;

            memset(string, 0, OFP_PRINT_MAX_STRLEN);
            ofp_port_config_tostr(string, p_info->config);


            vty_out (vty, "%-6d %-10s %02x:%02x:%02x:%02x:%02x:%02x %-15s",
                    p_info->port_no, p_info->name,
                    p_info->hw_addr[0], p_info->hw_addr[1], p_info->hw_addr[2],
                    p_info->hw_addr[3], p_info->hw_addr[4], p_info->hw_addr[5],
                    string);

            memset(string, 0, OFP_PRINT_MAX_STRLEN);
            vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);

    of_switch_put(sw);

    return CMD_SUCCESS;

}

struct cmd_node flow_actions_node =
{
    FLOW_NODE,
    "(config-flow-action)# ",
    1,
    NULL,
    NULL 
};

struct vty_flow_action_parms
{
    void *sw;
    void *fl;
    uint8_t action_len;
    void *actions;
    uint32_t wildcards;
    bool drop_pkt;
};

static void
vty_of_print_flow(void *arg, c_fl_entry_t *ent)
{
    char *flow_print_str = NULL;
    char *actions_print_str = NULL;
    char *wc_print_str = NULL;
    char *flow_app_str = NULL;
    struct vty *vty = arg;

    flow_print_str = of_dump_flow(&ent->fl, ent->FL_WILDCARDS);
    vty_out(vty, "%s\r\n", flow_print_str);

    actions_print_str = of_dump_actions(ent->actions, ent->action_len);
    vty_out(vty, "%s\r\n", actions_print_str);

    vty_out(vty, "%s: %hu\r\n", "Prio", ent->FL_PRIO);
    vty_out(vty, "%s: %s %s %s\r\n", "Flags",
            ent->FL_FLAGS & C_FL_ENT_STATIC ? "static":"dynamic",
            ent->FL_FLAGS & C_FL_ENT_CLONE ? "clone": "no-clone",
            ent->FL_FLAGS & C_FL_ENT_LOCAL ? "local": "non-local");

    if (!(ent->FL_FLAGS & C_FL_ENT_CLONE) && (ent->FL_FLAGS & C_FL_ENT_GSTATS) 
        && !(ent->FL_FLAGS & C_FL_ENT_LOCAL)) {
        vty_out(vty, "%s: Bytes %llu Packets %llu\r\n", "Stats",
                (unsigned long long)ent->fl_stats.byte_count, 
                (unsigned long long)ent->fl_stats.pkt_count);

        vty_out(vty, "%s  Bps %f Pps %f\r\n", "     ", 
                (float)ent->fl_stats.bps,  (float)ent->fl_stats.pps);
    }

    flow_app_str = of_dump_fl_app(ent);
    vty_out(vty, "%s\r\n", flow_app_str);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s%s",
            VTY_NEWLINE, VTY_NEWLINE);


    if (flow_print_str) free(flow_print_str);
    if (actions_print_str) free(actions_print_str);
    if (wc_print_str) free(wc_print_str);
    if (flow_app_str) free(flow_app_str);
}


DEFUN (show_of_switch_flow,
       show_of_switch_flow_cmd,
        "show of-flow switch X",
        SHOW_STR
        "Openflow flow tuple\n"
        "For a particular switch\n"
        "datapath-id in 0xXXX format\n")
{
    uint64_t                    dp_id;
    c_switch_t                  *sw;

    dp_id = strtoull(argv[0], NULL, 16);

    sw = of_switch_get(&ctrl_hdl, dp_id);

    if (!sw) {
        return CMD_SUCCESS;
    }

    of_flow_traverse_tbl_all(sw, vty, vty_of_print_flow); 

    of_switch_put(sw);

    return CMD_SUCCESS;
}

DEFUN (of_add_output_action,
       of_add_output_action_cmd,
       "action-add output <0-65535>",
       "Add openflow action\n"
       "Output action\n"
       "Enter port-id\n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr; 

    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_output((char **)&act_wr_ptr, 
                                              OF_MAX_ACTION_LEN - args->action_len,
                                              atoi(argv[0]));

    return CMD_SUCCESS;
}

DEFUN (of_add_set_vid_action,
       of_add_set_vid_action_cmd,
       "action-add vlan-id <0-4094>",
       "Add openflow action\n"
       "set vlanid action\n"
       "Enter vlan-id\n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr; 

    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_set_vid((char **)&act_wr_ptr, 
                                               OF_MAX_ACTION_LEN - args->action_len,
                                               strtoull(argv[0], NULL, 10));

    return CMD_SUCCESS;
}

DEFUN (of_add_strip_vlan_action,
       of_add_strip_vlan_action_cmd,
       "action-add strip-vlan",
       "Add openflow action\n"
       "Strip vlan action\n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr;

    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_strip_vlan((char **)&act_wr_ptr,
                                               OF_MAX_ACTION_LEN - args->action_len);

    return CMD_SUCCESS;
}

DEFUN (of_add_set_vpcp_action,
       of_add_set_vpcp_action_cmd,
       "action-add vlan-pcp <0-7>",
       "Add openflow action\n"
       "set vlan-pcp action\n"
       "Enter vlan-pcp\n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr;

    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_set_vlan_pcp((char **)&act_wr_ptr,
                                               OF_MAX_ACTION_LEN - args->action_len,
                                               strtoull(argv[0], NULL, 10));

    return CMD_SUCCESS;
}


DEFUN (of_add_set_dmac_action,
       of_add_set_dmac_action_cmd,
       "action-add set-dmac X",
       "Add openflow action\n"
       "set dmac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr; 
    uint8_t                      dmac[6];
    char                         *mac_str, *next = NULL;
    int                          i = 0;


    mac_str = (void *)argv[0];
    for (i = 0; i < 6; i++) {
        dmac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_set_dmac((char **)&act_wr_ptr, 
                                                OF_MAX_ACTION_LEN - args->action_len,
                                                dmac);

    return CMD_SUCCESS;
}

DEFUN (of_add_set_smac_action,
       of_add_set_smac_action_cmd,
       "action-add set-smac X",
       "Add openflow action\n"
       "set smac action\n"
       "Enter MAC address (xx:xx:xx:xx:xx:xx) \n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr;
    uint8_t                      smac[6];
    char                         *mac_str, *next = NULL;
    int                          i = 0;


    mac_str = (void *)argv[0];
    for (i = 0; i < 6; i++) {
        smac[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }


    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_set_smac((char **)&act_wr_ptr,
                                                OF_MAX_ACTION_LEN - args->action_len,
                                                smac);

    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_saddr_action,
       of_add_set_nw_saddr_action_cmd,
       "action-add nw-saddr A.B.C.D",
       "Add openflow action\n"
       "set source ip address action\n"
       "Enter ip address\n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr;
    struct in_addr               ip_addr;

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_set_nw_saddr((char **)&act_wr_ptr,
                                               OF_MAX_ACTION_LEN - args->action_len,
                                               ntohl(ip_addr.s_addr));

    return CMD_SUCCESS;
}

DEFUN (of_add_set_nw_daddr_action,
       of_add_set_nw_daddr_action_cmd,
       "action-add nw-daddr A.B.C.D",
       "Add openflow action\n"
       "set destination ip address action\n"
       "Enter ip address\n")
{
    struct vty_flow_action_parms *args = vty->index;
    uint8_t                      *act_wr_ptr; 
    struct in_addr               ip_addr;

    if (inet_aton(argv[0], &ip_addr) <= 0) {
        vty_out(vty, "Malformed ip address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }
    act_wr_ptr = (uint8_t *)args->actions + args->action_len;
    args->action_len += of_make_action_set_nw_daddr((char **)&act_wr_ptr,
                                               OF_MAX_ACTION_LEN - args->action_len,
                                               ntohl(ip_addr.s_addr));

    return CMD_SUCCESS;
}

DEFUN (of_add_drop_action,
       of_add_drop_action_cmd,
       "action-add drop",
       "Add openflow action\n"
       "drop packet action\n")
{
    struct vty_flow_action_parms *args = vty->index;


    args->drop_pkt = true;

    return CMD_SUCCESS;
}



DEFUN (flow_actions,
       flow_actions_cmd,
       "flow ARGS",
       "Flow\n"
       "Flow tuples\n")
{
    vty->node = FLOW_NODE;

    return CMD_SUCCESS;
}


DEFUN (flow_actions_commit,
       flow_actions_commit_cmd,
       "commit",
       "commit the acl and its actions")
{
    struct vty_flow_action_parms *args = vty->index;
    struct of_flow_mod_params fl_parms;
    c_switch_t *sw; 
    void *app;

    if (args) {
        sw = args->sw;
        if ((args->action_len >= 4 || args->drop_pkt)&& args->sw) {

            app = c_app_get(&ctrl_hdl, C_VTY_NAME);
            if (app && sw->switch_state == SW_REGISTERED) {
                
                /* TODO action validation here */
                memset(&fl_parms, 0, sizeof(fl_parms));
                
                fl_parms.flow = args->fl;
                if (!args->drop_pkt) {
                    fl_parms.actions = args->actions;
                    fl_parms.action_len = args->action_len;
                    fl_parms.prio = C_FL_PRIO_DFL;
                } else {
                    if (args->actions) free(args->actions);
                    fl_parms.prio = C_FL_PRIO_DRP;
                    vty_out(vty, "Ignoring all non-drop actions if any%s",
                            VTY_NEWLINE);
                }
                fl_parms.wildcards = args->wildcards;
                fl_parms.buffer_id = (uint32_t)(-1);
                fl_parms.flags = C_FL_ENT_GSTATS | C_FL_ENT_STATIC;
                fl_parms.prio = C_FL_PRIO_DFL;
                fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;
                fl_parms.app_owner = app;
                of_flow_add(args->sw, &fl_parms);
            }
            if (app) c_app_put(app);
            else vty_out(vty, "Can't get vty app handle%s", VTY_NEWLINE);
        } else {
            vty_out(vty, "No actions added.Flow not added%s", VTY_NEWLINE);
        } 

        if (args->fl) {
            free(args->fl);
        }
        free(args);
        vty->index = NULL;
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}



DEFUN (flow_actions_exit,
       flow_actions_exit_cmd,
       "exit",
       "Exit from Flow action configuration mode")
{
    struct vty_flow_action_parms *args = vty->index;

    if (args) {
        free(args->fl);
        free(args);
    }

    vty->node = CONFIG_NODE;
    return CMD_SUCCESS;
}

DEFUN (of_flow_del_exm,
       of_flow_del_exm_cmd,
       "of-flow-exm del switch X dip A.B.C.D sip A.B.C.D proto <0-255> tos <0-63> "
       "dport <0-65535> sport <0-65535> smac X dmac X eth-type <0-65535> "
       "vid <0-4095> vlan-pcp <0-7> in-port <0-65535>",
       "Exact match flow (No wildcards)\n"  
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "dst-ip\n"
       "Enter valid ip address\n"
       "src-ip\n"
       "Enter valid ip address\n"
       "IP protocol\n"
       "Enter a valid proto\n"
       "IP TOS\n"
       "Enter TOS valie\n"
       "dst-port\n"
       "Enter valid dst port\n"
       "src-port\n"
       "Enter valid src port\n"
       "source mac\n"
       "Enter valid source mac\n"
       "dst mac\n"
       "Enter valid destination mac\n"
       "ethernet type\n"
       "Enter valid eth type\n"
       "vlan id\n"
       "Enter vlan id\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "input port\n"
       "Enter input port idx\n")
{
    int                          i;
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  *flow;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct of_flow_mod_params    fl_parms;
    void                         *app;

    memset(&fl_parms, 0, sizeof(fl_parms));

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    dp_id = strtoull(argv[0], NULL, 16);
    sw = of_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        free(flow);
        return CMD_WARNING;
    }

    ret = inet_aton(argv[1], (struct in_addr *)&flow->nw_dst);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    ret = inet_aton(argv[2], (struct in_addr *)&flow->nw_src);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    flow->nw_proto = atoi(argv[3]);
    flow->nw_tos = atoi(argv[4]);
    flow->tp_dst = htons(atoi(argv[5]));
    flow->tp_src = htons(atoi(argv[6]));

    mac_str = (void *)argv[7];
    for (i = 0; i < 6; i++) {
        flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    mac_str = (void *)argv[8];
    for (i = 0; i < 6; i++) {
        flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    flow->dl_type = htons(atoi(argv[9]));
    flow->dl_vlan = htons(atoi(argv[10])); // Check ? 
    flow->dl_vlan_pcp = htons(atoi(argv[11])); // Check ? 
    flow->in_port = htons(atoi(argv[12])); 
    
    fl_parms.flow = flow;
    fl_parms.prio = C_FL_PRIO_DFL;
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;

    if (!(app = c_app_get(&ctrl_hdl, C_VTY_NAME))) {
        goto deref_free_err_out;
    }

    fl_parms.app_owner = app;

    if (of_flow_del(sw, &fl_parms)) {
        vty_out(vty, "Flow delete failed\r\n");
    } else {
        vty_out(vty, "Flow deleted\r\n");
    }

    c_app_put(app);
    of_switch_put(sw);  

    free(flow);

    return CMD_SUCCESS;

deref_free_err_out:
    free(flow);
    of_switch_put(sw);  
    return CMD_WARNING;
}


DEFUN_NOSH (of_flow_vty_add,
       of_flow_vty_add_cmd,
       "of-flow add switch X dip A.B.C.D/M sip A.B.C.D/M proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "smac (X|*) dmac (X|*) eth-type (<0-65535>|*) vid (<0-4095>|*)"
       "vlan-pcp (<0-7>|*) in-port (<0-65535>|*)",
       "Openflow flow tuple\n"  
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "IP protocol\n"
       "Enter a valid ip-proto OR * for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value OR * for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port OR * for wildcard\n"
       "src-port\n"
       "Enter valid src port OR * for wildcard\n"
       "source mac\n"
       "Enter valid source mac OR * for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac OR * for wildcard\n"
       "ether type\n"
       "Enter valid ether type OR * for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id OR * for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority OR * for wildcard\n"
       "input port\n"
       "Enter input port index OR * for wildcard\n")
{
    int                          i;
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  *flow;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    uint32_t                     wildcards = 0;
    struct prefix_ipv4           dst_p, src_p;
    struct vty_flow_action_parms *args; 
    uint32_t                     nmask;

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    args = calloc(1, sizeof(*args));
    assert(args);

    args->actions = calloc(1, OF_MAX_ACTION_LEN); 
    args->action_len = 0;

    dp_id = strtoull(argv[0], NULL, 16);
    sw = of_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        free(flow);
        free(args);
        return CMD_WARNING;
    }

    ret = str2prefix(argv[1], (void *)&dst_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;
    }

    if (dst_p.prefixlen) {
        nmask   =  make_inet_mask(dst_p.prefixlen);
        wildcards |= ((32 - dst_p.prefixlen) & ((1 << OFPFW_NW_DST_BITS)-1)) 
                                << OFPFW_NW_DST_SHIFT;

    } else {
        wildcards |= OFPFW_NW_DST_ALL;
        nmask = ~0;
    }


    flow->nw_dst = dst_p.prefix.s_addr & htonl(nmask); 

    ret = str2prefix(argv[2], (void *)&src_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;
    }

    if (src_p.prefixlen) {
        nmask   =  (make_inet_mask(src_p.prefixlen));
        wildcards |= ((32 - src_p.prefixlen) & ((1 << OFPFW_NW_SRC_BITS)-1))
                                << OFPFW_NW_SRC_SHIFT;

    } else {
        wildcards |= OFPFW_NW_SRC_ALL;
        nmask = ~0;
    }

    flow->nw_src = src_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->nw_proto = 0;
        wildcards |= OFPFW_NW_PROTO;
    } else {
        flow->nw_proto = atoi(argv[3]);
    }


    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->nw_tos = 0;
        wildcards |= OFPFW_NW_TOS;
    } else {
        flow->nw_tos = atoi(argv[4]);
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->tp_dst = 0;
        wildcards |= OFPFW_TP_DST;
    } else {
        flow->tp_dst = htons(atoi(argv[5]));
    }

    if (!strncmp(argv[6], "*", strlen(argv[6]))) {
        flow->tp_src = 0; 
        wildcards |= OFPFW_TP_SRC;
    } else {
        flow->tp_src = htons(atoi(argv[6]));
    }

    if (!strncmp(argv[7], "*", strlen(argv[7]))) {
        memset(&flow->dl_src, 0, 6);
        wildcards |= OFPFW_DL_SRC;
    } else {
        mac_str = (void *)argv[7];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto deref_free_err_out;
        }
    }


    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        memset(&flow->dl_dst, 0, 6);
        wildcards |= OFPFW_DL_DST;
    } else {
        mac_str = (void *)argv[8];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto deref_free_err_out;  
        }
    }

    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        flow->dl_type = 0;
        wildcards |= OFPFW_DL_TYPE;
    } else {
        flow->dl_type = htons(atoi(argv[9]));
    }

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        flow->dl_vlan = 0;
        wildcards |= OFPFW_DL_VLAN;
    } else {
        flow->dl_vlan = htons(atoi(argv[10])); // Check ? 
    }

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->dl_vlan_pcp = 0;
        wildcards |= OFPFW_DL_VLAN_PCP;
    } else {
        flow->dl_vlan_pcp = htons(atoi(argv[11])); // Check ? 
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->in_port = 0;
        wildcards |= OFPFW_IN_PORT;
    } else {
        flow->in_port = htons(atoi(argv[12])); 
    }
    
#if 0
    char *fl_str = of_dump_flow(flow);
    printf ("%s\n", fl_str);
    printf ("0x%x\n", wildcards);
    free(fl_str);
#endif

    args->fl = flow;
    args->sw = sw;
    args->wildcards = htonl(wildcards);

    vty->index = args;

    if ((ret = flow_actions_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto deref_free_err_out;  
    }

    of_switch_put(sw);  

    return CMD_SUCCESS;

deref_free_err_out:
    free(args);
    free(flow);
    of_switch_put(sw);  
    return CMD_WARNING;
}


DEFUN (of_flow_vty_del,
       of_flow_vty_del_cmd,
       "of-flow del switch X dip A.B.C.D/M sip A.B.C.D/M proto (<0-255>|*) "
       "tos (<0-63>|*) dport (<0-65535>|*) sport (<0-65535>|*) "
       "smac (X|*) dmac (X|*) eth-type (<0-65535>|*) vid (<0-4095>|*)"
       "vlan-pcp (<0-7>|*) in-port (<0-65535>|*)",
       "Openflow flow tuple\n"  
       "Delete\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "dst-ip/mask\n"
       "Enter valid ip address and mask\n"
       "src-ip/mask\n"
       "Enter valid ip address and mask\n"
       "IP protocol\n"
       "Enter a valid ip-proto OR * for wildcard\n"
       "IP TOS\n"
       "Enter ip-tos value OR * for wildcard\n"
       "dst-port\n"
       "Enter valid dst-port OR * for wildcard\n"
       "src-port\n"
       "Enter valid src port OR * for wildcard\n"
       "source mac\n"
       "Enter valid source mac OR * for wildcard\n"
       "destination mac\n"
       "Enter valid destination mac OR * for wildcard\n"
       "ether type\n"
       "Enter valid ether type OR * for wildcard\n"
       "vlan-id\n"
       "Enter vlan-id OR * for wildcard\n"
       "vlan pcp\n"
       "Enter vlan priority OR * for wildcard\n"
       "input port\n"
       "Enter input port index OR * for wildcard\n")
{
    int                          i;
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  *flow;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    uint32_t                     wildcards = 0;
    struct prefix_ipv4           dst_p, src_p;
    uint32_t                     nmask;
    struct of_flow_mod_params    fl_parms;
    void                         *app;

    memset(&fl_parms, 0, sizeof(fl_parms));

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    dp_id = strtoull(argv[0], NULL, 16);
    sw = of_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        free(flow);
        return CMD_WARNING;
    }

    ret = str2prefix(argv[1], (void *)&dst_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;
    }

    if (dst_p.prefixlen) {
        nmask   =  make_inet_mask(dst_p.prefixlen);
        wildcards |= ((32 - dst_p.prefixlen) & ((1 << OFPFW_NW_DST_BITS)-1))
                                << OFPFW_NW_DST_SHIFT;
    } else {
        wildcards |= OFPFW_NW_DST_ALL;
        nmask = ~0;
    }


    flow->nw_dst = dst_p.prefix.s_addr & htonl(nmask); 

    ret = str2prefix(argv[2], (void *)&src_p);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;
    }

    if (src_p.prefixlen) {
        nmask   =  (make_inet_mask(src_p.prefixlen));
        wildcards |= ((32 - src_p.prefixlen) & ((1 << OFPFW_NW_SRC_BITS)-1))
                                << OFPFW_NW_SRC_SHIFT;
    } else {
        wildcards |= OFPFW_NW_SRC_ALL;
        nmask = ~0;
    }

    flow->nw_src = src_p.prefix.s_addr & htonl(nmask);

    if (!strncmp(argv[3], "*", strlen(argv[3]))) {
        flow->nw_proto = 0;
        wildcards |= OFPFW_NW_PROTO;
    } else {
        flow->nw_proto = atoi(argv[3]);
    }


    if (!strncmp(argv[4], "*", strlen(argv[4]))) {
        flow->nw_tos = 0;
        wildcards |= OFPFW_NW_TOS;
    } else {
        flow->nw_tos = atoi(argv[4]);
    }

    if (!strncmp(argv[5], "*", strlen(argv[5]))) {
        flow->tp_dst = 0;
        wildcards |= OFPFW_TP_DST;
    } else {
        flow->tp_dst = htons(atoi(argv[5]));
    }

    if (!strncmp(argv[6], "*", strlen(argv[6]))) {
        flow->tp_src = 0; 
        wildcards |= OFPFW_TP_SRC;
    } else {
        flow->tp_src = htons(atoi(argv[6]));
    }

    if (!strncmp(argv[7], "*", strlen(argv[7]))) {
        memset(&flow->dl_src, 0, 6);
        wildcards |= OFPFW_DL_SRC;
    } else {
        mac_str = (void *)argv[7];
        for (i = 0; i < 6; i++) {
            flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto deref_free_err_out;
        }
    }


    if (!strncmp(argv[8], "*", strlen(argv[8]))) {
        memset(&flow->dl_dst, 0, 6);
        wildcards |= OFPFW_DL_DST;
    } else {
        mac_str = (void *)argv[8];
        for (i = 0; i < 6; i++) {
            flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
            if(mac_str == next)
                break;
            mac_str = next + 1;
        }

        if (i != 6) {
            vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
            goto deref_free_err_out;
        }
    }

    if (!strncmp(argv[9], "*", strlen(argv[9]))) {
        flow->dl_type = 0;
        wildcards |= OFPFW_DL_TYPE;
    } else {
        flow->dl_type = htons(atoi(argv[9]));
    }

    if (!strncmp(argv[10], "*", strlen(argv[10]))) {
        flow->dl_vlan = 0;
        wildcards |= OFPFW_DL_VLAN;
    } else {
        flow->dl_vlan = htons(atoi(argv[10])); // Check ? 
    }

    if (!strncmp(argv[11], "*", strlen(argv[11]))) {
        flow->dl_vlan_pcp = 0;
        wildcards |= OFPFW_DL_VLAN_PCP;
    } else {
        flow->dl_vlan_pcp = htons(atoi(argv[11])); // Check ? 
    }

    if (!strncmp(argv[12], "*", strlen(argv[12]))) {
        flow->in_port = 0;
        wildcards |= OFPFW_IN_PORT;
    } else {
        flow->in_port = htons(atoi(argv[12])); 
    }
    
#if 0
    char *fl_str = of_dump_flow(flow);
    printf ("%s\n", fl_str);
    printf ("0x%x\n", wildcards);
    free(fl_str);
#endif
    fl_parms.flow = flow;
    fl_parms.wildcards = htonl(wildcards);
    fl_parms.prio = C_FL_PRIO_DFL;
    fl_parms.tbl_idx = C_RULE_FLOW_TBL_DFL;

    if (!(app = c_app_get(&ctrl_hdl, C_VTY_NAME))) {
        goto deref_free_err_out;  
    }

    fl_parms.app_owner = app;

    if (of_flow_del(sw, &fl_parms)) {
        vty_out(vty, "Flow delete failed\r\n");
    } else {
        vty_out(vty, "Flow deleted\r\n");
    }

    c_app_put(app);
    of_switch_put(sw);  

    free(flow);

    return CMD_SUCCESS;

deref_free_err_out:
    free(flow);
    of_switch_put(sw);  
    return CMD_WARNING;
}


DEFUN_NOSH (of_flow_add_exm,
       of_flow_add_exm_cmd,
       "of-flow-exm add switch X dip A.B.C.D sip A.B.C.D proto <0-255> tos <0-63> "
       "dport <0-65535> sport <0-65535> smac X dmac X eth-type <0-65535> "
       "vid <0-4095> vlan-pcp <0-7> in-port <0-65535>",
       "Exact match flow (No wildcards)\n"  
       "Add\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n"
       "dst-ip\n"
       "Enter valid ip address\n"
       "src-ip\n"
       "Enter valid ip address\n"
       "IP protocol\n"
       "Enter a valid proto\n"
       "IP TOS\n"
       "Enter TOS valie\n"
       "dst-port\n"
       "Enter valid dst port\n"
       "src-port\n"
       "Enter valid src port\n"
       "source mac\n"
       "Enter valid source mac\n"
       "dst mac\n"
       "Enter valid destination mac\n"
       "ethernet type\n"
       "Enter valid eth type\n"
       "vlan id\n"
       "Enter vlan id\n"
       "vlan pcp\n"
       "Enter vlan priority\n"
       "input port\n"
       "Enter input port idx\n")
{
    int                          i;
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  *flow;
    int                          ret;
    char                         *mac_str = NULL, *next = NULL;
    struct vty_flow_action_parms *args; 

    flow = calloc(1, sizeof(*flow));
    assert(flow);

    args = calloc(1, sizeof(*args));
    assert(args);

    args->actions = calloc(1, OF_MAX_ACTION_LEN); 
    args->action_len = 0;

    dp_id = strtoull(argv[0], NULL, 16);
    sw = of_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        free(flow);
        free(args);
        return CMD_WARNING;
    }

    ret = inet_aton(argv[1], (struct in_addr *)&flow->nw_dst);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    ret = inet_aton(argv[2], (struct in_addr *)&flow->nw_src);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    flow->nw_proto = atoi(argv[3]);
    flow->nw_tos = atoi(argv[4]);
    flow->tp_dst = htons(atoi(argv[5]));
    flow->tp_src = htons(atoi(argv[6]));

    mac_str = (void *)argv[7];
    for (i = 0; i < 6; i++) {
        flow->dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    mac_str = (void *)argv[8];
    for (i = 0; i < 6; i++) {
        flow->dl_dst[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        goto deref_free_err_out;  
    }

    flow->dl_type = htons(atoi(argv[9]));
    flow->dl_vlan = htons(atoi(argv[10])); // Check ? 
    flow->dl_vlan_pcp = htons(atoi(argv[11])); // Check ? 
    flow->in_port = htons(atoi(argv[12])); 
    
    args->fl = flow;
    args->sw = sw;

    vty->index = args;

    if ((ret = flow_actions_cmd.func(self, vty, argc, argv)) != CMD_SUCCESS) {
        goto deref_free_err_out;  
    }

    of_switch_put(sw);  

    return CMD_SUCCESS;

deref_free_err_out:
    free(flow);
    free(args);
    of_switch_put(sw);  
    return CMD_WARNING;
}

DEFUN (of_flow_reset,
       of_flow_reset_cmd,
       "of-flow reset-all switch X",
       "Openflow flow\n"  
       "reset-all flows\n"
       "openflow-switch\n"
       "datapath-id in 0xXXX format\n")
{
    uint64_t                     dp_id;
    c_switch_t                   *sw;
    struct flow                  flow;
    struct of_flow_mod_params    fl_parms;

    memset(&fl_parms, 0, sizeof(fl_parms));
    memset(&flow, 0, sizeof(flow));

    dp_id = strtoull(argv[0], NULL, 16);
    sw = of_switch_get(&ctrl_hdl, dp_id);
    if (!sw) {
        return CMD_WARNING;
    }

    __of_send_flow_del_nocache(sw, &flow, htonl(OFPFW_ALL),
                               OFPP_NONE, false); 

    of_switch_flow_tbl_reset(sw);
    of_switch_put(sw);

    vty_out(vty, "All Flows reset\r\n");

    return CMD_SUCCESS;
}

static void
modvty__initcalls(void *arg)
{
    initcall_t *mod_init;

    mod_init = &__start_modvtyinit_sec;
    do {
        (*mod_init)(arg);
        mod_init++;
    } while (mod_init < &__stop_modvtyinit_sec);
}

static void
mul_vty_init(void)
{
    install_node(&flow_actions_node, NULL);
    install_element(ENABLE_NODE, &show_of_switch_cmd);
    install_element(ENABLE_NODE, &show_of_switch_detail_cmd);
    install_element(CONFIG_NODE, &of_flow_add_exm_cmd);
    install_element(CONFIG_NODE, &of_flow_del_exm_cmd);
    install_element(CONFIG_NODE, &of_flow_vty_add_cmd);
    install_element(CONFIG_NODE, &of_flow_vty_del_cmd);
    install_element(CONFIG_NODE, &of_flow_reset_cmd);
    install_element(ENABLE_NODE, &show_of_switch_flow_cmd);
    install_default(FLOW_NODE);
    install_element(FLOW_NODE, &of_add_output_action_cmd);
    install_element(FLOW_NODE, &of_add_set_vid_action_cmd);
    install_element(FLOW_NODE, &of_add_set_dmac_action_cmd);
    install_element(FLOW_NODE, &flow_actions_exit_cmd);
    install_element(FLOW_NODE, &flow_actions_commit_cmd);
    install_element(FLOW_NODE, &of_add_set_nw_saddr_action_cmd);
    install_element(FLOW_NODE, &of_add_set_nw_daddr_action_cmd);
    install_element(FLOW_NODE, &of_add_set_smac_action_cmd);
    install_element(FLOW_NODE, &of_add_strip_vlan_action_cmd);
    install_element(FLOW_NODE, &of_add_set_vpcp_action_cmd);
    install_element(FLOW_NODE, &of_add_drop_action_cmd);

    modvty__initcalls(NULL);
}

int
c_vty_thread_run(void *arg)
{
    uint64_t            dpid = 0;
    struct thread       thread;
    struct c_vty_ctx    *vty_ctx = arg;
    ctrl_hdl_t          *c_hdl = vty_ctx->cmn_ctx.c_hdl; 

    c_set_thread_dfl_affinity();

    signal(SIGPIPE, SIG_IGN);

    /* Register vty as an app for static flow install */
    mul_register_app(NULL, C_VTY_NAME, 0, 0, 1, &dpid, NULL);

    c_hdl->vty_master = thread_master_create();

    cmd_init(1);
    vty_init(c_hdl->vty_master);
    mul_vty_init();
    sort_node();

    vty_serv_sock(vty_addr, vty_port, C_VTYSH_PATH, 1);

    c_log_debug(" VTY THREAD RUNNING \n");

     /* Execute each thread. */
    while (thread_fetch(c_hdl->vty_master, &thread))
        thread_call(&thread);

    /* Not reached. */
    return (0);
}
