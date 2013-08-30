/*  mul_fabric_vty.c: Mul fabric vty implementation 
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
#include "mul_vty.h"

extern fab_struct_t *fab_ctx;

static void
fab_dump_per_route_elem(void *rt_arg, void *vty)
{
    rt_path_elem_t *rt_elem = rt_arg;

    vty_out(vty, "Node(%d):Link(%hu)->", rt_elem->sw_alias, rt_elem->link.la); 
}

DEFUN (show_fab_route,
       show_fab_route_cmd,
        "show fabric-route <0-1024> to <0-1024>",
        SHOW_STR
        "Route between OF nodes\n"
        "source switch node-id\n"
        "to\n"
        "destination switch node-id\n")
{
    int src_aliasid;
    int dst_aliasid;
    GSList *iroute = NULL;

    src_aliasid = atoi(argv[0]);
    dst_aliasid = atoi(argv[1]);

    iroute = fab_route_get(fab_ctx->route_service, src_aliasid, dst_aliasid,
                           NULL);
    if (!iroute) {
        vty_out(vty, "No route found%s", VTY_NEWLINE);
        return CMD_SUCCESS;         
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    mul_route_path_traverse(iroute, fab_dump_per_route_elem, vty);

    vty_out(vty, "%s", VTY_NEWLINE);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    mul_destroy_route(iroute);

    return CMD_SUCCESS;
}

static int 
__add_fab_host_cmd(struct vty *vty, const char **argv, bool is_gw)
{
    uint16_t tenant_id;
    uint16_t network_id;
    uint64_t dpid;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int  i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));

    tenant_id = atoi(argv[0]);
    network_id = atoi(argv[1]);
    dpid = strtoull(argv[4], NULL, 16);
    fl.in_port= htons(atoi(argv[5]));
    
    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    fl.nw_src = host_ip.prefix.s_addr;
    fab_add_tenant_id(&fl, NULL, tenant_id); 
    fab_add_network_id(&fl, network_id); 
    fl.FL_DFL_GW = is_gw;

    mac_str = (void *)argv[3];
    for (i = 0; i < 6; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    fab_host_add(fab_ctx, dpid, &fl, true);

    return CMD_SUCCESS;

}

DEFUN (add_fab_host_nongw,
       add_fab_host_nongw_cmd,
        "add fabric-host tenant <0-4096> network <0-65535> "
        "host-ip A.B.C.D host-mac X "
        "switch X port <0-65535> non-gw",
        "Add a configuration" 
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Enter alias-id\n"
        "ConnectepPort on switch\n"
        "Enter port-number\n"
        "This host is non gateway\n")
{
    return __add_fab_host_cmd(vty, argv, false);
}

DEFUN (add_fab_host_gw,
       add_fab_host_gw_cmd,
        "add fabric-host tenant <0-4096> network <0-65535> "
        "host-ip A.B.C.D host-mac X "
        "switch X port <0-65535> gw",
        "Add a configuration" 
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter Network-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n"
        "Switch directly connected to\n"
        "Enter dpid\n"
        "Enter alias-id\n"
        "ConnectepPort on switch\n"
        "Enter port-number\n"
        "This host is non gateway\n")
{
    return __add_fab_host_cmd(vty, argv, true);
}

static void
fab_host_route_show(void *route, void *u_arg)
{
    fab_route_t *froute = route;    
    struct vty *vty = u_arg;

    vty_out(vty, "Tenant(%hu) Net(%hu) (0x%x:%02x:%02x:%02x:%02x:%02x:%02x)=>" 
                 "(0x%x:%02x:%02x:%02x:%02x:%02x:%02x:)%s",
                 fab_tnid_to_tid(froute->src->hkey.tn_id), 
                 fab_tnid_to_nid(froute->src->hkey.tn_id), 
                 froute->src->hkey.host_ip, 
                 froute->src->hkey.host_mac[0], froute->src->hkey.host_mac[1],
                 froute->src->hkey.host_mac[2], froute->src->hkey.host_mac[3],
                 froute->src->hkey.host_mac[4], froute->src->hkey.host_mac[5],
                 froute->dst->hkey.host_ip,
                 froute->dst->hkey.host_mac[0], froute->dst->hkey.host_mac[1],
                 froute->dst->hkey.host_mac[2], froute->dst->hkey.host_mac[3],
                 froute->dst->hkey.host_mac[4], froute->dst->hkey.host_mac[5], 
                 VTY_NEWLINE);
    vty_out(vty, "\t");
    mul_route_path_traverse(froute->iroute, fab_dump_per_route_elem, vty);
    vty_out(vty, "%s", VTY_NEWLINE);
}

static void
__fab_show_host_route(void *host_arg, void *value UNUSED, void *vty_arg)
{
    struct vty *vty = vty_arg;

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    fab_loop_all_host_routes(host_arg, fab_host_route_show, vty);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);
}

DEFUN (show_fab_route_all,
       show_fab_route_all_cmd,
       "show fabric-route all",
       SHOW_STR
       "Dump all routes\n")
{

    fab_loop_all_hosts(fab_ctx, (GHFunc)__fab_show_host_route, vty);

    return CMD_SUCCESS;
}
 
DEFUN (del_fab_host,
       del_fab_host_cmd,
        "del fabric-host tenant <0-4096> network <0-65535> "
        "host-ip A.B.C.D host-mac X",
        "Del a configuration" 
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Host ip address\n"
        "Valid ip address\n"
        "Host mac address\n"
        "Valid mac address in X:X...X format \n")
{
    uint16_t tenant_id;
    uint16_t network_id;
    struct flow fl;
    struct prefix_ipv4 host_ip;
    char *mac_str = NULL, *next = NULL;
    int  i = 0, ret = 0;

    memset(&fl, 0, sizeof(fl));

    tenant_id = atoi(argv[0]);
    network_id = atoi(argv[1]);
    
    ret = str2prefix(argv[2], (void *)&host_ip);
    if (ret <= 0) {
        vty_out (vty, "%% Malformed address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    fl.nw_src = host_ip.prefix.s_addr;
    fab_add_tenant_id(&fl, NULL, tenant_id); 
    fab_add_network_id(&fl, network_id); 

    mac_str = (void *)argv[3];
    for (i = 0; i < 6; i++) {
        fl.dl_src[i] = (uint8_t)strtoul(mac_str, &next, 16);
        if(mac_str == next)
            break;
        mac_str = next + 1;
    }

    if (i != 6) {
        vty_out (vty, "%% Malformed mac address%s", VTY_NEWLINE);
        return CMD_WARNING;
    }

    fab_host_delete(fab_ctx, &fl, false, false, true);

    return CMD_SUCCESS;
}

static void
show_vty_fab_host_per_tenant(void *host, void *vty_arg)
{
    char *pbuf;
    struct vty *vty = vty_arg;

    pbuf = fab_dump_single_host(host);

    vty_out(vty, "%s", pbuf);    
    free(pbuf);
}

static void
show_vty_fab_host(void *host, void *v_arg UNUSED, void *vty_arg)
{
    char *pbuf;
    struct vty *vty = vty_arg;

    pbuf = fab_dump_single_host(host);

    vty_out(vty, "%s", pbuf);    
    free(pbuf);
}


DEFUN (show_fab_host,
       show_fab_host_cmd,
        "show fabric-hosts tenant <0-4096> network <0-65535>",
        SHOW_STR
        "Fabric connected host\n"
        "Tenant\n"
        "Enter Tenant-id\n"
        "Network\n"
        "Enter net-id\n")

{
    uint32_t tn_id;
    fab_tenant_net_t *tenant_nw = NULL;

    FAB_MK_TEN_NET_ID(tn_id, atoi(argv[0]), atoi(argv[1]));

    c_rd_lock(&fab_ctx->lock);
    if (!(tenant_nw = g_hash_table_lookup(fab_ctx->tenant_net_htbl,
                                          &tn_id))) {
        vty_out(vty, "Tenant (%x) not found\r\n", tn_id);
        c_rd_unlock(&fab_ctx->lock);
        return CMD_WARNING;
    }

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    __fab_tenant_nw_loop_all_hosts(tenant_nw, 
                                   show_vty_fab_host_per_tenant, vty);
    c_rd_unlock(&fab_ctx->lock);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_fab_host_all_active,
       show_fab_host_all_active_cmd,
        "show fabric-hosts all-active",
        SHOW_STR
        "Fabric connected host\n"
        "All active hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    fab_loop_all_hosts(fab_ctx, show_vty_fab_host, vty);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (show_fab_host_all_inactive,
       show_fab_host_all_inactive_cmd,
        "show fabric-hosts all-inactive",
        SHOW_STR
        "Fabric connected host\n"
        "All inactive hosts\n")
{
    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    fab_loop_all_inactive_hosts(fab_ctx, show_vty_fab_host, vty);

    vty_out (vty,
            "-------------------------------------------"
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    return CMD_SUCCESS;
}

DEFUN (fab_route_mp,
       fab_route_mp_cmd,
        "fabric-route-mp enable",
        "Fabric route multi-path attributes\n" 
        "Enable this feature\n")
{
    if (!fab_ctx->use_ecmp) {
        fab_ctx->use_ecmp = true;
        fab_reset_all_routes(fab_ctx);
    }

    return CMD_SUCCESS;
}

DEFUN (fab_route_mp_dis,
       fab_route_mp_dis_cmd,
        "fabric-route-mp disable",
        "Fabric route multi-path attributes\n" 
        "Disable this feature\n")
{
    if (fab_ctx->use_ecmp) {
        fab_ctx->use_ecmp = false;
        fab_reset_all_routes(fab_ctx);
    }

    return CMD_SUCCESS;
}
 
/* install available commands */
void
fabric_vty_init(void *arg UNUSED)
{
    /* commands work only after "enable" command in the beginning */
    c_log_debug("%s: installing fabric vty command", FN);
    install_element(ENABLE_NODE, &show_fab_route_cmd);
    install_element(ENABLE_NODE, &show_fab_route_all_cmd);
    install_element(ENABLE_NODE, &add_fab_host_gw_cmd);
    install_element(ENABLE_NODE, &add_fab_host_nongw_cmd);
    install_element(ENABLE_NODE, &del_fab_host_cmd);
    install_element(ENABLE_NODE, &show_fab_host_cmd);
    install_element(ENABLE_NODE, &show_fab_host_all_active_cmd);
    install_element(ENABLE_NODE, &show_fab_host_all_inactive_cmd);
    install_element(ENABLE_NODE, &fab_route_mp_cmd);
    install_element(ENABLE_NODE, &fab_route_mp_dis_cmd);
}
