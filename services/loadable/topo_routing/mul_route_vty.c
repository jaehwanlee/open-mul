/*  mul_route_vty.c: Mul route vty implementation 
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
#include "mul_tr.h"
#include "mul_vty.h"

extern tr_struct_t  *tr_hdl;


extern void mul_route_apsp_dump_adj_matrix(tr_struct_t *tr);

DEFUN (show_route_matrix,
       show_route_matrix_cmd,
        "show path-matrix",
        SHOW_STR
        "Route between OF nodes\n"
        "dump the adj matrix\n")
{
    char *pbuf = NULL;

    pbuf = tr_show_route_adj_matrix(tr_hdl);

    if (pbuf) {
        vty_out(vty, "%s", pbuf);
        free(pbuf);
    }
    
    return CMD_SUCCESS;
}
 
DEFUN (show_of_route,
       show_of_route_cmd,
        "show path-route <0-1024> to <0-1024>",
        SHOW_STR
        "Route between OF nodes\n"
        "source switch node-id\n"
        "to\n"
        "destination switch node-id\n")
{
    int src_aliasid;
    int dst_aliasid;
    GSList *iroute = NULL;
    char *pbuf = NULL;

    src_aliasid = atoi(argv[0]);
    dst_aliasid = atoi(argv[1]);

    iroute = tr_get_route(tr_hdl, src_aliasid, dst_aliasid);
    if (!iroute) {
        vty_out(vty, "No route found%s", VTY_NEWLINE);
        return CMD_SUCCESS;         
    }

    pbuf = tr_dump_route(iroute);

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    if (pbuf)  {
        vty_out(vty, "%s", pbuf);
        free(pbuf);
    }

    vty_out (vty,
            "-------------------------------------------"
            "----------------------------------%s",
            VTY_NEWLINE);

    tr_destroy_route(iroute);


    return CMD_SUCCESS;
}

/* install two available commands */
void
route_vty_init(void *arg UNUSED)
{
    /* commands work only after "enable" command in the beginning */
    c_log_debug("%s: installing route vty command", FN);
    install_element(ENABLE_NODE, &show_of_route_cmd);
    install_element(ENABLE_NODE, &show_route_matrix_cmd);
}


