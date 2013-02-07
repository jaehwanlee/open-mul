/*
 *  mul_route_apsp_priv.h: MUL routing all pairs shortest path headers 
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

#ifndef __MUL_ROUTE_APSP_PRIV_H__
#define __MUL_ROUTE_APSP_PRIV_H__

#define RT_APSP_INFO(tr)  (((rt_prot_hdl_t *)(tr->rt.rt_priv))->rt_prot_info)

int mul_route_apsp_calc(void *hdl);
GSList *mul_route_apsp_get_path(void *hdl, int src_sw, int dest_sw);
int mul_route_apsp_clean_state(void *hdl);
int mul_route_apsp_init_state(void *hdl);
void mul_route_apsp_add_neigh_conn(void *hdl, int sw_a, int sw_b, 
                                   lweight_pair_t *new_adj);
GSList *mul_route_apsp_get_sp(void *rt_service, int src_sw, int dest_sw);

#endif
