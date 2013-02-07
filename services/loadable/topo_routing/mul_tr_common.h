/*
 *  mul_tr_common.h : MUL topology/routing common headers 
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

#ifndef __MUL_TR_COMMON_H__
#define __MUL_TR_COMMON_H__

struct rt_info_
{
    bool    rt_trigger;
    bool    rt_init_trigger;
#define RT_INIT_TRIGGER_TS (4)
#define RT_PERIODIC_TRIGGER_TS (10*60)
    time_t  rt_next_trigger_ts;
    void    *rt_priv;
    int     (*rt_init_state)(void *tr);
    void    (*rt_add_neigh_conn)(void *tr_struct, int sw_a, int sw_b, 
                                 struct lweight_pair_ *new_adj);
    GSList  *(*rt_get_sp)(void *tr_struct, int alias_src_swid, 
                          int alias_dst_swid);
    int     (*rt_calc)(void *tr_struct);
    int     (*rt_clean_state)(void *tr_struct);
    char    *(*rt_dump_adj_matrix)(void *tr_struct);
};

/* Main global entry struct */
struct tr_struct_ {
    void         *app_ctx;        /* opaque handle to controller */
    void         *topo_hdl;       /* lldp control handle */
    void         *tr_service;     /* Topo routing service */

    struct rt_info_ rt;           /* Routing Info */          
};

struct tr_neigh_query_arg {
    struct tr_struct_ *tr;
    int src_sw;
    int dst_sw;
};

typedef struct tr_struct_ tr_struct_t;
typedef struct tr_neigh_query_arg tr_neigh_query_arg_t; 
typedef struct rt_info_ rt_info_t;

#define TR_ROUTE_PBUF_SZ (4096)

void __tr_invoke_routing(tr_struct_t *tr);
void tr_invoke_routing(tr_struct_t *tr);
int __tr_get_num_switches(tr_struct_t *tr);
int __tr_get_max_switch_alias(tr_struct_t *tr);
void __tr_init_neigh_pair_adjacencies(tr_neigh_query_arg_t *arg);

GSList *tr_get_route(tr_struct_t *tr, int src_node, int dst_node);
void tr_destroy_route(GSList *route);
char *tr_dump_route(GSList *route_path);
char *tr_show_route_adj_matrix(tr_struct_t *tr);

void tr_module_init(void *ctx);
void tr_vty_init(void *arg);


#endif /* __MUL_TR_COMMON_H__ */
