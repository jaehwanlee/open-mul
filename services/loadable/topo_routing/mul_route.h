/*  mul_route.h: MUL routing service header defintions 
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

#ifndef __MUL_ROUTE_H__
#define __MUL_ROUTE_H__

#define RT_HB_INTVL_SEC 2
#define RT_HB_INTVL_INITSEC 6 
#define RT_HB_INTVL_USEC 0

#define RT_MAX_GET_RETRIES 100

#define NEIGH_NO_PATH (INT_MAX)
#define NEIGH_NO_LINK (uint16_t)(-1)

struct lweight_pair_
{
    uint16_t la;
    uint16_t lb;
#define NEIGH_DFL_WEIGHT (100)
    int weight;
    bool onlink;
};  
typedef struct lweight_pair_ lweight_pair_t;

#define RT_MATRIX_ELEM(M, T, sz, row, col) (((T *)((((T (*)[sz])(M))+row)))+col)

struct rt_adj_elem_
{
    uint32_t pairs;
#define RT_MAX_ADJ_PAIRS (4)
    lweight_pair_t adj_pairs[RT_MAX_ADJ_PAIRS];
};
typedef struct rt_adj_elem_ rt_adj_elem_t;

struct rt_path_elem_
{
    int sw_alias;
#define RT_PELEM_FIRST_HOP 0x1
#define RT_PELEM_LAST_HOP 0x2
    uint8_t flags;
    lweight_pair_t link;
};
typedef struct rt_path_elem_ rt_path_elem_t;

struct rt_transit_elem_
{
    unsigned int n_paths;
#define RT_MAX_EQ_PATHS 4
    int sw_alias[RT_MAX_EQ_PATHS]; /* Switch Alias */
};
typedef struct rt_transit_elem_ rt_transit_elem_t;

struct rt_list
{
    GSList *route;
    struct rt_list *next;
};
typedef struct rt_list rt_list_t;

void mul_route_path_traverse(GSList *iroute, GFunc iter_fn, void *arg);
void mul_destroy_route(GSList *route);
size_t mul_route_get_nodes(void *rt_service);
GSList *mul_route_get(void *rt_service, int src_sw, int dest_sw);
GSList *mul_route_get_mp(void *rt_service, int src_sw, int dest_sw, void *u_arg,
                         size_t (*mp_select)(void *u_arg, size_t max_routes));
void mul_route_init_block_meta(void *rt_info, void *blk);
void *mul_route_service_get(void);
void mul_route_service_destroy(void *rt_service);

#endif
