/*  mul_route_apsp.h: MUL all-pairs SP routing service header defintions 
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

#ifndef __MUL_ROUTE_APSP_H__
#define __MUL_ROUTE_APSP_H__

#include "mul_route.h"

#define RT_APSP_MAX_MATRIX_SZ(sz) (MAX_SWITCHES_PER_CLUSTER*MAX_SWITCHES_PER_CLUSTER*sz) 

#define RT_APSP_BLOCK_SIZE (sizeof(rt_apsp_state_t) + \
                           RT_APSP_MAX_MATRIX_SZ(sizeof(rt_adj_elem_t)) + \
                           RT_APSP_MAX_MATRIX_SZ(sizeof(rt_transit_elem_t)))

#define RT_APSP_PATH_ELEM(H, i, j)  RT_MATRIX_ELEM((H)->paths, rt_transit_elem_t, (H)->state_info->nodes, i, j)
#define RT_APSP_ADJ_ELEM(H, i, j)  RT_MATRIX_ELEM((H)->adj_matrix, rt_adj_elem_t, (H)->state_info->nodes, i, j)

struct rt_apsp_state_
{
#define RT_APSP_NONE 0x0
#define RT_APSP_INIT 0x1
#define RT_APSP_ADJ_INIT 0x2
#define RT_APSP_RUN  0x4 
#define RT_APSP_CONVERGED 0x8
    uint32_t state;
    time_t   calc_ts;
    time_t   serv_ts;
    size_t   nodes;
    c_seq_lock_t lock;
};
typedef struct rt_apsp_state_ rt_apsp_state_t;

struct rt_apsp_
{
    rt_apsp_state_t *state_info;
    void *adj_matrix;
    void *paths;
};
typedef struct rt_apsp_ rt_apsp_t;

static inline int
rt_apsp_select_mp(rt_adj_elem_t *adj_elem UNUSED)
{
    /* We are not supporting MP as yet */
    return 0;
}

static inline int
rt_apsp_get_weight(rt_apsp_t *rt_apsp_info, int node_a, int node_b)
{
    lweight_pair_t *pair;
    rt_adj_elem_t *adj_elem = RT_APSP_ADJ_ELEM(rt_apsp_info, node_a, node_b);

    /* FIXME - If nodes are on-link we need to consider the least weight
     * among all possible links between these onlink pair
     */
    pair = &adj_elem->adj_pairs[rt_apsp_select_mp(adj_elem)];

    return pair->weight;
}

static inline int
rt_apsp_onlink_neigh(rt_apsp_t *rt_apsp_info, int node_a, int node_b)
{
    lweight_pair_t *pair;
    rt_adj_elem_t *adj_elem = RT_APSP_ADJ_ELEM(rt_apsp_info, node_a, node_b);

    pair = &adj_elem->adj_pairs[rt_apsp_select_mp(adj_elem)];

    return pair->onlink;
}

static inline void
rt_apsp_set_weight(rt_apsp_t *rt_apsp_info, int node_a, int node_b, int weight)
{
    lweight_pair_t *pair;
    rt_adj_elem_t *adj_elem = RT_APSP_ADJ_ELEM(rt_apsp_info, node_a, node_b);

    pair = &adj_elem->adj_pairs[rt_apsp_select_mp(adj_elem)];

    pair->weight = weight;
}

static inline lweight_pair_t *
rt_apsp_get_pair(rt_apsp_t *rt_apsp_info, int node_a, int node_b)
{
    lweight_pair_t *pair;
    rt_adj_elem_t *adj_elem = RT_APSP_ADJ_ELEM(rt_apsp_info, node_a, node_b);

    pair = &adj_elem->adj_pairs[rt_apsp_select_mp(adj_elem)];

    return pair;
}

static inline bool
rt_apsp_converged(rt_apsp_t *rt_apsp_info)
{
    return (rt_apsp_info->state_info->state & RT_APSP_INIT  &&
            rt_apsp_info->state_info->state & RT_APSP_ADJ_INIT &&
            rt_apsp_info->state_info->state & RT_APSP_CONVERGED);
}

#endif
