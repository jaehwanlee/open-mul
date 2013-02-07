/*  mul_route.h: MUL routing application framework header 
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

#ifndef __MUL_ROUTE_PRIV_H__
#define __MUL_ROUTE_PRIV_H__

#include "mul_lldp_common.h"

struct rt_prot_hdl_
{
    c_rw_lock_t     rt_lock;
    void            *rt_prot_info;
    struct event    *rt_timer_event;
    tr_struct_t     *tr_hdl;
};
typedef struct rt_prot_hdl_ rt_prot_hdl_t;

static inline void
rt_init_adj_pair_disconnected(lweight_pair_t *pair)
{
    pair->la = NEIGH_NO_LINK;
    pair->lb = NEIGH_NO_LINK;
    pair->weight = NEIGH_NO_PATH;
}

static inline void
rt_init_adj_pairs_disconnected(rt_adj_elem_t *adj_elem)
{
    int pair = 0;
    
    adj_elem->pairs = 0;

    for (pair = 0; pair < RT_MAX_ADJ_PAIRS; pair++) {
        rt_init_adj_pair_disconnected(&adj_elem->adj_pairs[pair]);
    }
}

static inline void *
rt_alloc_matrix(size_t n, size_t elem_sz)
{
    void *rt_matrix = calloc(1, n * n * elem_sz);
    assert(rt_matrix);

    return rt_matrix; 
}

static inline void 
rt_free_matrix(void *matrix_ptr)
{
    free(matrix_ptr);
}

#ifdef CONFIG_MUL_RT
int mul_route_init(tr_struct_t *tr);
void route_vty_init(void *arg);
#else
static inline int
mul_route_init(tr_struct_t *tr UNUSED)
{
    return 0;
}

static inline void
route_vty_init(void *arg UNUSED)
{
}
#endif

#endif
