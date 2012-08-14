/*
 *  idx_pool.c: Index pool support 
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include "idx_pool.h"

int
ipool_get(ipool_hdl_t *pool)
{
    int next_idx = pool->next_idx;

    if (next_idx == -1) {
        return -1;
    }

    pool->next_idx = pool->idx_arr[pool->next_idx];

    return next_idx;
}

int
ipool_put(ipool_hdl_t *pool, int ret_idx)
{

    if (ret_idx < 0 || ret_idx > pool->max_idx) {
        return -1;
    }

    pool->idx_arr[ret_idx] = pool->next_idx;
    pool->next_idx = ret_idx;
    
    return 0;
}

ipool_hdl_t *
ipool_create(size_t sz, uint32_t start_idx)
{
    ipool_hdl_t *pool;
    int         idx = 0; 

    if (sz > INT_MAX) {
        return NULL;
    }

    pool = calloc(1, sizeof(ipool_hdl_t));
    if (pool == NULL) {
        return NULL;
    }

    pool->idx_arr = calloc(1, sz);
    if (pool->idx_arr == NULL) {
        free(pool);
        return NULL;
    }

    pool->max_idx = start_idx + sz - 1; 
    pool->next_idx = start_idx;

    for (; idx < sz; idx++) {
        pool->idx_arr[idx] = idx+1;
    }

    pool->idx_arr[idx-1] = -1;
    
    return pool;
}

void
ipool_delete(ipool_hdl_t *pool)
{
    if (pool == NULL) {
        return;
    }

    if (pool->idx_arr) {
        free(pool->idx_arr);
    }

    free(pool);
}
