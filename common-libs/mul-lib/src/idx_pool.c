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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#include "lock.h"
#include "idx_pool.h"

int
ipool_get(ipool_hdl_t *pool, void *priv)
{
    int next_idx;

    c_wr_lock(&pool->lock);

    next_idx = pool->next_idx;

    if (next_idx == -1) {
        c_wr_unlock(&pool->lock);
        return -1;
    }

    pool->next_idx = pool->idx_arr[next_idx].next_idx;
    pool->idx_arr[next_idx].priv = priv;

    c_wr_unlock(&pool->lock);

    return next_idx;
}

int
ipool_put(ipool_hdl_t *pool, int ret_idx)
{

    c_wr_lock(&pool->lock);

    if (ret_idx < 0 || ret_idx > pool->max_idx) {
        c_wr_unlock(&pool->lock);
        return -1;
    }

    pool->idx_arr[ret_idx].next_idx = pool->next_idx;
    pool->idx_arr[ret_idx].priv = NULL;
    pool->next_idx = ret_idx;

    c_wr_unlock(&pool->lock);
    
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

    pool->idx_arr = calloc(1, sz * sizeof(ipool_arr_t));
    if (pool->idx_arr == NULL) {
        free(pool);
        return NULL;
    }

    c_rw_lock_init(&pool->lock);

    pool->max_idx = start_idx + sz - 1; 
    pool->next_idx = start_idx;

    for (; idx < sz; idx++) {
        pool->idx_arr[idx].next_idx = idx+1;
    }

    pool->idx_arr[idx-1].next_idx = -1;
    
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

void *
ipool_idx_priv(ipool_hdl_t *pool, int idx)
{
    /**
     * Do we need locking here ? It is best to
     * delegate locking responsilibty to the user
     * or caller of idx pool
     */

    if (!pool || idx > pool->max_idx) {
        return NULL;
    }

    return pool->idx_arr[idx].priv;
}
