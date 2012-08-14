/*
 *  idx_pool.h: Index pool header file 
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

typedef struct ipool_hdl_
{
    int next_idx;
    int max_idx;
    int *idx_arr;    
}ipool_hdl_t;

int ipool_get(ipool_hdl_t *pool);
int ipool_put(ipool_hdl_t *pool, int ret_idx);
ipool_hdl_t *ipool_create(size_t sz, uint32_t start_idx);
void ipool_delete(ipool_hdl_t *pool);
