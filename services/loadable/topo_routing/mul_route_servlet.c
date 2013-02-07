/*
 *  mul_route_servlet.c: MUL routing service 
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

#include "mul_common.h"
#include "mul_route.h"
#include "mul_route_apsp.h"

GSList *mul_route_apsp_get_sp(void *rt_service, int src_sw, int dest_sw);

/**
 * mul_route_path_traverse -
 *
 * Traverse through all path elements of a route
 */
void
mul_route_path_traverse(GSList *iroute, GFunc iter_fn, void *arg)
{
    if (iroute) {
        g_slist_foreach(iroute, (GFunc)iter_fn, arg);
    }

}

/**
 * mul_free_rt_links -
 *
 * Free all path elements of a route
 */
static void
mul_free_rt_links(void *ptr)
{
    free(ptr);
}

/**
 * mul_destroy_route -
 *
 * Destroy a route
 */ 
void
mul_destroy_route(GSList *route)
{
    if (route) {
        g_slist_free_full(route, mul_free_rt_links);
    }
}

/**
 * mul_route_init_block_meta -
 *
 * Initialize shared memory meta data for routing subsystem 
 */
void
mul_route_init_block_meta(void *rt_info, void *blk)
{
    rt_apsp_t *rt_apsp_info = rt_info;

    rt_apsp_info->state_info = blk;
    rt_apsp_info->adj_matrix = (void *)(((uint8_t *)(blk))+sizeof(rt_apsp_state_t));
    rt_apsp_info->paths = (void *)((uint8_t *)(rt_apsp_info->adj_matrix) + 
                                        RT_APSP_MAX_MATRIX_SZ(sizeof(rt_adj_elem_t)));
}

/**
 * mul_route_service_get -
 *
 * Get a handle to the routing service 
 */
void *
mul_route_service_get(void)
{
    void *ptr = NULL;
    rt_apsp_t *rt_apsp_info;
    int serv_fd;

    c_log_debug("%s: ", FN);

    if ((serv_fd = shm_open(MUL_TR_SERVICE_NAME, O_RDONLY, 0)) < 0) {
        c_log_err("%s: Cant get service (unavailable)", FN);
        return NULL;
    }

    perror("shm_open");

    ptr = mmap(0, RT_APSP_BLOCK_SIZE, PROT_READ, MAP_SHARED, serv_fd, 0);
    if (ptr == MAP_FAILED) {
        c_log_err("%s: Cant get service (failed to map)", FN);
        return NULL;
    }

    rt_apsp_info = calloc(1, sizeof(*rt_apsp_info));
    if (!rt_apsp_info) {
        c_log_err("%s: RT apsp info allocation fail", FN);
        return NULL;
    }

    mul_route_init_block_meta(rt_apsp_info, ptr);

    close(serv_fd);

    return (void *)rt_apsp_info;
}

/**
 * mul_route_service_destroy -
 *
 * Derefer usage handle of the routing service
 */
void
mul_route_service_destroy(void *rt_service)
{
    munmap((void *)rt_service, RT_APSP_BLOCK_SIZE);
    
    shm_unlink(MUL_TR_SERVICE_NAME);
}

/**
 * add_route_path_elem -
 *
 * Adds a path element to a route 
 */
static inline void
add_route_path_elem(GSList **route_path, int node, lweight_pair_t *adj,
                    bool last_hop)
{
    rt_path_elem_t *path_elem;

    path_elem = calloc(1, sizeof(*path_elem));
    path_elem->sw_alias = node;
    path_elem->flags = last_hop ? RT_PELEM_LAST_HOP :0;
    
    memcpy(&path_elem->link, adj, sizeof(lweight_pair_t));

    if (!(*route_path)) {
        path_elem->flags |= RT_PELEM_FIRST_HOP;
    }

    *route_path = g_slist_append((*route_path), path_elem);
}

/**
 * mul_route_apsp_get_subp -
 *
 * Get a list of shortest paths between src and dest 
 */
static void
mul_route_apsp_get_subp(rt_apsp_t *rt_apsp_info, int src, int dest,
                        GSList **path)
{
    int transit_sw = NEIGH_NO_PATH;

    if (((transit_sw = RT_APSP_PATH_ELEM(rt_apsp_info, src, dest)->sw_alias[0]) 
                        == NEIGH_NO_PATH)) {
        if (rt_apsp_onlink_neigh(rt_apsp_info, src, dest)) {
            add_route_path_elem(path, src, 
                                rt_apsp_get_pair(rt_apsp_info, src, dest),
                                false);
        } else {
            c_log_err("%s: No route between %d to %d", FN, src, dest);
        }
        return;
    }

    mul_route_apsp_get_subp(rt_apsp_info, src, transit_sw, path);
    mul_route_apsp_get_subp(rt_apsp_info, transit_sw, dest, path);

    return;
}


/**
 * mul_route_apsp_get_sp -
 * @route_service : Handle to the route service 
 * @src_sw : Source node  
 * @dest_sw : Destination node 
 *
 */
GSList *
mul_route_apsp_get_sp(void *rt_service, int src_sw, int dest_sw)
{
    unsigned int lock, max_retries = 0;
    rt_apsp_t *rt_apsp_info = rt_service;
    GSList *path = NULL;
    lweight_pair_t last_hop = { NEIGH_NO_LINK, NEIGH_NO_LINK, 
                                NEIGH_NO_PATH, false };

    if (src_sw == dest_sw) {
        goto route_same_node;
    }

retry:
    if (max_retries++ >= RT_MAX_GET_RETRIES) {
        c_log_err("Too much writer contention or service died");
        return NULL;
    }

    lock = c_seq_rd_lock(&rt_apsp_info->state_info->lock);
    if (!rt_apsp_converged(rt_apsp_info)) {
        if (c_seq_rd_unlock(&rt_apsp_info->state_info->lock, lock))  {
            goto retry;
        }
        c_log_err("%s: Routes not yet converged", FN);
        return NULL;
    }

    if (rt_apsp_get_weight(rt_apsp_info, src_sw, dest_sw) == NEIGH_NO_PATH) {
        if (c_seq_rd_unlock(&rt_apsp_info->state_info->lock, lock))  {
            goto retry;
        }
        c_log_err("%s: Not a neigbour (%d:%d) %d", FN, src_sw, dest_sw, 
                  rt_apsp_get_weight(rt_apsp_info, src_sw, dest_sw));
        return NULL;
    }

    mul_route_apsp_get_subp(rt_apsp_info, src_sw, dest_sw, &path);

    if (c_seq_rd_unlock(&rt_apsp_info->state_info->lock, lock)) {
        mul_destroy_route(path);
        goto retry;
    }

route_same_node:
    add_route_path_elem(&path, dest_sw, &last_hop, true);

    return path;
}

/**
 * mul_route_service_alive -
 * @service : Handle to the route service 
 *
 * Checks status of routing service 
 */
static bool
mul_route_service_alive(void *service)
{
    rt_apsp_t *rt_apsp_info = service;
    time_t curr_ts = time(NULL);

    if (curr_ts >
        (rt_apsp_info->state_info->serv_ts + (2*RT_HB_INTVL_SEC))) {
        c_log_err("%s: %s not available", FN, MUL_TR_SERVICE_NAME);
        return false;
    }

    return true;
}


/**
 * mul_route_get_nodes -
 * @rt_service : Handle to the route service 
 *
 * Get number of nodes in routing matrix 
 */
size_t
mul_route_get_nodes(void *rt_service)
{
    rt_apsp_t *rt_apsp_info = rt_service;

    if (!mul_route_service_alive(rt_service)) {
        return 0;
    }

    return rt_apsp_info->state_info->nodes;
} 


/**
 * mul_route_get -
 * @rt_service : Handle to the route service 
 * @src_sw : Source node  
 * @dest_sw : Destination node 
 *
 * Front-end api of routing service to get route from source to dest 
 * Applicable when users dont want multi-pathing support
 */
GSList *
mul_route_get(void *rt_service, int src_sw, int dest_sw)
{
    rt_apsp_t *rt_apsp_info = rt_service;

    if (!mul_route_service_alive(rt_service)) {
        return 0;
    }

    if (src_sw < 0 || dest_sw < 0 ||
        ((src_sw != dest_sw) && (src_sw >= rt_apsp_info->state_info->nodes ||
        dest_sw >= rt_apsp_info->state_info->nodes))) {
        c_log_err("%s: src(%d) or dst(%d) out of range(%d)",
                  FN, src_sw, dest_sw, rt_apsp_info->state_info->nodes);
        return NULL;
    }

    return mul_route_apsp_get_sp(rt_service, src_sw, dest_sw);
}
