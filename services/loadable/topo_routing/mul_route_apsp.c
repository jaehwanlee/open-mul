/*
 *  mul_route_apsp.c: MUL routing all pairs shortest path algorithm
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

static char *
mul_route_apsp_dump_adj_matrix(void *tr_hdl);


/**
 * mul_clear_route_matrix -
 *
 * Clear(Zero) the routing matrices
 */
static inline void
mul_clear_route_matrix(rt_apsp_t *rt_apsp_info)
{
    memset(rt_apsp_info->adj_matrix, 0,
           RT_APSP_BLOCK_SIZE - sizeof(rt_apsp_state_t));
}

/**
 * mul_clear_route_state_info -
 *
 * Clear(Zero) the routing state info
 */
static inline void
mul_clear_route_state_info(rt_apsp_t *rt_apsp_info)
{
    rt_apsp_info->state_info->state = RT_APSP_NONE;
    rt_apsp_info->state_info->calc_ts = 0;
    rt_apsp_info->state_info->nodes = 0;
}


/**
 * mul_route_apsp_hearbeat -
 * @fd : File descriptor (unused)
 * @event : event type (unused)
 * @arg : user arg (tr struct pointer)
 *
 * Heartbeat timer to flag that route service is alive
 */
static void
mul_route_apsp_hearbeat(evutil_socket_t fd UNUSED, short event UNUSED,
                        void *arg)
{
    tr_struct_t *tr = arg;
    rt_apsp_t *rt_apsp_info;
    rt_prot_hdl_t *rt_prot;
    struct timeval tv = { RT_HB_INTVL_SEC,
                          RT_HB_INTVL_USEC };

    assert(tr && tr->rt.rt_priv);

    rt_prot = tr->rt.rt_priv;
    rt_apsp_info  = RT_APSP_INFO(tr);

    rt_apsp_info->state_info->serv_ts = time(NULL); 

    evtimer_add(rt_prot->rt_timer_event, &tv);
}

/*
 * mul_route_apsp_add_neigh_conn -
 * @hdl: Main module struct  
 *
 * Callback to get info about neighbour connection from topology module
 */
void 
mul_route_apsp_add_neigh_conn(void *hdl, int sw_a, int sw_b, 
                              lweight_pair_t *new_adj)
{
    tr_struct_t *tr = hdl;
    rt_apsp_t *rt_apsp_info;
    rt_adj_elem_t *adj_elem = NULL;
    lweight_pair_t *adj = NULL;
    int pair = 0;

    assert(tr && tr->rt.rt_priv);
    rt_apsp_info  = RT_APSP_INFO(tr);


    if (!(rt_apsp_info->state_info->state & RT_APSP_INIT)) {
        c_log_err("%s: APSP State not initialized", FN);
        return;
    }  

    if (rt_apsp_info->state_info->nodes <= sw_a || 
        rt_apsp_info->state_info->nodes <= sw_a) {
        c_log_err("%s: State mismatch, Cant continue", FN);
        return;
    }

    c_log_debug("%s:src_sw:port(%d:%d)->dst_sw:port(%d:%d)", 
                FN, sw_a, new_adj->la, sw_b, new_adj->lb); 

    adj_elem = RT_APSP_ADJ_ELEM(rt_apsp_info, sw_a, sw_b);
    if (adj_elem->pairs >= RT_MAX_ADJ_PAIRS-1) {
        c_log_err("%s: Cant support adjacency pairs > %u", FN, RT_MAX_ADJ_PAIRS);
        return;
    }

    for (pair = 0; pair < adj_elem->pairs; pair++) {
        adj = &adj_elem->adj_pairs[pair];

        if (adj->la == new_adj->la && adj->lb == new_adj->lb) {
            if (adj->weight != new_adj->weight) {
                adj->weight = new_adj->weight;        
                rt_apsp_info->state_info->state &= ~RT_APSP_ADJ_INIT; /* Force recalc */
            }
            return;
        }
    }

    if (pair < RT_MAX_ADJ_PAIRS) {
        adj = &adj_elem->adj_pairs[pair];

        adj->la = new_adj->la;
        adj->lb = new_adj->lb;
        adj->weight = new_adj->weight;
        adj->onlink = true;
        adj_elem->pairs++;

        rt_apsp_info->state_info->state &= ~RT_APSP_ADJ_INIT; /* Force recalc */
    } 

    return;
}

/*
 * mul_route_apsp_init_state -
 * @hdl: Main module struct
 *
 * Initialize APSP state to latest topology map 
 */
int
mul_route_apsp_init_state(void *hdl)
{
    tr_struct_t *tr = hdl;
    rt_prot_hdl_t *rt_prot;
    rt_apsp_t *rt_apsp_info;
    tr_neigh_query_arg_t tr_neigh_arg;
    int i = 0, j = 0, k =0, nodes = 0;

    if (!tr || !tr->rt.rt_priv) {
        c_log_err("%s: Invalid tr handle", FN);
        return -EINVAL;
    }

    rt_prot = tr->rt.rt_priv;

    c_log_debug("%s: ", FN);

    if (!rt_prot->rt_prot_info) {
        c_log_err("%s: [fatal] RT apsp block not found", FN);
        return -EINVAL;
    }


    rt_apsp_info = rt_prot->rt_prot_info;

    mul_route_apsp_clean_state(hdl);
   
    nodes = __tr_get_max_switch_alias(rt_prot->tr_hdl);
    if (nodes++ < 0) { 
        c_log_err("%s: No nodes in graph", FN);
        return -EINVAL;
    }

    c_seq_wr_lock(&rt_apsp_info->state_info->lock);

    /* Clear the block just to be safe */
    mul_clear_route_matrix(rt_apsp_info);

    rt_apsp_info->state_info->nodes = nodes;

    for (; i < nodes; i++) {
        for (j = 0; j < nodes; j++) {
            rt_adj_elem_t *adj_elem = RT_APSP_ADJ_ELEM(rt_apsp_info, i, j);
            rt_init_adj_pairs_disconnected(adj_elem);
            RT_APSP_PATH_ELEM(rt_apsp_info, i, j)->n_paths = 0;
            for (k = 0; k < RT_MAX_EQ_PATHS; k++) {
                RT_APSP_PATH_ELEM(rt_apsp_info, i, j)->sw_alias[k]
                            = NEIGH_NO_PATH;
            }
        }
    }

    rt_apsp_info->state_info->state = RT_APSP_INIT;

    tr_neigh_arg.tr = tr;

    for (i = 0; i < nodes; i++) {
        for (j = 0; j < nodes; j++) {
            tr_neigh_arg.src_sw = i;
            tr_neigh_arg.dst_sw = j;
            __tr_init_neigh_pair_adjacencies(&tr_neigh_arg); 
        }
    }
    rt_apsp_info->state_info->state |= RT_APSP_ADJ_INIT;
    c_seq_wr_unlock(&rt_apsp_info->state_info->lock);

    return 0;
}

/*
 *  mul_route_apsp_calc -
 *  @hdl: Main module struct
 *
 *  Calculate the all pairs shortest paths  
 */
int
mul_route_apsp_calc(void *hdl)
{
    tr_struct_t *tr = hdl;
    rt_apsp_t *rt_apsp_info; 
    int fw_i, fw_j, fw_k;    /* Floyd warshall loop variables*/
    int w_ik, w_kj, w_ij;
    unsigned int n_paths;
    size_t nodes = 0;

    assert(tr && tr->rt.rt_priv);

    rt_apsp_info  = RT_APSP_INFO(tr);

    c_seq_wr_lock(&rt_apsp_info->state_info->lock);

    if (!(rt_apsp_info->state_info->state & RT_APSP_INIT) ||
        !(rt_apsp_info->state_info->state & RT_APSP_ADJ_INIT) ) {
        c_seq_wr_unlock(&rt_apsp_info->state_info->lock);
        c_log_err("%s: rt apsp not initialized", FN);
        return -EINVAL;
    }

    nodes = rt_apsp_info->state_info->nodes;
    rt_apsp_info->state_info->state |= RT_APSP_RUN;

    for (fw_k = 0; fw_k < nodes; fw_k++) {
        for(fw_i = 0; fw_i < nodes; fw_i++) {
            for(fw_j = 0; fw_j < nodes; fw_j++) {
                if (fw_i == fw_j) continue;
                w_ij = rt_apsp_get_weight(rt_apsp_info, fw_i, fw_j);
                w_ik = rt_apsp_get_weight(rt_apsp_info, fw_i, fw_k);
                w_kj = rt_apsp_get_weight(rt_apsp_info, fw_k, fw_j);

                //printf ("i(%d) j(%d) wij(%d) wik(%d) wkj(%d)\n", 
                //          fw_i, fw_j, w_ij, w_ik, w_kj );
                if (w_ik != NEIGH_NO_PATH && w_kj != NEIGH_NO_PATH) {
                    if (w_ik + w_kj < w_ij)  {
                        rt_apsp_set_weight(rt_apsp_info, fw_i, fw_j, w_ik + w_kj);
                        for (n_paths = 0; n_paths < RT_MAX_EQ_PATHS; n_paths++) {
                            RT_APSP_PATH_ELEM(rt_apsp_info, fw_i, fw_j)
                                   ->sw_alias[n_paths] = NEIGH_NO_PATH;
                        }

                        RT_APSP_PATH_ELEM(rt_apsp_info, fw_i, fw_j)
                                    ->n_paths = 1;
                        RT_APSP_PATH_ELEM(rt_apsp_info, fw_i, fw_j)
                                    ->sw_alias[0] = fw_k;
                    } else if (w_ik + w_kj ==  w_ij &&
                               fw_k != fw_i && fw_k != fw_j) {

                        n_paths = RT_APSP_PATH_ELEM(rt_apsp_info, fw_i, fw_j)
                                    ->n_paths;
                        if (n_paths < RT_MAX_EQ_PATHS) {
                            RT_APSP_PATH_ELEM(rt_apsp_info, fw_i, fw_j)
                                    ->sw_alias[n_paths++] = fw_k;
                            RT_APSP_PATH_ELEM(rt_apsp_info, fw_i, fw_j)
                                    ->n_paths = n_paths;
                        }
                    }
                }
            }
        }
    }

    rt_apsp_info->state_info->calc_ts = time(NULL);
    rt_apsp_info->state_info->state &= ~RT_APSP_RUN;
    rt_apsp_info->state_info->state |= RT_APSP_CONVERGED;

    c_seq_wr_unlock(&rt_apsp_info->state_info->lock);

    return 0;
}

/**
 * add_route_path_elem -
 * @route_path - Pointer of pointer to the route
 * @node - Node (sw alias)
 * @adj - A single adjacency pair
 *
 * Add a path element to a route
 */
static inline void
add_route_path_elem(GSList **route_path, int node, lweight_pair_t *adj)
{
    rt_path_elem_t *path_elem;

    path_elem = calloc(1, sizeof(*path_elem));
    path_elem->sw_alias = node;
    
    memcpy(&path_elem->link, adj, sizeof(lweight_pair_t));

    *route_path = g_slist_append((*route_path), path_elem);
}


/*
 *  mul_route_apsp_get_path -
 *  @hdl: Main module struct
 *  @src_sw: Source switch
 *  @dest_sw: Source switch
 *
 *  Retrieve a path from one switch to another  
 *  NOTE : This only works on alias switch ids
 */
GSList *
mul_route_apsp_get_path(void *hdl, int src_sw, int dest_sw)
{
    tr_struct_t *tr = hdl;
    rt_apsp_t *rt_apsp_info;

    assert(tr && tr->rt.rt_priv);
    rt_apsp_info  = RT_APSP_INFO(tr);

    return mul_route_apsp_get_sp(rt_apsp_info, src_sw, dest_sw);
}

/*
 * mul_route_apsp_clean_state -
 * @hdl: Main module struct
 *
 * Cleans APSP state
 */
int
mul_route_apsp_clean_state(void *hdl)
{
    tr_struct_t *tr = hdl;
    rt_prot_hdl_t *rt_prot;
    rt_apsp_t *rt_apsp_info;

    if (!tr || !tr->rt.rt_priv) {
        c_log_err("%s: Invalid tr handle", FN);
        return -EINVAL;
    }

    rt_prot = tr->rt.rt_priv;
    rt_apsp_info = rt_prot->rt_prot_info;

    if (rt_apsp_info) {
        c_seq_wr_lock(&rt_apsp_info->state_info->lock);
        mul_clear_route_state_info(rt_apsp_info);
        c_seq_wr_unlock(&rt_apsp_info->state_info->lock);
    }

    return 0; 
}

/**
 * mul_route_apsp_dump_adj_matrix -
 *
 * Dump the adjacency matrix info
 */
static char *
mul_route_apsp_dump_adj_matrix(void *tr_hdl)
{
#define APSP_ADJ_PBUF_SZ 4096
    char *pbuf;
    int i = 0, j = 0, len = 0;
    rt_apsp_t *rt_apsp_info;
    tr_struct_t *tr = tr_hdl;

    assert(tr && tr->rt.rt_priv);
    rt_apsp_info = RT_APSP_INFO(tr);

    pbuf = calloc(1, APSP_ADJ_PBUF_SZ);

    for (i = 0; i < rt_apsp_info->state_info->nodes; i++) {
        for (j = 0; j < rt_apsp_info->state_info->nodes; j++) {
            lweight_pair_t *pair = rt_apsp_get_pair(rt_apsp_info, i, j);

            len += snprintf(pbuf+len, APSP_ADJ_PBUF_SZ-len-1, 
                            "(%d)->(%d) %hu %hu %d\r\n", i, j, 
                            pair->la, pair->lb, pair->weight);
            if (len >= APSP_ADJ_PBUF_SZ-1) break;
        }
    }

    return pbuf;
}

/**
 * mul_route_init_apsp -
 *
 * All paths shortest pair routing algo initialization
 */
static int 
mul_route_init_apsp(rt_prot_hdl_t *rt_prot)
{
    rt_apsp_t *rt_apsp_info;
    int route_serv_fd = -1;
    void *blk_ptr;

    if (rt_prot->rt_prot_info) {
        c_log_err("%s: RT apsp info already allocated", FN);
        return -EINVAL;
    }

    rt_apsp_info = calloc(1, sizeof(*rt_apsp_info));
    if (!rt_apsp_info) {
        c_log_err("%s: RT apsp info allocation fail", FN);
        return -ENOMEM;
    }

    //shm_unlink(MUL_TR_SERVICE_NAME);

    route_serv_fd = shm_open(MUL_TR_SERVICE_NAME, 
                             O_CREAT | O_RDWR, 0666);
    if (route_serv_fd < 0) {
        c_log_err("%s: RT apsp block alloc fail", FN);
        goto free;
    }

    if((ftruncate(route_serv_fd, RT_APSP_BLOCK_SIZE)) != 0) {    
        c_log_err("%s: RT apsp block size set failed", FN);
        goto free;
    }

    blk_ptr = mmap(0, RT_APSP_BLOCK_SIZE, PROT_READ | PROT_WRITE, 
                   MAP_SHARED, route_serv_fd, 0);
    if (blk_ptr == MAP_FAILED) {
        c_log_err("%s: RT apsp block map fail", FN);
        goto unlink;
    }


    rt_prot->rt_prot_info = rt_apsp_info;
    memset(blk_ptr, 0, RT_APSP_BLOCK_SIZE);

    mul_route_init_block_meta(rt_apsp_info, blk_ptr);
    c_seq_lock_init(&rt_apsp_info->state_info->lock);

    close(route_serv_fd);

    return 0;
unlink:
    shm_unlink(MUL_TR_SERVICE_NAME);
free:
    free(rt_apsp_info);
    return -1;
}

/**
 * mul_route_init -
 *
 * Routing module init
 */
int 
mul_route_init(tr_struct_t *tr)
{
    struct timeval tv = { RT_HB_INTVL_SEC,
                          RT_HB_INTVL_USEC };
    rt_info_t *rt_info;
    rt_prot_hdl_t *rt_prot;
    struct event_base *base = tr->app_ctx;
    
    if (!tr) {
        c_log_err("%s: No Topo handle", FN); 
        assert(0);
    }    

    rt_info = &tr->rt;

    rt_info->rt_priv = calloc(1, sizeof(rt_prot_hdl_t));
    if (!rt_info->rt_priv) {
        c_log_err("%s: Could not alloc protocol handle", FN);
        assert(0);
    }

    rt_info->rt_init_state = mul_route_apsp_init_state; 
    rt_info->rt_add_neigh_conn = mul_route_apsp_add_neigh_conn;
    rt_info->rt_calc = mul_route_apsp_calc; 
    rt_info->rt_get_sp = mul_route_apsp_get_path;
    rt_info->rt_clean_state = mul_route_apsp_clean_state;
    rt_info->rt_dump_adj_matrix = mul_route_apsp_dump_adj_matrix;

    rt_prot = rt_info->rt_priv;
    
    rt_prot->tr_hdl = tr;
    c_rw_lock_init(&rt_prot->rt_lock);

    if (mul_route_init_apsp(rt_prot) < 0) {
        assert(0);
    }

    rt_prot->rt_timer_event = evtimer_new(base, mul_route_apsp_hearbeat,
                                          (void *)tr);
    evtimer_add(rt_prot->rt_timer_event, &tv);

    c_log_debug("%s", FN);

    return 0;
}
