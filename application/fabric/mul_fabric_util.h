/*
 *  mul_fabric_util.h: Mul fabric util headers
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
#ifndef __MUL_FABRIC_UTIL_H__
#define __MUL_FABRIC_UTIL_H__

#define FAB_MK_TEN_NET_ID(tnid, tid, nid)               \
do {                                                    \
    tnid = (((uint16_t)(tid)) << 16 | (uint16_t)(nid)); \
}while(0)


static inline void *
fab_zalloc(size_t sz)
{
    void *ptr;
    
    ptr = calloc(1, sz); 
    assert(ptr);
    
    return ptr;
}

static inline void *
fab_malloc(size_t sz)
{
    void *ptr;
    
    ptr = malloc(sz); 
    assert(ptr);
    
    return ptr;
}

static inline void
fab_free(void *buf)
{
    free(buf);
}

/**
 * fab_add_tenant_id -
 * @fl : flow pointer
 * @wildcards : wildcard pointer to  be updated
 * @tenant_id : tenant id
 *
 * Embed a tenant-id in flow struct 
 */
static inline void
fab_add_tenant_id(struct flow *fl, uint32_t *wildcards, uint16_t tenant_id)
{

    if (wildcards)
        *wildcards &= ~(OFPFW_DL_VLAN);

    fl->dl_vlan = htons(tenant_id);
}

/**
 * fab_reset_tenant_id -
 * @fl : flow pointer
 * @wildcards : wildcard pointer to be updated
 *
 * reset tenant id in flow struct 
 */
static inline void
fab_reset_tenant_id(struct flow *fl, uint32_t *wildcards)
{

    if (wildcards)
        *wildcards |= (OFPFW_DL_VLAN);

    fl->dl_vlan = 0;
}


/*
 * fab_extract_tenant_id -
 * @fl : flow pointer
 
 * extract tenant from flow struct 
 */
static inline uint16_t
fab_extract_tenant_id(struct flow *fl)
{
    return ntohs(fl->dl_vlan);
}

/**
 * fab_add_network_id -
 * @fl : flow pointer
 * @network_id : network id denoting a network segment
 *
 * embed network in the flow struct
 */
static inline void
fab_add_network_id(struct flow *fl, uint16_t network_id)
{
    *(uint16_t *)&fl->pad[1] = htons(network_id);
}

/**
 * fab_extract_network_id -
 * @fl : flow pointer
 * @network_id : network id denoting a network segment
 *
 * extract network id from flow struct
 */
static inline uint16_t
fab_extract_network_id(struct flow *fl)
{
    return ntohs(*(uint16_t *)&fl->pad[1]);
}


static inline uint16_t
fab_tnid_to_tid(uint32_t tnid)
{
    return (uint16_t)((tnid > 16) & 0xffff);
}

static inline uint16_t
fab_tnid_to_nid(uint32_t tnid)
{
    return (uint16_t)(tnid & 0xffff);
}


#define HOST_PBUF_SZ 512

/**
 * fab_dump_single_host_from_flow -
 *  
 * Dump a single host from flow struct and dpid
 */
static inline char * 
fab_dump_single_host_from_flow(uint64_t dpid, struct flow *fl)
{
    char     *pbuf = calloc(1, HOST_PBUF_SZ);
    int      len = 0;
    
    len += snprintf(pbuf+len, HOST_PBUF_SZ-len-1,
                    "Tenant %4hu, Network %4hu, host-ip 0x%-8x,host-mac "
                    "%02x:%02x:%02x:%02x:%02x:%02x on switch "
                    "0x%016llx port %4hu (%s)\r\n",
                    fab_extract_tenant_id(fl), 
                    fab_extract_network_id(fl), 
                    ntohl(fl->nw_src),
                    fl->dl_src[0], fl->dl_src[1],
                    fl->dl_src[2], fl->dl_src[3],
                    fl->dl_src[4], fl->dl_src[5],
                    dpid,
                    ntohs(fl->in_port),
                    fl->FL_DFL_GW ? "dfl-gw" : "non-gw");
    assert(len < HOST_PBUF_SZ-1);
    return pbuf;
}
#endif
