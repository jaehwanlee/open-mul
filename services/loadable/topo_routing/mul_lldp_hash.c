/*  mul_lldp_hash.c: Mul lldp hash implementation 
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

/**
 * dpid_hash_func - 
 *
 * helper dpid hash function 
 */
unsigned int
dpid_hash_func(const void *key)
{
	return hash_bytes(key,sizeof(uint64_t),1);
}

/**
 * dpid_equal_func - 
 *
 * Return true of two dpid keys are equal 
 */
int
dpid_equal_func(const void *key1, const void *key2)
{
	uint64_t idA = *((uint64_t *)key1);
	uint64_t idB = *((uint64_t *)key2);

	return idA == idB;
}

/**
 * lldp_switch_remove -
 *
 * Wrapper over lldp_switch_unref()
 */
void
lldp_switch_remove(void *data)
{
	lldp_switch_unref((lldp_switch_t *)data);
}

/**
 * portid_hash_func -
 *
 * helper portid hash function
 */
unsigned int
portid_hash_func(const void* key)
{
	return *((uint16_t *)key);
}

/**
 * portid_equal_func -
 *
 * Return true if two portid keys are equal
 */
int
portid_equal_func(const void *key1, const void *key2)
{
	uint16_t idA = *((uint16_t *)key1);
	uint16_t idB = *((uint16_t *)key2);
	return idA == idB;
}

/* send_pkt table functions */
unsigned int
sent_pkt_hash_func(const void *key)
{
	/* just hash sender id and port id*/
	return hash_bytes(key, sizeof(uint64_t) + sizeof(uint16_t),1);
}
int
sent_pkt_equal_func(const void *key1, const void *key2)
{
	lldp_sent_pkt_t *pkt1,*pkt2;
	pkt1 = (lldp_sent_pkt_t *)key1;
	pkt2 = (lldp_sent_pkt_t *)key2;
	return (pkt1->sender_id == pkt2->sender_id) && (pkt1->port_id == pkt2->port_id);
}
/* end of send_pkt table functions */
