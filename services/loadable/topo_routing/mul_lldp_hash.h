/*  mul_lldp_hash.h: Mul lldp hashing defines
 *  Copyright (C) 2012, Dipjyoti Saikia<dipjyoti.saikia@gmail.com> 
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
#ifndef __MUL_LLDP_HASH_H__
#define __MUL_LLDP_HASH_H__ 

unsigned int dpid_hash_func(const void *key);
int dpid_equal_func(const void *key1, const void *key2);
void lldp_switch_remove(void *data);

unsigned int portid_hash_func(const void* key);
int portid_equal_func(const void *key1, const void *key2);

unsigned int sent_pkt_hash_func(const void *key);
int sent_pkt_equal_func(const void *key1, const void *key2);


#endif /* __MUL_LLDP_HASH_H__ */
