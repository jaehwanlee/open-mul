/*
 *  mul_tr_servlet.h: MUL topo-routing service header
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
#ifndef  __MUL_TR_SERVLET_H__
#define  __MUL_TR_SERVLET_H__

#define TR_DFL_PBUF_SZ (4096) 

struct cbuf *mul_neigh_get(void *service, uint64_t dpid);
char *mul_dump_neigh(struct cbuf *b, bool free_buf);

#endif
