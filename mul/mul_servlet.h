/*
 *  mul_servlet.h: MUL controller service header
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

#ifndef __MUL_SERVLET_H__
#define __MUL_SERVLET_H__

#define OFP_PRINT_MAX_STRLEN (256*4)
#define MUL_SERVLET_PBUF_DFL_SZ (10240)
#define SWITCH_BR_PBUF_SZ (MUL_SERVLET_PBUF_DFL_SZ) 

struct cbuf *mul_get_switches_brief(void *service);
struct cbuf *mul_get_switch_detail(void *service, uint64_t dpid);
void *mul_nbapi_dump_switch_brief(struct cbuf *b, bool free_buf);
char *mul_dump_switches_brief(struct cbuf *b, bool free_buf);
char *mul_dump_switch_detail(struct cbuf *b, bool free_buf);
int mul_get_flow_info(void *service, uint64_t dpid, bool flow_self,
                  bool dump_cmd, bool nbapi_cmd, void *arg,
                  void (*cb_fn)(void *arg, void *pbuf));

#endif
