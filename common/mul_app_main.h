/*
 *  mul_app_main.h: MUL application main headers
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
#ifndef __MUL_APP_MAIN_H___
#define __MUL_APP_MAIN_H___

#define C_APP_RCV_BUF_SZ 4096
#define C_APP_VTY_COMMON_PATH "/var/run/app_"

struct c_app_hdl_
{
    char *progname;
    c_conn_t conn;
    struct event_base *base;
    struct event *reconn_timer_event;
    void (*ev_cb)(void *app, void *buf);

    /* For VTY thread */
    pthread_t vty_thread;
    void  *vty_master;
    uint16_t vty_port;
};
typedef struct c_app_hdl_ c_app_hdl_t;

#endif
