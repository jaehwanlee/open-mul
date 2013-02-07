/*
 *  mul_services.h: MUL services import headers
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

#ifndef __MUL_SERVICES_H__
#define __MUL_SERVICES_H__

/* For routing related services */
#include "mul_route.h"
#include "mul_route_apsp.h"

/* For Topo&Routing combo services */
#include "mul_tr_servlet.h"

/* For Mul Core Services */
#include "mul_servlet.h"

#define MUL_TR_SERVICE_NAME       "mul-tr"
#define MUL_ROUTE_SERVICE_NAME    "mul-route"
#define MUL_FAB_CLI_SERVICE_NAME  "mul-fab-cli"
#define MUL_CORE_SERVICE_NAME     "mul-core"

#define MAX_SWITCHES_PER_CLUSTER  (128)

#define C_APP_PORT      7744
#define C_AUX_APP_PORT  7745

#define MUL_TR_SERVICE_PORT 12345 
#define MUL_FAB_CLI_PORT 12346 

#define C_SERV_RCV_BUF_SZ 4096

struct mul_service
{
#define MAX_SERV_NAME_LEN 64
    char service_name[MAX_SERV_NAME_LEN];
    uint16_t serv_port;
    c_conn_t conn;
    bool is_client;
    struct event_base *ev_base;
    struct event *reconn_timer_event;
    struct event *valid_timer_event;
    void (*ev_cb)(void *service, struct cbuf *buf);
#define MUL_SERVICE_UP (0)
#define MUL_SERVICE_DOWN (1)
    void (*conn_update)(void *service, unsigned char conn_event);
    void *priv;
};
typedef struct mul_service mul_service_t;

static inline bool
mul_service_available(mul_service_t *service)
{
    return !service->conn.dead;
}

struct cbuf   *c_service_wait_response(mul_service_t *service);
int           c_service_timed_throw_resp(mul_service_t *service);
void          c_service_send(mul_service_t *service, struct cbuf *b);
void          c_service_reconnect(mul_service_t *service);
mul_service_t *mul_service_start(void *base, const char *name, uint16_t service_port,
                                void (*service_handler)(void *service, 
                                                        struct cbuf *msg));
mul_service_t *mul_service_instantiate(void *base, const char *name,
                                       uint16_t service_port,
                                       void (*conn_update)(void *service,
                                                           unsigned char conn_event),
                                       bool retry_conn);
void mul_service_destroy(mul_service_t *service);
bool mul_service_alive(mul_service_t *service);



#endif
