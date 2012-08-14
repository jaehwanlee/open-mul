/*
 *  cbuf.h: Buffer handling infra 
 *  Copyright (C) 2012, Dipjyoti Saikia
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

#ifndef __C_BUF_H__
#define __C_BUF_H__

#include "atomic.h"

struct cbuf
{
    unsigned char *data;
    unsigned char *tail;
    unsigned char *end;
    size_t        len;
    struct cbuf   *next;
    unsigned long cloned:8;
    unsigned long res:24;
};

struct cbuf_head
{
    size_t len;
    struct cbuf *next;
};

#define CBUF_SZ             (sizeof(struct cbuf))
#define CBUF_BLK_ALIGN_SZ  (64)
#define CBUF_ALIGN_SZ(len) (((len) + (CBUF_BLK_ALIGN_SZ-1))&(~(CBUF_BLK_ALIGN_SZ-1)))

static inline int
cbuf_list_queue_len(struct cbuf_head *head)
{
    if (head) {
        return head->len;
    }
    return 0;
}

void cbuf_list_head_init(struct cbuf_head *head);
void cbuf_list_queue_tail(struct cbuf_head *head,
                     struct cbuf *buf);
void cbuf_list_queue(struct cbuf_head *head,
                     struct cbuf *buf);
struct cbuf *cbuf_list_dequeue(struct cbuf_head *head);
void cbuf_list_purge(struct cbuf_head *head);
struct cbuf *alloc_cbuf(size_t len);
void *cbuf_put(struct cbuf *b, size_t len);    
size_t cbuf_headroom(struct cbuf *b);
size_t cbuf_tailroom(struct cbuf *b);
struct cbuf *cbuf_realloc_tailroom(struct cbuf *b, size_t room, int do_free);
struct cbuf *cbuf_realloc_headroom(struct cbuf *b, size_t room, int do_free);
void *cbuf_pull(struct cbuf *b, size_t len);
void *cbuf_push(struct cbuf *b, size_t len);
void free_cbuf(struct cbuf *b);

#endif
