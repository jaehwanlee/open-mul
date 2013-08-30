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
    unsigned long nofree;
    unsigned long cloned;
    unsigned long res;
};

struct cbuf_head
{
    size_t len;
    struct cbuf *next;
};

#define CBUF_SZ             (sizeof(struct cbuf))
#define CBUF_BLK_ALIGN_SZ  (64)
#define CBUF_ALIGN_SZ(len) (((len) + (CBUF_BLK_ALIGN_SZ-1))&(~(CBUF_BLK_ALIGN_SZ-1)))
#define CBUF_DATA(b) ((void *)(b->data))

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
struct cbuf *cbuf_realloc_tailroom(struct cbuf *b, size_t room, int do_free);
struct cbuf *cbuf_realloc_headroom(struct cbuf *b, size_t room, int do_free);
void *cbuf_pull(struct cbuf *b, size_t len);
void *cbuf_push(struct cbuf *b, size_t len);
void free_cbuf(struct cbuf *b);
void cbuf_list_rm_inline_bufs(struct cbuf_head *head);

static inline void *
cbuf_put_inline(struct cbuf *b, size_t len)
{
    void *tmp = b->tail;

    assert(b->tail+len <= b->end);

    b->tail += len;
    b->len  += len;

    return tmp;
}

static inline void *
cbuf_pull_inline(struct cbuf *b, size_t len)
{
    assert(b->data + len <= b->end);

    b->data += len;
    b->len -= len;

    return (void *)(b->data);
}

static inline void *
cbuf_push_inline(struct cbuf *b, size_t len)
{
    assert(cbuf_headroom(b) >= len);

    b->data -= len;
    b->len += len;

    return (void *)(b->data);
}

static inline size_t
cbuf_headroom_inline(struct cbuf *b)
{
    int room;

    assert(b && b->data);

    room = (b->data - (unsigned char *)b) + CBUF_SZ;
    if (room < 0) return 0;

    return room;
}

static inline size_t
cbuf_tailroom(struct cbuf *b)
{
    return b->end - b->tail;
}

static inline
void cbuf_init_on_stack(struct cbuf *b, void *data, size_t alloc_len)
{
    b->data = (unsigned char *)(data);
    b->tail = (unsigned char *)(data) + alloc_len;
    b->end = b->tail;
    b->len = alloc_len;
    b->next = NULL;
    b->nofree = 1;
}

#endif
