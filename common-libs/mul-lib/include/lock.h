/*
 *  lock.h: Common lock functions
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
#ifndef __LOCK_H__
#define __LOCK_H__

#include <pthread.h>

typedef pthread_mutex_t  c_mutex_lock_t;
typedef pthread_rwlock_t c_rw_lock_t;

static inline void
c_rw_lock_init(c_rw_lock_t *lock)
{
    pthread_rwlock_init(lock, NULL);
}

static inline void
c_rw_lock_destroy(c_rw_lock_t *lock)
{
    pthread_rwlock_destroy(lock);
}

//#define LOCK_DEBUG

#ifdef LOCK_DEBUG
static inline void
__c_rd_lock(c_rw_lock_t *lock)
{
    printf("%s: Enter \n", __FUNCTION__);
    pthread_rwlock_rdlock(lock);
}

#define c_rd_lock(lock) \
do { \
    printf ("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__); \
    __c_rd_lock(lock); \
}while(0)



static inline void
__c_rd_unlock(c_rw_lock_t *lock)
{
    pthread_rwlock_unlock(lock);
    printf("%s: Exit \n", __FUNCTION__);
}

#define c_rd_unlock(lock) \
do { \
    printf ("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__); \
    __c_rd_unlock(lock); \
}while(0)


static inline void
__c_wr_lock(c_rw_lock_t *lock)
{
    printf("%s: Enter \n", __FUNCTION__);
    pthread_rwlock_wrlock(lock);
}

#define c_wr_lock(lock) \
do { \
    printf ("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__); \
    __c_wr_lock(lock); \
}while(0)

static inline void
__c_wr_unlock(c_rw_lock_t *lock)
{
    pthread_rwlock_unlock(lock);
    printf("%s: Exit \n", __FUNCTION__);
}

#define c_wr_unlock(lock) \
do { \
    printf ("%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__); \
    __c_wr_unlock(lock); \
}while(0)

static inline int
c_wr_trylock(c_rw_lock_t *lock)
{
    return pthread_rwlock_trywrlock(lock);
}

static inline int
c_rd_trylock(c_rw_lock_t *lock)
{
    return pthread_rwlock_tryrdlock(lock);
}

#else

static inline void
c_rd_lock(c_rw_lock_t *lock)
{
    pthread_rwlock_rdlock(lock);
}

static inline void
c_rd_unlock(c_rw_lock_t *lock)
{
    pthread_rwlock_unlock(lock);
}

static inline void
c_wr_lock(c_rw_lock_t *lock)
{
    pthread_rwlock_wrlock(lock);
}

static inline void
c_wr_unlock(c_rw_lock_t *lock)
{
    pthread_rwlock_unlock(lock);
}

static inline int
c_wr_trylock(c_rw_lock_t *lock)
{
    return pthread_rwlock_trywrlock(lock);
}

static inline int
c_rd_trylock(c_rw_lock_t *lock)
{
    return pthread_rwlock_tryrdlock(lock);
}

#endif

typedef struct c_seq_lock
{
    unsigned int seq;
    c_rw_lock_t  wr_lock;
}c_seq_lock_t;

static inline void
c_seq_lock_init(c_seq_lock_t *lock)
{
    lock->seq = 0;
    c_rw_lock_init(&lock->wr_lock);
}

static inline unsigned int
c_seq_rd_lock(c_seq_lock_t *seq_lock)
{
    unsigned int seq;

    while(1) {
        seq = FETCH_ALWAYS(seq_lock->seq);
        if (!(seq & 0x1)) break;
    }

    mb();

    return seq;
}

static inline unsigned int
c_seq_rd_unlock(c_seq_lock_t *seq_lock, unsigned int seq)
{
    mb();
    if (seq_lock->seq != seq) return 1;
    return 0;
}

static inline void
c_seq_wr_lock(c_seq_lock_t *seq_lock)
{
    c_wr_lock(&seq_lock->wr_lock);
    seq_lock->seq++;
    mb();
}

static inline void
c_seq_wr_unlock(c_seq_lock_t *seq_lock)
{
    mb();
    seq_lock->seq++;
    c_wr_unlock(&seq_lock->wr_lock);
}

#endif
