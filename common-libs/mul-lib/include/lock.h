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

#endif
