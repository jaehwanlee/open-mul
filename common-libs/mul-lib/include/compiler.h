/*
 *  compiler.h: Compiler helpers and macros 
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
#ifndef __C_COMPILER_H__
#define __C_COMPILER_H__

#define barrier() __asm__ __volatile__("": : :"memory")

# define likely(x)  __builtin_expect(!!(x), 1)
# define unlikely(x)  __builtin_expect(!!(x), 0)

#define prefetch(x) __builtin_prefetch(x)

/* GCC Quirks */
#ifndef UNUSED
#define UNUSED __attribute__((unused))
#endif

#define __hot __attribute__((hot))
#define __fastpath __attribute__((__section__(".fastpath"))) 
#define __fastcall     __attribute__((regparm(3)))

#ifndef CPU_L1_CACHE_SZ
#define CPU_L1_CACHE_SZ (64)
#endif

#define __aligned __attribute__((aligned(CPU_L1_CACHE_SZ)))

#define mb() __sync_synchronize()
#define wmb() mb()
#define rmb() mb()

#define FETCH_ALWAYS(x) (*(volatile typeof(x) *)&(x))


#endif
