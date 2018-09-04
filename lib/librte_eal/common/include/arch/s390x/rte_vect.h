/* SPDX-License-Identifier: BSD-3-Clause
 * (c) Copyright IBM Corp. 2018, 2018
 */

#ifndef _RTE_VECT_S390X_H_
#define _RTE_VECT_S390X_H_

#include <vecintrin.h>
#include "generic/rte_vect.h"

#ifdef __cplusplus
extern "C" {
#endif

//typedef __m128i xmm_t; //x86
//typedef vector signed int xmm_t;  //ppc
//typedef int32x4_t xmm_t;  //arm
//typedef __int128 xmm_t;  //first attempt
typedef int xmm_t __attribute__ (( vector_size(4*sizeof(int)) ));

#define	XMM_SIZE	(sizeof(xmm_t))
#define	XMM_MASK	(XMM_SIZE - 1)

typedef union rte_xmm {
	xmm_t    x;
	uint8_t  u8[XMM_SIZE / sizeof(uint8_t)];
	uint16_t u16[XMM_SIZE / sizeof(uint16_t)];
	uint32_t u32[XMM_SIZE / sizeof(uint32_t)];
	uint64_t u64[XMM_SIZE / sizeof(uint64_t)];
	double   pd[XMM_SIZE / sizeof(double)];
} __attribute__((aligned(16))) rte_xmm_t;

#ifdef __cplusplus
}
#endif

#endif /* _RTE_VECT_S390X_H_ */
