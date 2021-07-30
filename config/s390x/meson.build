# SPDX-License-Identifier: BSD-3-Clause
# (c) Copyright IBM Corp. 2019, 2020

if not dpdk_conf.get('RTE_ARCH_64')
	error('Only 64-bit compiles are supported for this platform type')
endif
dpdk_conf.set('RTE_ARCH', 's390x')
dpdk_conf.set('RTE_ARCH_S390X', 1)
dpdk_conf.set('RTE_MACHINE_CPUFLAG_ZARCH', 1)

dpdk_conf.set('RTE_FORCE_INTRINSICS', 1)

# overrides specific to s390x
dpdk_conf.set('RTE_MAX_LCORE', 256)
dpdk_conf.set('RTE_MAX_NUMA_NODES', 32)
dpdk_conf.set('RTE_CACHE_LINE_SIZE', 128)
