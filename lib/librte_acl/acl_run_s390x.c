/* SPDX-License-Identifier: BSD-3-Clause
 * (c) Copyright IBM Corp. 2018, 2018
 */

#include "acl_run_s390x.h"

int
rte_acl_classify_s390x(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t num, uint32_t categories)
{
	if (likely(num >= MAX_SEARCHES_S390X8))
		return search_s390x_8(ctx, data, results, num, categories);
	else if (num >= MAX_SEARCHES_S390X4)
		return search_s390x_4(ctx, data, results, num, categories);
	else
		return rte_acl_classify_scalar(ctx, data, results, num,
			categories);
}
