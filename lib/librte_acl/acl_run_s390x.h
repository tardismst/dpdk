/* SPDX-License-Identifier: BSD-3-Clause
 * (c) Copyright IBM Corp. 2018, 2018
 */

#include "acl_run.h"
#include "acl_vect.h"

struct _s390x_acl_const {
	rte_xmm_t xmm_shuffle_input;
	rte_xmm_t xmm_index_mask;
	rte_xmm_t xmm_ones_16;
	rte_xmm_t range_base;
} s390x_acl_const  __attribute__((aligned(RTE_CACHE_LINE_SIZE))) = {
	{
		.u32 = {0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c}
	},
	{
		.u32 = {RTE_ACL_NODE_INDEX, RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX, RTE_ACL_NODE_INDEX}
	},
	{
		.u16 = {1, 1, 1, 1, 1, 1, 1, 1}
	},
	{
		.u32 = {0xffffff00, 0xffffff04, 0xffffff08, 0xffffff0c}
	},
};

/*
 * Resolve priority for multiple results (s390x version).
 * This consists comparing the priority of the current traversal with the
 * running set of results for the packet.
 * For each result, keep a running array of the result (rule number) and
 * its priority for each category.
 */
static inline void
resolve_priority_s390x(uint64_t transition, int n,
	const struct rte_acl_ctx *ctx, struct parms *parms,
	const struct rte_acl_match_results *p, uint32_t categories)
{
	typedef unsigned int vector_bool_int __attribute__ (( vector_size(4*sizeof(unsigned int)) ));
	uint32_t x;
	xmm_t results, priority, results1, priority1;
	vector_bool_int selector;
	xmm_t *saved_results, *saved_priority;

	for (x = 0; x < categories; x += RTE_ACL_RESULTS_MULTIPLIER) {

		saved_results = (xmm_t *)(&parms[n].cmplt->results[x]);
		saved_priority =
			(xmm_t *)(&parms[n].cmplt->priority[x]);

		/* get results and priorities for completed trie */
		results = *(const xmm_t *)&p[transition].results[x];
		priority = *(const xmm_t *)&p[transition].priority[x];

		/* if this is not the first completed trie */
		if (parms[n].cmplt->count != ctx->num_tries) {

			/* get running best results and their priorities */
			results1 = *saved_results;
			priority1 = *saved_priority;

			/* select results that are highest priority */
			selector = vec_cmpgt(priority1, priority);
			results = vec_sel(results, results1, selector);
			priority = vec_sel(priority, priority1,
				selector);
		}

		/* save running best results and their priorities */
		*saved_results = results;
		*saved_priority = priority;
	}
}

/*
 * Check for any match in 4 transitions
 */
static __rte_always_inline uint32_t
check_any_match_x4(uint64_t val[])
{
	return (val[0] | val[1] | val[2] | val[3]) & RTE_ACL_NODE_MATCH;
}

static __rte_always_inline void
acl_match_check_x4(int slot, const struct rte_acl_ctx *ctx, struct parms *parms,
	struct acl_flow_data *flows, uint64_t transitions[])
{
	while (check_any_match_x4(transitions)) {
		transitions[0] = acl_match_check(transitions[0], slot, ctx,
			parms, flows, resolve_priority_s390x);
		transitions[1] = acl_match_check(transitions[1], slot + 1, ctx,
			parms, flows, resolve_priority_s390x);
		transitions[2] = acl_match_check(transitions[2], slot + 2, ctx,
			parms, flows, resolve_priority_s390x);
		transitions[3] = acl_match_check(transitions[3], slot + 3, ctx,
			parms, flows, resolve_priority_s390x);
	}
}

/*
 * Process 4 transitions (in 2 XMM registers) in parallel
 */
static inline __attribute__((optimize("O2"))) xmm_t
transition4(xmm_t next_input, const uint64_t *trans,
	xmm_t *indices1, xmm_t *indices2)
{
	typedef unsigned int vector_bool_int __attribute__ (( vector_size(4*sizeof(unsigned int)) ));
	typedef char vector_signed_char __attribute__ (( vector_size(16*sizeof(char)) ));
	typedef unsigned char vector_unsigned_char __attribute__ (( vector_size(16*sizeof(unsigned char)) ));
	//typedef short vector_signed_short __attribute__ (( vector_size(8*sizeof(short)) ));
	//typedef unsigned long long vector_unsigned_long_long __attribute__ (( vector_size(2*sizeof(unsigned long long)) ));
	xmm_t addr, tr_lo, tr_hi;
	xmm_t in, node_type, r, t;
	xmm_t dfa_ofs, quad_ofs;
	xmm_t *index_mask, *tp;
	vector_bool_int dfa_msk;
	vector_signed_char zeroes = {};
	union {
		uint64_t d64[2];
		uint32_t d32[4];
	} v;

	/* Move low 32 into tr_lo and high 32 into tr_hi */
	tr_lo = (xmm_t){(*indices1)[0], (*indices1)[2],
			(*indices2)[0], (*indices2)[2]};
	tr_hi = (xmm_t){(*indices1)[1], (*indices1)[3],
			(*indices2)[1], (*indices2)[3]};

	 /* Calculate the address (array index) for all 4 transitions. */
	index_mask = (xmm_t *)&s390x_acl_const.xmm_index_mask.u32;
	t = vec_xor(*index_mask, *index_mask);
	in = vec_perm(next_input, (xmm_t){},
		*(vector_unsigned_char *)&s390x_acl_const.xmm_shuffle_input);

	/* Calc node type and node addr */
	node_type = vec_and(vec_nor(*index_mask, *index_mask), tr_lo);
	addr = vec_and(tr_lo, *index_mask);

	/* mask for DFA type(0) nodes */
	dfa_msk = vec_cmpeq(node_type, t);

	/* DFA calculations. */
	//r = vec_srl(in, (vector_bool_int){30, 30, 30, 30});
	r[0] = in[0] >> 30;
	r[1] = in[1] >> 30;
	r[2] = in[2] >> 30;
	r[3] = in[3] >> 30;

	tp = (xmm_t *)&s390x_acl_const.range_base.u32;
	r = r + *tp;
	//r = (xmm_t)vec_addc((vector_bool_int)r, (vector_bool_int)*tp); //needs to be unsigned int
	//t = vec_srl(in, (vector_bool_int){24, 24, 24, 24});
	t[0] = in[0] >> 24;
	t[1] = in[1] >> 24;
	t[2] = in[2] >> 24;
	t[3] = in[3] >> 24;

	r = vec_perm(tr_hi, (xmm_t){(uint16_t)0 << 16},
		(vector_unsigned_char)r);

	dfa_ofs = t - r;
	//dfa_ofs = (xmm_t)vec_subc((vector_bool_int)t, (vector_bool_int)r);

	/* QUAD/SINGLE caluclations. */
	t = (xmm_t)vec_cmpgt(in, tr_hi);
	t = (xmm_t)vec_sel(
		(vector_unsigned_char)vec_sel(
			(vector_unsigned_char)(
				(vector_unsigned_char)zeroes - (vector_unsigned_char)t),
			(vector_unsigned_char)t,
			(vector_unsigned_char)vec_cmpgt((vector_unsigned_char)t, (vector_unsigned_char)zeroes)), //needs to be unsigned
		(vector_unsigned_char)zeroes,
		(vector_unsigned_char)vec_cmpeq((vector_unsigned_char)t, (vector_unsigned_char)zeroes)); //needs to be unsigned

	char * ct = (char *)&t;
        short * st = (short*)&t;
        //do scalar calculation, no msum intrinsics on LoZ
	st[0]=ct[0]+ct[1];
	st[1]=ct[2]+ct[3];
	st[2]=ct[4]+ct[5];
	st[3]=ct[6]+ct[7];
	st[4]=ct[8]+ct[9];
	st[5]=ct[10]+ct[11];
	st[6]=ct[12]+ct[13];
	st[7]=ct[14]+ct[15];

	int * quad_ofs_int = (int *)&quad_ofs;

	quad_ofs_int[0]=st[0]+st[1];
        quad_ofs_int[1]=st[2]+st[3];
	quad_ofs_int[2]=st[4]+st[5];
	quad_ofs_int[3]=st[6]+st[7];

        //t = (xmm_t)vec_msum_u128((vector_unsigned_long_long)t,
	//	(vector_unsigned_long_long)t, (vector_unsigned_char){});
	//quad_ofs = (xmm_t)vec_msum_u128((vector_unsigned_long_long)t,
	//	*(vector_unsigned_long_long *)&s390x_acl_const.xmm_ones_16.u16,
	//	(vector_unsigned_char){});

	/* blend DFA and QUAD/SINGLE. */
	t = vec_sel(quad_ofs, dfa_ofs, dfa_msk);

	/* calculate address for next transitions. */
	addr = addr + t;
	//addr = (xmm_t)vec_addc((vector_bool_int)addr, (vector_bool_int)t);

	v.d64[0] = (uint64_t)trans[addr[0]];
	v.d64[1] = (uint64_t)trans[addr[1]];
	*indices1 = (xmm_t){v.d32[0], v.d32[1], v.d32[2], v.d32[3]};
	v.d64[0] = (uint64_t)trans[addr[2]];
	v.d64[1] = (uint64_t)trans[addr[3]];
	*indices2 = (xmm_t){v.d32[0], v.d32[1], v.d32[2], v.d32[3]};

	next_input[0] = next_input[0] >> CHAR_BIT;
	next_input[1] = next_input[1] >> CHAR_BIT;
	next_input[2] = next_input[2] >> CHAR_BIT;
	next_input[3] = next_input[3] >> CHAR_BIT;

	return next_input;

	//return vec_srl(next_input,
	//	(vector_bool_int){CHAR_BIT, CHAR_BIT, CHAR_BIT, CHAR_BIT});
}

/*
 * Execute trie traversal with 8 traversals in parallel
 */
static inline int
search_s390x_8(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t total_packets, uint32_t categories)
{
	int n;
	struct acl_flow_data flows;
	uint64_t index_array[MAX_SEARCHES_S390X8];
	struct completion cmplt[MAX_SEARCHES_S390X8];
	struct parms parms[MAX_SEARCHES_S390X8];
	xmm_t input0, input1;

	acl_set_flow(&flows, cmplt, RTE_DIM(cmplt), data, results,
		total_packets, categories, ctx->trans_table);

	for (n = 0; n < MAX_SEARCHES_S390X8; n++) {
		cmplt[n].count = 0;
		index_array[n] = acl_start_next_trie(&flows, parms, n, ctx);
	}

	 /* Check for any matches. */
	acl_match_check_x4(0, ctx, parms, &flows, (uint64_t *)&index_array[0]);
	acl_match_check_x4(4, ctx, parms, &flows, (uint64_t *)&index_array[4]);

	while (flows.started > 0) {

		/* Gather 4 bytes of input data for each stream. */
		input0 = (xmm_t){GET_NEXT_4BYTES(parms, 0),
				GET_NEXT_4BYTES(parms, 1),
				GET_NEXT_4BYTES(parms, 2),
				GET_NEXT_4BYTES(parms, 3)};

		input1 = (xmm_t){GET_NEXT_4BYTES(parms, 4),
				GET_NEXT_4BYTES(parms, 5),
				GET_NEXT_4BYTES(parms, 6),
				GET_NEXT_4BYTES(parms, 7)};

		 /* Process the 4 bytes of input on each stream. */

		input0 = transition4(input0, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input1 = transition4(input1, flows.trans,
			(xmm_t *)&index_array[4], (xmm_t *)&index_array[6]);

		input0 = transition4(input0, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input1 = transition4(input1, flows.trans,
			(xmm_t *)&index_array[4], (xmm_t *)&index_array[6]);

		input0 = transition4(input0, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input1 = transition4(input1, flows.trans,
			(xmm_t *)&index_array[4], (xmm_t *)&index_array[6]);

		input0 = transition4(input0, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input1 = transition4(input1, flows.trans,
			(xmm_t *)&index_array[4], (xmm_t *)&index_array[6]);

		 /* Check for any matches. */
		acl_match_check_x4(0, ctx, parms, &flows,
			(uint64_t *)&index_array[0]);
		acl_match_check_x4(4, ctx, parms, &flows,
			(uint64_t *)&index_array[4]);
	}

	return 0;
}

/*
 * Execute trie traversal with 4 traversals in parallel
 */
static inline int
search_s390x_4(const struct rte_acl_ctx *ctx, const uint8_t **data,
	 uint32_t *results, int total_packets, uint32_t categories)
{
	int n;
	struct acl_flow_data flows;
	uint64_t index_array[MAX_SEARCHES_S390X4];
	struct completion cmplt[MAX_SEARCHES_S390X4];
	struct parms parms[MAX_SEARCHES_S390X4];
	xmm_t input;

	acl_set_flow(&flows, cmplt, RTE_DIM(cmplt), data, results,
		total_packets, categories, ctx->trans_table);

	for (n = 0; n < MAX_SEARCHES_S390X4; n++) {
		cmplt[n].count = 0;
		index_array[n] = acl_start_next_trie(&flows, parms, n, ctx);
	}

	/* Check for any matches. */
	acl_match_check_x4(0, ctx, parms, &flows, index_array);

	while (flows.started > 0) {

		/* Gather 4 bytes of input data for each stream. */
		input = (xmm_t){GET_NEXT_4BYTES(parms, 0),
				GET_NEXT_4BYTES(parms, 1),
				GET_NEXT_4BYTES(parms, 2),
				GET_NEXT_4BYTES(parms, 3)};

		/* Process the 4 bytes of input on each stream. */
		input = transition4(input, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input = transition4(input, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input = transition4(input, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);
		input = transition4(input, flows.trans,
			(xmm_t *)&index_array[0], (xmm_t *)&index_array[2]);

		/* Check for any matches. */
		acl_match_check_x4(0, ctx, parms, &flows, index_array);
	}

	return 0;
}
