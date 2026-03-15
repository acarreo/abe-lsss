///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   zelement.h
///
/// \brief  Base class definition for ZTK groups (EC/pairings)
///
/// \author J. Ayo Akinyele
///

#ifndef __ZELEMENT_H__
#define __ZELEMENT_H__

#include <relic.h>

/* BEGIN RELIC macro definitions (default if BN_WITH_OEPNSSL not set) */
typedef bn_t bignum_t;

#define zmbignum_free(b)                bn_free(b)
#define zmbignum_safe_free(b)           if (b != NULL) free(b)

#define zmbignum_fromHex(b, str, len)   bn_read_str(b, str, len, 16)
#define zmbignum_fromBin(b, ustr, len)  bn_read_bin(b, ustr, len)
#define zmbignum_toBin(b, str, len)     bn_write_bin(str, len, b)

#define zmbignum_setuint(b, x)          bn_set_dig(b, x)
#define zmbignum_setzero(a)             bn_zero(a)
#define zmbignum_is_zero(b)             bn_is_zero(b)
#define zmbignum_is_one(b)              bn_is_one(b)
#define zmbignum_sign(a)                bn_sign(a)
#define zmbignum_cmp(a, b)              bn_cmp(a, b)
#define zmbignum_countbytes(a)          bn_size_bin(a)

#define zmbignum_copy(to, from)         bn_copy(to, from)
#define zmbignum_rand(a, o)             bn_rand_mod(a, o)
#define zmbignum_mod(x, o)              bn_mod(x, x, o)
#define zmbignum_add(r, x, y, o)        {bn_add(r, x, y); bn_mod(r, r, o);}
#define zmbignum_sub(r, x, y)           bn_sub(r, x, y)
#define zmbignum_sub_order(r, x, y, o)  {bn_sub(r, x, y); bn_mod(r, r, o);}
#define zmbignum_mul(r, x, y, o)        {bn_mul(r, x, y); bn_mod(r, r, o);}
#define zmbignum_div(r, x, y, o)        {bn_mod_inv(r, y, o); zmbignum_mul(r, r, x, o);}
#define zmbignum_exp(r, x, y, o)        bn_mxp(r, x, y, o)
#define zmbignum_lshift(r, a, n)        bn_lsh(r, a, n)
#define zmbignum_rshift(r, a, n)        bn_rsh(r, a, n)
#define zmbignum_negate(b, o)           {bn_neg(b, b); bn_mod(b, b, o);}
#define zmbignum_mod_inv(a, b, o)       bn_mod_inv(a, b, o)

#define bn_inits(b)                     {bn_null(b); bn_new(b);}
#define bn_is_one(a)                    (((a->used == 1) && (a->dp[0] == 1)))

#define BN_CMP_LT                       RLC_LT
#define BN_CMP_EQ                       RLC_EQ
#define BN_CMP_GT                       RLC_GT

int static inline zmcheck_error() {
  ctx_t *ctx = core_get();
  if (ctx != NULL) return (ctx->code == 1);
  return -1;
}

void static inline zmbignum_init(bignum_t *b) {
  bn_null(*b);
  bn_new(*b);
}

/* EC helps functions */
#define g1_init(p)                      g1_null(p); g1_new(p);
#define g2_init(p)                      g2_null(p); g2_new(p);
#define gt_init(p)                      gt_null(p); gt_new(p);




#endif /* ifdef __ZELEMENT_H__ */
