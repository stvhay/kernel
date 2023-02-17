/*
 * AES (Rijndael) cipher - encrypt
 *
 * Modifications to public domain implementation:
 * - cleanup
 * - use C pre-processor to make it easier to change S table access
 * - added option (AES_SMALL_TABLES) for reducing code size by about 8 kB at
 *   cost of reduced throughput (quite small difference on Pentium 4,
 *   10-25% when using -O1 or -O2 optimization)
 *
 * Copyright (c) 2003-2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "rtw_crypto_wrap.h"

#include "aes_i.h"


void * aes_encrypt_init(const u8 *key, size_t len)
{
	u32 *rk;
	int res;

	if (TEST_FAIL())
		return NULL;

	rk = os_malloc(AES_PRIV_SIZE);
	if (rk == NULL)
		return NULL;
	res = rijndaelKeySetupEnc(rk, key, len * 8);
	if (res < 0) {
		rtw_mfree(rk, AES_PRIV_SIZE);
		return NULL;
	}
	rk[AES_PRIV_NR_POS] = res;
	return rk;
}


void aes_encrypt_deinit(void *ctx)
{
	os_memset(ctx, 0, AES_PRIV_SIZE);
	rtw_mfree(ctx, AES_PRIV_SIZE);
}
