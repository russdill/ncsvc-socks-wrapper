/*
 * Cryptographic API.
 *
 * MD5 Message Digest Algorithm (RFC1321).
 *
 * Derived from cryptoapi implementation, originally based on the
 * public domain implementation written by Colin Plumb in 1993.
 *
 * Copyright (c) Cryptoapi developers.
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include <string.h>
#include "md5.h"

extern void MD5_Transform(u_int32_t *hash, u_int32_t *block);

int md5_init(struct md5_state *ctx)
{
	ctx->hash[0] = 0x67452301;
	ctx->hash[1] = 0xefcdab89;
	ctx->hash[2] = 0x98badcfe;
	ctx->hash[3] = 0x10325476;
	ctx->byte_count = 0;

	return 0;
}

int md5_update(struct md5_state *ctx, const u_char *data, unsigned int len)
{
	const u_int32_t avail = sizeof(ctx->block) - (ctx->byte_count & 0x3f);

	ctx->byte_count += len;

	if (avail > len) {
		memcpy((char *)ctx->block + (sizeof(ctx->block) - avail),
		       data, len);
		return 0;
	}

	memcpy((char *)ctx->block + (sizeof(ctx->block) - avail),
	       data, avail);

	MD5_Transform(ctx->hash, ctx->block);
	data += avail;
	len -= avail;

	while (len >= sizeof(ctx->block)) {
		memcpy(ctx->block, data, sizeof(ctx->block));
		MD5_Transform(ctx->hash, ctx->block);
		data += sizeof(ctx->block);
		len -= sizeof(ctx->block);
	}

	memcpy(ctx->block, data, len);

	return 0;
}

int md5_final(struct md5_state *ctx, u_char *out)
{
	const unsigned int offset = ctx->byte_count & 0x3f;
	char *p = (char *)ctx->block + offset;
	int padding = 56 - (offset + 1);

	*p++ = 0x80;
	if (padding < 0) {
		memset(p, 0x00, padding + 8);
		MD5_Transform(ctx->hash, ctx->block);
		p = (char *)ctx->block;
		padding = 56;
	}

	memset(p, 0, padding);
	ctx->block[14] = ctx->byte_count << 3;
	ctx->block[15] = ctx->byte_count >> 29;
	MD5_Transform(ctx->hash, ctx->block);
	memcpy(out, ctx->hash, sizeof(ctx->hash));
	memset(ctx, 0, sizeof(*ctx));

	return 0;
}
