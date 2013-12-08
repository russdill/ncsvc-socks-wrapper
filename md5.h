#ifndef __MD5_H__
#define __MD5_H__

#include <sys/types.h>

#define MD5_DIGEST_SIZE		16
#define MD5_HMAC_BLOCK_SIZE	64
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4

struct md5_state {
	u_int32_t hash[MD5_HASH_WORDS];
	u_int32_t block[MD5_BLOCK_WORDS];
	unsigned long byte_count;
};

int md5_init(struct md5_state *mctx);
int md5_update(struct md5_state *mctx, const u_char *data, unsigned int len);
int md5_final(struct md5_state *mctx, u_char *out);

#endif
