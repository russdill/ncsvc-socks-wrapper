#ifndef _LINUX_UNALIGNED_BE_BYTESHIFT_H
#define _LINUX_UNALIGNED_BE_BYTESHIFT_H

#include <sys/types.h>

static inline u_int16_t __get_unaligned_be16(const u_char *p)
{
	return p[0] << 8 | p[1];
}

static inline u_int32_t __get_unaligned_be32(const u_char *p)
{
	return p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
}

static inline u_int64_t __get_unaligned_be64(const u_char *p)
{
	return (u_int64_t)__get_unaligned_be32(p) << 32 |
	       __get_unaligned_be32(p + 4);
}

static inline void __put_unaligned_be16(u_int16_t val, u_char *p)
{
	*p++ = val >> 8;
	*p++ = val;
}

static inline void __put_unaligned_be32(u_int32_t val, u_char *p)
{
	__put_unaligned_be16(val >> 16, p);
	__put_unaligned_be16(val, p + 2);
}

static inline void __put_unaligned_be64(u_int64_t val, u_char *p)
{
	__put_unaligned_be32(val >> 32, p);
	__put_unaligned_be32(val, p + 4);
}

static inline u_int16_t get_unaligned_be16(const void *p)
{
	return __get_unaligned_be16((const u_char *)p);
}

static inline u_int32_t get_unaligned_be32(const void *p)
{
	return __get_unaligned_be32((const u_char *)p);
}

static inline u_int64_t get_unaligned_be64(const void *p)
{
	return __get_unaligned_be64((const u_char *)p);
}

static inline void put_unaligned_be16(u_int16_t val, void *p)
{
	__put_unaligned_be16(val, p);
}

static inline void put_unaligned_be32(u_int32_t val, void *p)
{
	__put_unaligned_be32(val, p);
}

static inline void put_unaligned_be64(u_int64_t val, void *p)
{
	__put_unaligned_be64(val, p);
}

#endif /* _LINUX_UNALIGNED_BE_BYTESHIFT_H */
