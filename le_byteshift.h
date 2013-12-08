#ifndef _LINUX_UNALIGNED_LE_BYTESHIFT_H
#define _LINUX_UNALIGNED_LE_BYTESHIFT_H

#include <sys/types.h>

static inline u_int16_t __get_unaligned_le16(const u_char *p)
{
	return p[0] | p[1] << 8;
}

static inline u_int32_t __get_unaligned_le32(const u_char *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline u_int64_t __get_unaligned_le64(const u_char *p)
{
	return (u_int64_t)__get_unaligned_le32(p + 4) << 32 |
	       __get_unaligned_le32(p);
}

static inline void __put_unaligned_le16(u_int16_t val, u_char *p)
{
	*p++ = val;
	*p++ = val >> 8;
}

static inline void __put_unaligned_le32(u_int32_t val, u_char *p)
{
	__put_unaligned_le16(val >> 16, p + 2);
	__put_unaligned_le16(val, p);
}

static inline void __put_unaligned_le64(u_int64_t val, u_char *p)
{
	__put_unaligned_le32(val >> 32, p + 4);
	__put_unaligned_le32(val, p);
}

static inline u_int16_t get_unaligned_le16(const void *p)
{
	return __get_unaligned_le16((const u_char *)p);
}

static inline u_int32_t get_unaligned_le32(const void *p)
{
	return __get_unaligned_le32((const u_char *)p);
}

static inline u_int64_t get_unaligned_le64(const void *p)
{
	return __get_unaligned_le64((const u_char *)p);
}

static inline void put_unaligned_le16(u_int16_t val, void *p)
{
	__put_unaligned_le16(val, p);
}

static inline void put_unaligned_le32(u_int32_t val, void *p)
{
	__put_unaligned_le32(val, p);
}

static inline void put_unaligned_le64(u_int64_t val, void *p)
{
	__put_unaligned_le64(val, p);
}

#endif /* _LINUX_UNALIGNED_LE_BYTESHIFT_H */
