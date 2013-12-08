#ifndef _LINUX_UNALIGNED_BE_STRUCT_H
#define _LINUX_UNALIGNED_BE_STRUCT_H

#include "packed_struct.h"

static inline u_int16_t get_unaligned_be16(const void *p)
{
	return __get_unaligned_cpu16((const u8 *)p);
}

static inline u_int32_t get_unaligned_be32(const void *p)
{
	return __get_unaligned_cpu32((const u8 *)p);
}

static inline u_int64_t get_unaligned_be64(const void *p)
{
	return __get_unaligned_cpu64((const u8 *)p);
}

static inline void put_unaligned_be16(u_int16_t val, void *p)
{
	__put_unaligned_cpu16(val, p);
}

static inline void put_unaligned_be32(u_int32_t val, void *p)
{
	__put_unaligned_cpu32(val, p);
}

static inline void put_unaligned_be64(u_int64_t val, void *p)
{
	__put_unaligned_cpu64(val, p);
}

#endif /* _LINUX_UNALIGNED_BE_STRUCT_H */
