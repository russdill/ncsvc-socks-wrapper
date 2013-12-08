#ifndef _LINUX_UNALIGNED_PACKED_STRUCT_H
#define _LINUX_UNALIGNED_PACKED_STRUCT_H

#define __packed __attribute__((__packed__))

struct __una_u16 { u_int16_t x; } __packed;
struct __una_u32 { u_int32_t x; } __packed;
struct __una_u64 { u_int64_t x; } __packed;

static inline u_int16_t __get_unaligned_cpu16(const void *p)
{
	const struct __una_u16 *ptr = (const struct __una_u16 *)p;
	return ptr->x;
}

static inline u_int32_t __get_unaligned_cpu32(const void *p)
{
	const struct __una_u32 *ptr = (const struct __una_u32 *)p;
	return ptr->x;
}

static inline u_int64_t __get_unaligned_cpu64(const void *p)
{
	const struct __una_u64 *ptr = (const struct __una_u64 *)p;
	return ptr->x;
}

static inline void __put_unaligned_cpu16(u_int16_t val, void *p)
{
	struct __una_u16 *ptr = (struct __una_u16 *)p;
	ptr->x = val;
}

static inline void __put_unaligned_cpu32(u_int32_t val, void *p)
{
	struct __una_u32 *ptr = (struct __una_u32 *)p;
	ptr->x = val;
}

static inline void __put_unaligned_cpu64(u_int64_t val, void *p)
{
	struct __una_u64 *ptr = (struct __una_u64 *)p;
	ptr->x = val;
}

#endif /* _LINUX_UNALIGNED_PACKED_STRUCT_H */
