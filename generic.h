#ifndef _LINUX_UNALIGNED_GENERIC_H
#define _LINUX_UNALIGNED_GENERIC_H

/*
 * Cause a link-time error if we try an unaligned access other than
 * 1,2,4 or 8 bytes long
 */
extern void __bad_unaligned_access_size(void);

#define __get_unaligned_le(ptr) ((typeof(*(ptr)))({			\
	__builtin_choose_expr(sizeof(*(ptr)) == 1, *(ptr),			\
	__builtin_choose_expr(sizeof(*(ptr)) == 2, get_unaligned_le16((ptr)),	\
	__builtin_choose_expr(sizeof(*(ptr)) == 4, get_unaligned_le32((ptr)),	\
	__builtin_choose_expr(sizeof(*(ptr)) == 8, get_unaligned_le64((ptr)),	\
	__bad_unaligned_access_size()))));					\
	}))

#define __get_unaligned_be(ptr) ((typeof(*(ptr)))({			\
	__builtin_choose_expr(sizeof(*(ptr)) == 1, *(ptr),			\
	__builtin_choose_expr(sizeof(*(ptr)) == 2, get_unaligned_be16((ptr)),	\
	__builtin_choose_expr(sizeof(*(ptr)) == 4, get_unaligned_be32((ptr)),	\
	__builtin_choose_expr(sizeof(*(ptr)) == 8, get_unaligned_be64((ptr)),	\
	__bad_unaligned_access_size()))));					\
	}))

#define __put_unaligned_le(val, ptr) ({					\
	void *__gu_p = (ptr);						\
	switch (sizeof(*(ptr))) {					\
	case 1:								\
		*(u_char *)__gu_p = (u_char)(val);			\
		break;							\
	case 2:								\
		put_unaligned_le16((u_int16_t)(val), __gu_p);		\
		break;							\
	case 4:								\
		put_unaligned_le32((u_int32_t)(val), __gu_p);		\
		break;							\
	case 8:								\
		put_unaligned_le64((u_int64_t)(val), __gu_p);		\
		break;							\
	default:							\
		__bad_unaligned_access_size();				\
		break;							\
	}								\
	(void)0; })

#define __put_unaligned_be(val, ptr) ({					\
	void *__gu_p = (ptr);						\
	switch (sizeof(*(ptr))) {					\
	case 1:								\
		*(u_char *)__gu_p = (u_char)(val);			\
		break;							\
	case 2:								\
		put_unaligned_be16((u_int16_t)(val), __gu_p);		\
		break;							\
	case 4:								\
		put_unaligned_be32((u_int32_t)(val), __gu_p);		\
		break;							\
	case 8:								\
		put_unaligned_be64((u_int64_t)(val), __gu_p);		\
		break;							\
	default:							\
		__bad_unaligned_access_size();				\
		break;							\
	}								\
	(void)0; })

#endif /* _LINUX_UNALIGNED_GENERIC_H */
