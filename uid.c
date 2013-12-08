#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include "dbg.h"
#include "preload.h"

int setuid(uid_t uid)
{
/*
	static int (*orig_setuid)(uid_t);
	ASSIGN(setuid);
*/
	dbg("%s(uid=%d)\n", __func__, uid);
	return 0; /*orig_setuid(uid);*/
}
