#include <libgen.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "dbg.h"
#include "fd_info.h"

static int log_fstat(struct fd_info *info, struct stat *st)
{
	st->st_uid = st->st_gid = 0x3e8;
	st->st_ino = 0xee6f8b;
	st->st_size = 0x995ead;
	st->st_dev = 0x806;
	st->st_blocks = 0x4cb8;
	st->st_blksize = 0x1000;
	st->st_mode = 0x81a4; // S_IFREG|0755;
	st->st_nlink = 1;
	st->st_atime = 0x528162a1;
	st->st_mtime = 0x52a3e2b6;
	st->st_ctime = 0x52a3e2b6;
	return 0;
}

static int log_stat(const char *pathname, struct stat *st)
{
	if (strcmp(basename((char *) pathname), "ncsvc.log"))
		return FD_NONE;

	dbg("%s\n", __func__);
	//memset(st, 0, sizeof(*st));
	st->st_uid = st->st_gid = 0x3e8;
	st->st_ino = 0xee6f8b;
	st->st_size = 0x995ead;
	st->st_dev = 0x806;
	st->st_blocks = 0x4cb8;
	st->st_blksize = 0x1000;
	st->st_mode = 0x81a4; // S_IFREG|0755;
	st->st_nlink = 1;
	st->st_atime = 0x528162a1;
	st->st_mtime = 0x52a3e2b6;
	st->st_ctime = 0x52a3e2b6;

/*
st_uid: 3e8
st_gid: 3e8
st_ino: ee6f8b
st_size: 995ead
st_blksize: 1000
st_mode: 81a4
st_nlink: 1
st_atime: 528162a1
st_mtime: 52a3e2b6
st_ctime: 52a3e2b6
st_dev: 806
st_rdev: 0
st_blocks: 4cb8
*/

	return 0;
}

static int log_open(struct fd_info *info, const char *pathname)
{
	if (!strcmp(basename((char *) pathname), "ncsvc.log")) {
		dbg("%s\n", __func__);
		return dup(1);
	} else
		return FD_NONE;
}

struct fd_listener log_listener = {
	.open = log_open,
	.fstat = log_fstat,
};

__attribute__((constructor))
static void log_init(void)
{
	fd_listener_add(&log_listener);
	stat_add_intercept(log_stat);
}

