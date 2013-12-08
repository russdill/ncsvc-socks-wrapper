#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>

#include "dbg.h"
#include "preload.h"
#include "fd_info.h"

int open(const char *file, int oflag, ...)
{
	static int (*orig_open)(const char *file, int oflag, ...);
	int ret;
	ASSIGN(open);
	if (oflag & O_CREAT) {
		mode_t mode;
		va_list ap;
		va_start(ap, oflag);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		ret = fd_open(file);
		if (ret == FD_NONE)
			ret = orig_open(file, oflag, mode);
		dbg("%s(file=%s, oflag=%d, mode=0%03o) = %d\n", __func__, file,
					oflag, mode, ret);
	} else {
		ret = fd_open(file);
		if (ret == FD_NONE)
			ret = orig_open(file, oflag);
		dbg("%s(file=%s, oflag=%d) = %d\n", __func__, file, oflag, ret);
	}
	return ret;
}


int real_close(int fd)
{
	static int (*orig_close)(int fd);
	ASSIGN(close);
	return orig_close(fd);
}

int close(int fd)
{
	dbg("%s(%d)\n", __func__, fd);
	fd_close(fd);
	return real_close(fd);
}

int __fxstat(int ver, int fd, struct stat *stat_buf)
{
	static int (*orig___fxstat)(int ver, int fd, struct stat *stat_buf);
	int ret;
	ASSIGN(__fxstat);
	ret = fd_fstat(fd, stat_buf);
	if (ret == FD_NONE)
		ret = orig___fxstat(ver, fd, stat_buf);

	dbg("%s(%d) = %d\n", __func__, fd, ret);
	return ret;
}

static LIST_HEAD(stat_intercepts);

struct stat_intercept {
	int (*stat)(const char *filename, struct stat *stat_buf);
	struct list_head node;
};

int __xstat(int ver, const char *filename, struct stat *stat_buf)
{
	static int (*orig___xstat)(int, const char*, struct stat*);
	struct stat_intercept *statx;
	int ret;

	ASSIGN(__xstat);
	dbg("%s(filename=%s, stat_buf)\n", __func__, filename);
	list_for_each_entry(statx, &stat_intercepts, node) {
		ret = statx->stat(filename, stat_buf);
		if (ret != FD_NONE)
			return ret;
	}
	return orig___xstat(ver, filename, stat_buf);
}

void stat_add_intercept(int (*stat)(const char*, struct stat*))
{
	struct stat_intercept *statx;

	statx = malloc(sizeof(*statx));
	statx->stat = stat;
	list_add(&statx->node, &stat_intercepts);
}
