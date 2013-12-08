#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>

#include "dbg.h"
#include "preload.h"

static int ignore_fs;

int chmod(const char *file, mode_t mode)
{
	static int (*orig_chmod)(const char *file, mode_t mode);
	ASSIGN(chmod);
	dbg("%s(file=%s, mode=0%04o)\n", __func__, file, mode);
	return ignore_fs ? 0 : orig_chmod(file, mode);
}

int chown(const char *file, uid_t owner, gid_t group)
{
	static int (*orig_chown)(const char *file, uid_t owner, gid_t group);
	ASSIGN(chown);
	dbg("%s(file=%s, owner=%d, group=%d)\n", __func__, file, owner, group);
	return ignore_fs ? 0 : orig_chown(file, owner, group);
}

int mkdir(const char *path, mode_t mode)
{
	static int (*orig_mkdir)(const char *path, mode_t mode);
	ASSIGN(mkdir);
	dbg("%s(path=%s, mode=0%04o)\n", __func__, path, mode);
	return ignore_fs ? 0 : orig_mkdir(path, mode);
}

int unlink(const char *name)
{
	static int (*orig_unlink)(const char *name);
	ASSIGN(unlink);
	dbg("%s(%s)\n", __func__, name);
	return ignore_fs ? 0 : orig_unlink(name);
}

int rename(const char *old, const char *_new)
{
	static int (*orig_rename)(const char *old, const char *_new);
	ASSIGN(rename);
	return ignore_fs ? 0 : orig_rename(old, _new);
}

void set_ignore_fs(void)
{
	ignore_fs = 1;
}
