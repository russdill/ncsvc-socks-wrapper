#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dbg.h"
#include "preload.h"
#include "list.h"
#include "fopen.h"

static LIST_HEAD(intercepts);
static LIST_HEAD(finfos);

void fopen_add_intercept(const struct fopen_intercept *fi)
{
	struct fopen_intercept *ni;
	ni = malloc(sizeof(*ni));
	memcpy(ni, fi, sizeof(*ni));
	list_add(&ni->node, &intercepts);
}

FILE *fopen(const char *filename, const char *modes)
{
	static FILE *(*orig_fopen)(const char *filename, const char *modes);
	struct fopen_intercept *fi;

	ASSIGN(fopen);

	dbg("%s(filename=%s, modes=%s)\n", __func__, filename, modes);
	list_for_each_entry(fi, &intercepts, node)
		if (fi->intercept(filename, modes)) {
			struct fopen_info *info;
			FILE *fp;
			info = malloc(sizeof(*info));
			memset(info, 0, sizeof(*info));
			info->orig_fopen = orig_fopen;
			info->intercept = fi;
			info->fp = fp = fi->fopen(info, filename, modes);
			if (fp)
				list_add(&info->node, &finfos);
			else
				free(info);
			return fp;
		}
	return orig_fopen(filename, modes);
}

FILE *fopen64(const char *filename, const char *modes)
{
	static FILE *(*orig_fopen64)(const char *filename, const char *modes);
	ASSIGN(fopen64);
	dbg("%s(filename=%s, modes=%s)\n", __func__, filename, modes);
	return orig_fopen64(filename, modes);
}

int fclose(FILE *fp)
{
	static int (*orig_fclose)(FILE *fp);
	struct fopen_info *info;
	ASSIGN(fclose);
	dbg("%s\n", __func__);
	list_for_each_entry(info, &finfos, node)
		if (info->fp == fp) {
			if (info->intercept->fclose)
				info->intercept->fclose(info);
			break;
		}
	return orig_fclose(fp);
}
