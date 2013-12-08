#ifndef __FOPEN_H__
#define __FOPEN_H__

#include <stdio.h>

#include "list.h"

struct fopen_info;

struct fopen_intercept {
	int (*intercept)(const char*, const char*);
	FILE *(*fopen)(struct fopen_info*, const char*, const char*);
	int (*fclose)(struct fopen_info*);
	struct list_head node;
};

struct fopen_info {
	struct fopen_intercept *intercept;
	FILE *(*orig_fopen)(const char *filename, const char *modes);
	FILE *fp;

	void *ctx;
	struct list_head node;
};

void fopen_add_intercept(const struct fopen_intercept *fi);

#endif
