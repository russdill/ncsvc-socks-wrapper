#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "preload.h"
#include "dbg.h"
#include "fopen.h"

static int hosts_intercept(const char *path, const char *modes)
{
	return !strcmp(path, "/etc/jnpr-nc-hosts.new") ||
		!strcmp(path, "/etc/jnpr-nc-hosts.bak") ||
		!strcmp(path, "/etc/resolv.conf");
}

static FILE *hosts_fopen(struct fopen_info *info, const char *path,
							const char *mode)
{
	return tmpfile();
}

static int hosts_fclose(struct fopen_info *info)
{
	return 0;
}

static struct fopen_intercept hosts_fopen_intercept = {
	.intercept = hosts_intercept,
	.fopen = hosts_fopen,
	.fclose = hosts_fclose,
};

__attribute__((constructor))
static void resolv_init(void)
{
	fopen_add_intercept(&hosts_fopen_intercept);
}
