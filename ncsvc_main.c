#include <string.h>
#include <libgen.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "md5.h"
#include "preload.h"
#include "dbg.h"

static void print_usage(void)
{
	printf(
"usage: ncsvc -h host -c cookies -f cert_file [-l log_level] [-L log_level] [-U sign_in_url] [-p socks port]\n"
"       ncsvc -v\n"
"    log_level : 0 : Log Critical messages only\n"
"                1 : Log Critital and Error messages\n"
"                2 : Log Critital, Error and Warning messages\n"
"                3 : Log Critital, Error, Warning and Info messages(default)\n"
"                4 : Log All Verbose messages\n"
"                5 : Log All messages\n"
	);
}

char *ncsvc_host = NULL;
char *ncsvc_cookie = NULL;
int ncsvc_log_level = 3;
char *ncsvc_url = NULL;
int ncsvc_socks_port = 1080;
char *ncsvc_md5sum;

int __libc_start_main(int (*main) (int, char * *, char * *), int argc, char * * argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
	static int (*orig___libc_start_main)(int (*main) (int, char * *, char * *), int argc, char * * argv, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end));
	struct md5_state ctx;
	char *cert_file = NULL;
	FILE *fp;
	char *argv_empty[2];
	u_char buffer[256];
	u_char hash[MD5_HASH_WORDS*4];
	char md5sum[MD5_HASH_WORDS*4*2+1];
	int c;
	int i;
	int len;

	/* valgrind */
	if (strcmp(basename(argv[0]), "ncsvc"))
		return orig___libc_start_main(main, 1, argv, init, fini, rtld_fini, stack_end);

	opterr = 0;

	dbg("%s\n", __func__);

	while ((c = getopt(argc, argv, "h:c:f:l:U:p:")) != -1) {
		switch (c) {
		case 'h':
			ncsvc_host = optarg;
			break;
		case 'c':
			ncsvc_cookie = optarg;
			break;
		case 'f':
			cert_file = optarg;
			break;
		case 'l':
			ncsvc_log_level = atoi(optarg);
			break;
		case 'U':
			ncsvc_url = optarg;
			break;
		case 'p':
			ncsvc_socks_port = atoi(optarg);
			break;
		default:
			print_usage();
			exit(1);
		}
	}

	if (!ncsvc_host || !ncsvc_cookie || !cert_file) {
		print_usage();
		exit(1);
	}

	fp = fopen(cert_file, "r");
	if (!fp) {
		perror(cert_file);
		exit(1);
	}

	md5_init(&ctx);
	while ((len = fread(buffer, 1, sizeof(buffer), fp)))
		md5_update(&ctx, buffer, len);
	fclose(fp);
	md5_final(&ctx, hash);
	for (i = 0; i < sizeof(hash); i++)
		sprintf(md5sum + i*2, "%.2x", hash[i]);
	ncsvc_md5sum = strdup(md5sum);
	dbg("certificate md5sum: %s\n", ncsvc_md5sum);

	ASSIGN(__libc_start_main);
	argv_empty[0] = argv[0];
	argv_empty[1] = NULL;
	return orig___libc_start_main(main, 1, argv_empty, init, fini, rtld_fini, stack_end);
}
