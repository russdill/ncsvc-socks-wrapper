#ifndef __FD_INFO_H__
#define __FD_INFO_H__

#include <sys/types.h>
#include <sys/socket.h>

#include "list.h"

#define FD_NONE		-5555

struct fd_info;
struct stat;

struct fd_listener {
	int (*open)(struct fd_info *info, const char *pathname);
	int (*socket)(struct fd_info *info, int domain, int type, int protocol);
	int (*ioctl)(struct fd_info *info, int request, void *argp);
	int (*accept)(struct fd_info*, struct sockaddr*, socklen_t*);
	int (*bind)(struct fd_info*, const struct sockaddr*, socklen_t);
	int (*fstat)(struct fd_info*, struct stat *stat_buf);
	int (*connect)(struct fd_info*, const struct sockaddr*, socklen_t);
	int (*listen)(struct fd_info*, int);
	void (*close)(struct fd_info *info);
	struct list_head node;
};

struct fd_info {
	struct fd_listener *listener;
	int fd;
	void *ctx;
	struct hlist_node node;
};

void fd_listener_add(const struct fd_listener *l);
int fd_open(const char *pathname);
int fd_socket(int domain, int type, int protocol);
int fd_ioctl(int fd, int request, char *argp);
int fd_accept(int fd, struct sockaddr *addr, socklen_t *addr_len);
int fd_bind(int fd, const struct sockaddr *addr, socklen_t len);
int fd_connect(int fd, const struct sockaddr *addr, socklen_t len);
int fd_listen(int fd, int n);
int fd_fstat(int fd, struct stat *stat_buf);
void fd_close(int fd);

int real_close(int fd);

struct stat;
void stat_add_intercept(int (*stat)(const char*, struct stat*));


#endif
