#include <sys/types.h>
#include <sys/socket.h>

#include "dbg.h"
#include "preload.h"
#include "fd_info.h"

int real_socket(int domain, int type, int protocol)
{
	static int (*orig_socket)(int domain, int type, int protocol);
	ASSIGN(socket);
	return orig_socket(domain, type, protocol);
}

int accept(int fd, struct sockaddr *addr, socklen_t *addr_len)
{
	static int (*orig_accept)(int fd, struct sockaddr *addr, socklen_t*);
	int ret;
	ASSIGN(accept);
	ret = fd_accept(fd, addr, addr_len);
	if (ret == FD_NONE)
		ret = orig_accept(fd, addr, addr_len);
	dbg("%s(fd=%d) = %d\n", __func__, fd, ret);
	return ret;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	static int (*orig_bind)(int fd, const struct sockaddr *addr, socklen_t);
	int ret;
	ASSIGN(bind);
	ret = fd_bind(fd, addr, len);
	if (ret == FD_NONE)
		ret = orig_bind(fd, addr, len);
	dbg("%s(fd=%d) = %d\n", __func__, fd, ret);
	return ret;
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	static int (*orig_connect)(int fd, const struct sockaddr*, socklen_t);
	int ret;
	ASSIGN(connect);
	ret = fd_connect(fd, addr, len);
	if (ret == FD_NONE)
		ret = orig_connect(fd, addr, len);
	dbg("%s(fd=%d) = %d\n", __func__, fd, ret);
	return ret;
}

int listen(int fd, int n)
{
	static int (*orig_listen)(int fd, int n);
	int ret;
	ASSIGN(listen);
	ret = fd_listen(fd, n);
	if (ret == FD_NONE)
		ret = orig_listen(fd, n);
	dbg("%s(fd=%d) = %d\n", __func__, fd, ret);
	return ret;
}

int socket(int domain, int type, int protocol)
{
	int ret;
	ret = fd_socket(domain, type, protocol);
	if (ret == FD_NONE)
		ret = real_socket(domain, type, protocol);
	dbg("%s(domain=%d, type=%d, protocol=%d) = %d\n", __func__, domain,
							type, protocol, ret);
	return ret;
}

