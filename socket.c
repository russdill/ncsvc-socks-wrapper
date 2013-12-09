
#undef _FORTIFY_SOURCE
#include <features.h>
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


int getsockopt(int fd, int level, int name, void *val, socklen_t *len)
{
	static int (*orig_getsockopt)(int, int, int, void*, socklen_t*);
	int ret;
	ASSIGN(getsockopt);
	ret = fd_getsockopt(fd, level, name, val, len);
	if (ret == FD_NONE)
		ret = orig_getsockopt(fd, level, name, val, len);
	return ret;
}

int setsockopt(int fd, int level, int name, const void *val, socklen_t len)
{
	static int (*orig_setsockopt)(int, int, int, const void*, socklen_t);
	int ret;
	ASSIGN(setsockopt);
	ret = fd_setsockopt(fd, level, name, val, len);
	if (ret == FD_NONE)
		ret = orig_setsockopt(fd, level, name, val, len);
	return ret;
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *len)
{
	static int (*orig_getsockname)(int, struct sockaddr*, socklen_t*);
	int ret;
	ASSIGN(getsockname);
	ret = fd_getsockname(fd, addr, len);
	if (ret == FD_NONE)
		ret = orig_getsockname(fd, addr, len);
	return ret;
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen)
{

	static ssize_t (*orig_recvfrom)(int, void*, size_t, int,
				struct sockaddr*, socklen_t*);
	int ret;
	ASSIGN(recvfrom);
	ret = fd_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	if (ret == FD_NONE)
		ret = orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
	dbg("%s(fd=%d) = %d\n", __func__, sockfd, ret);
	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
	static ssize_t (*orig_recv)(int, void*, size_t, int);
	int ret;
	ASSIGN(recv);
	ret = fd_recv(sockfd, buf, len, flags);
	if (ret == FD_NONE)
		ret = orig_recv(sockfd, buf, len, flags);
	dbg("%s(fd=%d) = %d\n", __func__, sockfd, ret);
	return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
	static ssize_t (*orig_send)(int, const void*, size_t, int);
	int ret;
	ASSIGN(send);
	ret = fd_send(sockfd, buf, len, flags);
	if (ret == FD_NONE)
		ret = orig_send(sockfd, buf, len, flags);
	dbg("%s(fd=%d) = %d\n", __func__, sockfd, ret);
	return ret;
}
