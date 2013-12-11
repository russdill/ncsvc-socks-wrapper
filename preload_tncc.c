#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "dbg.h"
#include "fd_info.h"
#include "preload.h"

struct tncc_info {
	socklen_t len;
	struct sockaddr addr[];
};

static ssize_t tncc_sub_recv(struct fd_info *info, void *buf, size_t len, int flags)
{
	dbg("%s\n", __func__);
	return read(info->fd, buf, len);
}

static ssize_t tncc_sub_send(struct fd_info *info, const void *buf, size_t len, int flags)
{
	dbg("%s\n", __func__);
	return write(0, buf, len);
}

static struct fd_listener tncc_sub_listener = {
	.recv = tncc_sub_recv,
	.send = tncc_sub_send,
};

static int tncc_socket(struct fd_info *info, int domain, int type, int protocol)
{
	if (domain != AF_INET && domain != AF_INET6)
		return FD_NONE;
	dbg("%s\n", __func__);
	return real_socket(domain, type, protocol);
}

static int tncc_bind(struct fd_info *info, const struct sockaddr *addr, socklen_t len)
{
	struct tncc_info *tinfo;

	dbg("%s\n", __func__);
	tinfo = malloc(sizeof(*tinfo) + len);
	memcpy(&tinfo->addr[0], addr, len);
	tinfo->len = len;
	info->ctx = tinfo;

	return 0;
}

static int tncc_listen(struct fd_info *info, int n)
{
	/*
	 * stdin is the socketpair passed to us. Just return a copy of that.
	 * When its ready for reading, the app will call accept
	 */
	dbg("%s\n", __func__);
	real_close(info->fd);
	real_dup2(0, info->fd);

	return 0;
}

static int tncc_accept(struct fd_info *info, struct sockaddr *addr, socklen_t *len)
{
	int fds[2];
	int ret;
	struct tncc_info *tinfo = info->ctx;
	char buf[1024];

	dbg("%s(%d, ..., %d)\n", __func__, info->fd, tinfo->len);
	memcpy(addr, &tinfo->addr[0], tinfo->len);
	*len = tinfo->len;

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
		dbg("%s: AF_INET\n", __func__);
		addr_in->sin_addr.s_addr = INADDR_LOOPBACK;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *) addr;
		static const unsigned char mapped_ipv4_localhost[] =
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };
		dbg("%s: AF_INET6\n", __func__);
		memcpy(&addr_in->sin6_addr.s6_addr, mapped_ipv4_localhost, 16);
	}

	ret = socketpair(AF_LOCAL, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, fds);
	if (ret < 0) {
		dbg("%s: socketpair failed\n", __func__);
		return ret;
	}

	ret = recv(info->fd, buf, sizeof(buf), 0);
	if (ret < 0) {
		real_close(fds[0]);
		real_close(fds[1]);
		return ret;
	}

	ret = send(fds[0], buf, ret, 0);
	real_close(fds[0]);
	if (ret < 0) {
		real_close(fds[1]);
		return ret;
	}

	ret = fds[1];
	fd_grab(ret, &tncc_sub_listener);
	return ret;
}

static void tncc_close(struct fd_info *info)
{
	dbg("%s\n", __func__);
	free(info->ctx);
}

static struct fd_listener tncc_listener = {
	.socket = tncc_socket,
	.bind = tncc_bind,
	.listen = tncc_listen,
	.accept = tncc_accept,
	.close = tncc_close,
};

/* "hide" stdin */
static int stdin_getsockname(struct fd_info *info, struct sockaddr *addr, socklen_t *addrlen)
{
	errno = ENOTSOCK;
	return -1;
}

static struct fd_listener stdin_listener = {
	.getsockname = stdin_getsockname,
};

__attribute__((constructor))
static void tncc_init(void)
{
	fd_grab(0, &stdin_listener);
	fd_listener_add(&tncc_listener);
}

