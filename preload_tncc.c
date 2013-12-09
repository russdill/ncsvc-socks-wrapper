#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include "dbg.h"
#include "fd_info.h"
#include "preload.h"

struct tncc_info {
	int fd;
	socklen_t len;
	struct sockaddr addr[];
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
	int fds[2];
	u_int16_t port = 1;
	struct tncc_info *tinfo;

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
		port = addr_in->sin_port;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *) addr;
		port = addr_in->sin6_port;
	}

	if (port)
		return FD_NONE;
	dbg("%s: start (%d)\n", __func__, info->fd);

	socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, fds);
	tinfo = malloc(sizeof(*tinfo) + len);
	tinfo->fd = fds[1];
	memcpy(&tinfo->addr[0], addr, len);
	tinfo->len = len;

	real_close(info->fd);
	dup2(fds[0], info->fd);
	real_close(fds[0]);
	info->ctx = tinfo;

	dbg("%s: end (%d)\n", __func__, info->fd);

	return 0;
}

static int tncc_listen(struct fd_info *info, int n)
{
	char ch = 0;
	int ret;
	struct tncc_info *tinfo = info->ctx;

	if (!tinfo)
		return FD_NONE;

	dbg("%s\n", __func__);
	ret = write(tinfo->fd, &ch, 1);
	if (ret < 0)
		dbg("%s: canary push failed\n", __func__);
	return ret == 1 ? 0 : ret;
}

static ssize_t kill_recv(struct fd_info *info, void *buf, size_t len, int flags)
{
	dbg("%s\n", __func__);
	return read(info->fd, buf, len);
}

static ssize_t kill_send(struct fd_info *info, const void *buf, size_t len, int flags)
{
	dbg("%s\n", __func__);
	return write(1, buf, len);
}

static void kill_close(struct fd_info *info)
{
	dbg("%s\n", __func__);
	exit(0);
}


static struct fd_listener kill_listener = {
	.recv = kill_recv,
	.send = kill_send,
	.close = kill_close,
};

static int tncc_accept(struct fd_info *info, struct sockaddr *addr, socklen_t *len)
{
	int ret;
	char ch;
	struct tncc_info *tinfo = info->ctx;

	if (!tinfo)
		return FD_NONE;

	dbg("%s\n", __func__);
	ret = read(info->fd, &ch, 1);
	if (ret < 0)
		return ret;

	ret = dup(0);
	if (ret < 0) {
		dbg("%s: dup failed\n", __func__);
		return ret;
	}
	memcpy(addr, &tinfo->addr[0], tinfo->len);

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
		addr_in->sin_addr.s_addr = INADDR_LOOPBACK;
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr_in = (struct sockaddr_in6 *) addr;
		static const unsigned char mapped_ipv4_localhost[] =
			{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1 };
		memcpy(&addr_in->sin6_addr.s6_addr, mapped_ipv4_localhost, 16);
	}


	fd_grab(ret, &kill_listener);
	return ret;
}

static struct fd_listener tncc_listener = {
	.socket = tncc_socket,
	.bind = tncc_bind,
	.listen = tncc_listen,
	.accept = tncc_accept,
};

__attribute__((constructor))
static void tncc_init(void)
{
	fd_listener_add(&tncc_listener);
}

