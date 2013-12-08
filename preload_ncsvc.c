#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <linux/if_tun.h>

#include <netif/tunif.h>
#include <lwip/socks.h>
#include <lwip/init.h>
#include <arch/libevent.h>

#include "dbg.h"
#include "list.h"
#include "fd_info.h"
#include "preload.h"
#include "ncsvc_main.h"

struct tun_ctx {
	int fds[2];
	void *data;
	struct list_head node;
};

enum msg_id {
	TUNIF_ADD,
	TUNIF_DEL,
	TUNIF_IFCONFIG,
};

struct tunif_data;

struct tun_msg {
	enum msg_id cmd;
	struct tun_ctx *ctx;
	int header;
	struct tunif_data *data;
	u_int32_t ip;
	u_int32_t gw;
	u_int32_t netmask;
	int mtu;
};

static pthread_mutex_t tun_msg_mutex = PTHREAD_MUTEX_INITIALIZER;
static int tun_msg_fd = -1;
static LIST_HEAD(tuns);

void tun_ifconfig(u_int32_t ip, u_int32_t gw, u_int32_t netmask, int mtu)
{
	struct tun_msg msg = {
		.cmd = TUNIF_IFCONFIG,
		.ip = ip,
		.gw = gw,
		.netmask = netmask,
		.mtu = mtu
	};
	dbg("%s\n", __func__);
	if (write(tun_msg_fd, &msg, sizeof(msg)) < 0)
		dbg("%s: write failed\n", __func__);
}

static int tun_open(struct fd_info *info, const char *pathname)
{
	struct tun_ctx *ctx;
	int ret;
	int fds[2];

	if (strcmp(pathname, "/dev/net/tun"))
		return FD_NONE;

	ret = socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds);
	if (ret < 0)
		return ret;

	ctx = malloc(sizeof(*ctx));
	memset(ctx, 0, sizeof(*ctx));

	info->ctx = ctx;
	ctx->fds[0] = fds[0];
	ctx->fds[1] = fds[1];

	pthread_mutex_lock(&tun_msg_mutex);
	list_add(&ctx->node, &tuns);
	pthread_mutex_unlock(&tun_msg_mutex);

	return fds[0];
}

static int tun_ioctl(struct fd_info *info, int request, void *argp)
{
	struct tun_ctx *ctx = info->ctx;
	struct tun_msg msg = {
		.cmd = TUNIF_ADD,
	};
	struct ifreq *ifr = argp;

	switch (request) {
	case TUNSETIFF:
		if (!(ifr->ifr_flags & IFF_TUN)) {
			errno = EINVAL;
			return -1;
		}
		pthread_mutex_lock(&tun_msg_mutex);
		if (ctx->data) {
			pthread_mutex_unlock(&tun_msg_mutex);
			errno = EBUSY;
			return -1;
		}
		msg.ctx = ctx;
		msg.header = !(ifr->ifr_flags & IFF_NO_PI);
		snprintf(ifr->ifr_name, sizeof(ifr->ifr_name),
			"virt_tun%d", ctx->fds[0]);
		if (write(tun_msg_fd, &msg, sizeof(msg)) < 0)
			dbg("%s: write failed\n", __func__);
		return 0;
	default:
		return FD_NONE;
	}
}

static void tun_close(struct fd_info *info)
{
	struct tun_ctx *ctx = info->ctx;

	pthread_mutex_lock(&tun_msg_mutex);
	list_del(&ctx->node);
	if (ctx->data) {
		struct tun_msg msg = {
			.cmd = TUNIF_DEL,
			.data = ctx->data,
		};
		dbg("%s: Closing tun device\n", __func__);
		if (write(tun_msg_fd, &msg, sizeof(msg)) < 0)
			dbg("%s: write failed\n", __func__);
	} else
		pthread_mutex_unlock(&tun_msg_mutex);

	free(ctx);
}

static struct fd_listener tun_listener = {
	.open = tun_open,
	.ioctl = tun_ioctl,
	.close = tun_close,
};

static void
process_msg(evutil_socket_t fd, short events, void *ctx)
{
	struct event_base *base = ctx;
	struct tunif_data *data;
	struct tun_msg msg;

	if (read(fd, &msg, sizeof(msg)) <= 0)
		return;

	switch (msg.cmd) {
	case TUNIF_ADD:
		dbg("%s: Adding tunnel\n", __func__);
		msg.ctx->data = tunif_add(base, msg.ctx->fds[1], msg.header);
		break;

	case TUNIF_DEL:
		dbg("%s: Removing tunnel\n", __func__);
		tunif_del(msg.data);
		break;

	case TUNIF_IFCONFIG:
		if (list_empty(&tuns))
			break;
		dbg("%s: Configuring tunnel\n", __func__);
		data = list_first_entry(&tuns, struct tun_ctx, node)->data;

		if (msg.ip)
			tunif_set_ipaddr(data, msg.ip);
		if (msg.netmask)
			tunif_set_netmask(data, msg.netmask);
		if (msg.gw)
			tunif_set_gw(data, msg.gw);
		if (msg.mtu)
			tunif_set_mtu(data, msg.mtu);
		tunif_set_up(data);
		break;

	}
	pthread_mutex_unlock(&tun_msg_mutex);
}

static int ignore_system(const char *command)
{
	return 0;
}

struct thread_data {
	int msg_fd;
	int ncsvc_fd;
};

static void *tun_thread(void *arg)
{
	struct thread_data *data = arg;
	struct event_base *base;
	struct event *ev;

	base = event_base_new();
	ev = event_new(base, data->msg_fd, EV_READ | EV_PERSIST, process_msg,
									base);
	event_add(ev, NULL);
	lwip_init();
	libevent_timeouts_init(base);
	ncsvc_packet_init(base, data->ncsvc_fd);
	if (socks_listen(base, ntohs(ncsvc_socks_port)) < 0)
		exit(1);
	event_base_dispatch(base);
	return NULL;
}

static void tun_init(int ncsvc_fd)
{
	struct thread_data *data;
	int fds[2];
	pthread_t id;

	fd_listener_add(&tun_listener);
	system_set_intercept(ignore_system);

	socketpair(PF_LOCAL, SOCK_SEQPACKET, 0, fds);
	data = malloc(sizeof(*data));
	data->msg_fd = fds[0];
	data->ncsvc_fd = ncsvc_fd;
	dbg("%s: Creating tun_thread\n", __func__);
	pthread_create(&id, NULL, tun_thread, data);
	tun_msg_fd = fds[1];
}

static int ncsvc_socket(struct fd_info *info, int domain, int type,
								int protocol)
{
	if (domain == AF_INET && type == SOCK_STREAM && protocol == IPPROTO_IP)
		return real_socket(domain, type, protocol);
	else
		return FD_NONE;
}

int ncsvc_bind(struct fd_info *info, const struct sockaddr *addr, socklen_t len)
{
	struct sockaddr_in *addr_in = (struct sockaddr_in *) addr;
	int fds[2];

	if (addr_in->sin_addr.s_addr != htonl(INADDR_LOOPBACK) ||
					addr_in->sin_port != htons(4242))
		return FD_NONE;

	socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, fds);
	real_close(info->fd);
	dup2(fds[0], info->fd);
	real_close(fds[0]);
	info->ctx = (void *) fds[1];

	return 0;
}

int ncsvc_listen(struct fd_info *info, int n)
{
	int fd;
	char ch = 0;
	int ret;

	if (!info->ctx)
		return FD_NONE;

	fd = (int) info->ctx;
	dbg("%s: Stuffing canary char into %d\n", __func__, fd);
	ret = write(fd, &ch, 1);

	return ret == 1 ? 0 : ret;
}

int ncsvc_accept(struct fd_info *info, struct sockaddr *addr, socklen_t *len)
{
	int fds[2];
	int ret;

	char ch = 0;

	if (!info->ctx)
		return FD_NONE;

	dbg("%s: Pulling out canary char from %d\n", __func__, info->fd);
	ret = read(info->fd, &ch, 1);
	if (ret < 0) {
		dbg("%s: canary pull failed?\n", __func__);
		return ret;
	}

	ret = socketpair(AF_LOCAL, SOCK_SEQPACKET, 0, fds);
	if (ret < 0) {
		dbg("%s: socketpair failed\n", __func__);
		return ret;
	}

	tun_init(fds[1]);

	return fds[0];
}

void ncsvc_close(struct fd_info *info)
{

	if (info->ctx) {
		int fd;
		fd = (int) info->ctx;
		real_close(fd);
	}
}

struct fd_listener ncsvc_listener = {
	.socket = ncsvc_socket,
	.bind = ncsvc_bind,
	.listen = ncsvc_listen,
	.accept = ncsvc_accept,
	.close = ncsvc_close,
};

__attribute__((constructor))
static void ncsvc_init(void)
{
	signal_ignore_all();
	set_ignore_fs();
	fd_listener_add(&ncsvc_listener);
}
