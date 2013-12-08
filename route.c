#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <linux/route.h>
#include <errno.h>
#include <stdlib.h>

#include "dbg.h"
#include "fd_info.h"
#include "preload.h"
#include "list.h"
#include "fopen.h"

struct fake_route {
	struct rtentry route;
	struct list_head node;
};

static LIST_HEAD(fake_routes);

static void route_parse(void)
{
	FILE *fp;
	char line[129];
	struct sockaddr_in *dst;
	struct sockaddr_in *mask;
	struct sockaddr_in *gw;

	fp = fopen("/proc/net/route", "r");
	if (!fgets(line, sizeof(line), fp)) {
		fclose(fp);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		struct fake_route *fake;
		struct rtentry *route;
		char name[32];

		fake = malloc(sizeof(*fake));
		memset(fake, 0, sizeof(*fake));
		route = &fake->route;
		dst = (struct sockaddr_in *) &route->rt_dst;
		gw = (struct sockaddr_in *) &route->rt_gateway;
		mask = (struct sockaddr_in *) &route->rt_genmask;

		sscanf(line, "%s %x %x %hx %*u %*d %hd %x %ld %ld %hd\n",
			name,
			&dst->sin_addr.s_addr,
			&gw->sin_addr.s_addr,
			&route->rt_flags,
			&route->rt_metric,
			&mask->sin_addr.s_addr,
			&route->rt_mtu,
			&route->rt_window,
			&route->rt_irtt);

		route->rt_metric++;
		if (strcmp(name, "*"))
			route->rt_dev = strdup(name);
		list_add_tail(&fake->node, &fake_routes);
	}
	fclose(fp);
}


static int route_socket(struct fd_info *info, int domain, int type, int protocol)
{
	if (domain == AF_INET && type == SOCK_DGRAM && protocol == 0)
		return real_socket(domain, type, protocol);
	else
		return FD_NONE;
}

static int route_ioctl(struct fd_info *info, int request, void *argp)
{
	struct fake_route *fake;
	struct fake_route *fake_orig = NULL;
	struct rtentry *route;
	struct sockaddr_in *dst;
	struct sockaddr_in *mask;
	struct sockaddr_in *gw;
	char dst_buf[INET_ADDRSTRLEN];
	char mask_buf[INET_ADDRSTRLEN];
	char gw_buf[INET_ADDRSTRLEN];

	if (request != SIOCADDRT && request != SIOCDELRT)
		return FD_NONE;

	route = argp;

	dst = (struct sockaddr_in *) &route->rt_dst;
	gw = (struct sockaddr_in *) &route->rt_gateway;
	mask = (struct sockaddr_in *) &route->rt_genmask;

	inet_ntop(AF_INET, &dst->sin_addr, dst_buf, sizeof(dst_buf));
	inet_ntop(AF_INET, &mask->sin_addr, mask_buf, sizeof(mask_buf));
	inet_ntop(AF_INET, &gw->sin_addr, gw_buf, sizeof(gw_buf));

	if (route->rt_flags & RTF_GATEWAY)
		dbg("%s: %s dev %s, dst %s, gw %s, mask %s\n", __func__,
			request == SIOCADDRT ? "add" : "remove",
			route->rt_dev ? : "*",
			dst_buf, gw_buf, mask_buf);
	else
		dbg("%s: %s dev %s, dst %s, mask %s\n", __func__,
			request == SIOCADDRT ? "add" : "remove",
			route->rt_dev ? : "*",
			dst_buf, mask_buf);

	if (request == SIOCADDRT) {
		fake = malloc(sizeof(*fake));
		memcpy(&fake->route, route, sizeof(fake->route));
		if (route->rt_dev)
			fake->route.rt_dev = strdup(route->rt_dev);
		list_add_tail(&fake->node, &fake_routes);
	} else {
		list_for_each_entry(fake, &fake_routes, node) {
			struct sockaddr_in *dst_a;
			struct sockaddr_in *mask_a;

			dst_a = (struct sockaddr_in *) &fake->route.rt_dst;
			mask_a = (struct sockaddr_in *) &fake->route.rt_genmask;

			if (dst_a->sin_addr.s_addr == dst->sin_addr.s_addr &&
			    mask_a->sin_addr.s_addr == mask->sin_addr.s_addr) {
				fake_orig = fake;
				break;
			}
		}

		if (!fake_orig) {
			errno = ESRCH;
			return -1;
		}
		list_del(&fake_orig->node);
		if (fake_orig->route.rt_dev)
			free(fake_orig->route.rt_dev);
		free(fake_orig);
	}
	return 0;
}

static struct fd_listener route_listener = {
	.socket = route_socket,
	.ioctl = route_ioctl,
};

static int route_check(const char *name, const char *mode)
{
	return !strcmp(name, "/proc/net/route");
}

static FILE *route_fopen(struct fopen_info *info, const char *name, const char *mode)
{
	struct fake_route *fake;
	int sz = 0;

	list_for_each_entry(fake, &fake_routes, node) {
		int len;
		struct rtentry *route;
		struct sockaddr_in *dst;
		struct sockaddr_in *mask;
		struct sockaddr_in *gw;

		route = &fake->route;
		dst = (struct sockaddr_in *) &route->rt_dst;
		gw = (struct sockaddr_in *) &route->rt_gateway;
		mask = (struct sockaddr_in *) &route->rt_genmask;

		info->ctx = realloc(info->ctx, sz + 128);
		sprintf(((char *) info->ctx) + sz,
			"%s\t%08X\t%08X\t%04X\t%d\t%u\t%d\t%08X\t%d\t%u\t%u%n",
			route->rt_dev ? : "*",
			dst->sin_addr.s_addr,
			gw->sin_addr.s_addr,
			route->rt_flags, 0, 0,
			route->rt_metric - 1,
			mask->sin_addr.s_addr,
			(int) route->rt_mtu,
			(unsigned int) route->rt_window,
			route->rt_irtt, &len);
		for (; len < 127; len++)
			((char *) info->ctx)[sz + len] = ' ';
		((char *) info->ctx)[sz + len] = '\n';
		sz += len + 1;
	}

	return fmemopen(info->ctx, sz, mode);
}

static int route_fclose(struct fopen_info *info)
{
	free(info->ctx);
	return 0;
}

static struct fopen_intercept route_intercept = {
	.intercept = route_check,
	.fopen = route_fopen,
	.fclose = route_fclose,
};

__attribute__((constructor))
static void route_init(void)
{
	fd_listener_add(&route_listener);
	route_parse();
	fopen_add_intercept(&route_intercept);
}

