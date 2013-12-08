#ifndef __PRELOAD_H__
#define __PRELOAD_H__

#include <dlfcn.h>
#include <sys/types.h>

#define ASSIGN(x) do { 						\
	if (!orig_ ## x) orig_ ##x = dlsym(RTLD_NEXT, #x);	\
} while (0)

struct ioctl_names {
	int request;
	char name[32];
};

#define barrier() __asm__ __volatile__ ("" : : : "memory")

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct event_base;

int real_socket(int domain, int type, int protocol);
void set_ignore_fs(void);
void exec_set_intercept(int (*execv)(const char *file, char *const argv[]));
void system_set_intercept(int (*_system)(const char *command));
void signal_ignore_all(void);
void tun_ifconfig(u_int32_t ip, u_int32_t gw, u_int32_t netmask, int mtu);
void ncsvc_packet_init(struct event_base *base, int fd);

#endif
