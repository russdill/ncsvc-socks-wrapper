#ifndef __PING_H__
#define __PING_H__

#include <sys/types.h>

struct icmp_data;

void icmp_send_ping(struct icmp_data *data, u_int32_t addr);
struct icmp_data *icmp_init(void (*reply)(void *arg), void *arg);
void icmp_cleanup(struct icmp_data *data);

#endif
