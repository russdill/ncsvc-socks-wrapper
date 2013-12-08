#include <sys/ioctl.h>
#include <stdarg.h>

#include "dbg.h"
#include "preload.h"
#include "fd_info.h"

extern const struct ioctl_names ioctl_sockios[];

int ioctl(int fd, unsigned long int request, ...)
{
	static int (*orig_ioctl)(int fd, unsigned long int request, ...);
	void *argp;
	int ret;
	int i;

	ASSIGN(ioctl);

	va_list ap;
	va_start(ap, request);
	argp = va_arg(ap, void*);
	va_end(ap);

	for (i = 0; ioctl_sockios[i].request; i++)
		if (ioctl_sockios[i].request == request) break;

	ret = fd_ioctl(fd, request, argp);
	if (ret == FD_NONE)
		ret = orig_ioctl(fd, request, argp);

	if (ioctl_sockios[i].request)
		dbg("%s(fd=%d, request=%s, argp=%p) = %d\n", __func__, fd,
			ioctl_sockios[i].name, argp, ret);
	else
		dbg("%s(fd=%d, request=%ld, argp=%p) = %d\n", __func__, fd,
			request, argp, ret);

	return ret;
}
