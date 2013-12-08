#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>

#include "dbg.h"
#include "preload.h"
#include "list.h"

static int (*system_intercept)(const char *command);

void system_set_intercept(int (*_system)(const char *command))
{
	system_intercept = _system;
}

int system(const char *command)
{
	static int (*orig_system)(const char *command);
	ASSIGN(system);
	dbg("%s(%s)\n", __func__, command);
	if (system_intercept)
		return system_intercept(command);
	else
		return orig_system(command);
}

