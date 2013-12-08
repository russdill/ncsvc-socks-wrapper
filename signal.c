#include <signal.h>
#include <unistd.h>

#include "dbg.h"
#include "preload.h"

static int sig_ignore;

int sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
	static int (*orig_sigaction)(int, const struct sigaction*,
							struct sigaction*);
	ASSIGN(sigaction);
	dbg("%s(sig=%d)\n", __func__, sig);
	return sig_ignore ? 0 : orig_sigaction(sig, act, oact);
}

int sigaddset(sigset_t *set, int signo)
{
	static int (*orig_sigaddset)(sigset_t *set, int signo);
	ASSIGN(sigaddset);
	/* dbg("%s(signo=%d)\n", __func__, signo); */
	return orig_sigaddset(set, signo);
}

int sigdelset(sigset_t *set, int signo)
{
	static int (*orig_sigdelset)(sigset_t *set, int signo);
	ASSIGN(sigdelset);
	/* dbg("%s(signo=%d)\n", __func__, signo); */
	return orig_sigdelset(set, signo);
}

int sigemptyset(sigset_t *set)
{
	static int (*orig_sigemptyset)(sigset_t *set);
	ASSIGN(sigemptyset);
	/* dbg("%s\n", __func__); */
	return orig_sigemptyset(set);
}

int sigismember(const sigset_t *set, int signo)
{
	static int (*orig_sigismember)(const sigset_t *set, int signo);
	ASSIGN(sigismember);
	/* dbg("%s(signo=%d)\n", __func__, signo); */
	return orig_sigismember(set, signo);
}

sighandler_t signal(int sig, sighandler_t handler)
{
	static sighandler_t (*orig_signal)(int sig, sighandler_t handler);
	ASSIGN(signal);
	dbg("%s(sig=%d)\n", __func__, sig);
	return sig_ignore ? 0 : orig_signal(sig, handler);
}

unsigned int sleep(unsigned int seconds)
{
	static unsigned int (*orig_sleep)(unsigned int seconds);
	ASSIGN(sleep);
	dbg("%s(seconds=%d)\n", __func__, seconds);
	return orig_sleep(seconds);
}

void signal_ignore_all(void)
{
	sig_ignore = 1;
}
