#ifndef __DBG_H__
#define __DBG_H__

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


#ifdef DEBUG
#define dbg(fmt, arg...) printf(APP_NAME "_preload[%d]: " fmt, getpid(), ##arg)
#define dbg_cont(fmt, arg...) printf(fmt, ##arg)
#else
#define dbg(fmt, arg...) do {} while(0)
#define dbg_cont(fmt, arg...) do {} while(0)
#endif

#endif
