CC=gcc
LWIP=$(HOME)/src/lwip
CFLAGS=-fno-stack-protector -m32 -Wall -O2 -g -D_GNU_SOURCE -fPIC -I$(LWIP)/src/include
#CFLAGS += -DDEBUG

C_SOURCES=\
fd.c \
fd_info.c \
files.c \
fopen.c \
ioctl.c \
ioctl_sockios.c \
signal.c \
socket.c \
uid.c \
preload_ncsvc.c \
route.c \
resolv.c \
system.c \
md5.c \
ncsvc_packet.c \
ncsvc_main.c \
log.c

OBJS=$(C_SOURCES:.c=.o)

LIBS=-L. -L$(LWIP) -ldl -levent_core -lpthread -ltunsock -nostdlib -lpcap

all: ncsvc_preload.so

ncsvc_preload.so: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -Wl,-soname,$@ -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f ncsvc_preload.so *.o

