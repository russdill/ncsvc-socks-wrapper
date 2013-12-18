CC=gcc
LWIP?=$(HOME)/src/lwip
CFLAGS=-fno-stack-protector -Wall -O2 -g -D_GNU_SOURCE -fPIC
CFLAGS+=-I$(LWIP)/src/include/ipv4 -I$(LWIP)/src/include/ipv6
CFLAGS+=-I$(LWIP)/src/include
JAVA_32=$(shell java -version 2>&1 | grep -q "32-Bit" && echo -m32)

LIB_SOURCES=\
fd.c \
fd_info.c \
files.c \
fopen.c \
ioctl.c \
ioctl_sockios.c \
signal.c \
socket.c \
uid.c \
system.c

NCSVC_SOURCES=\
md5.c \
ncsvc_packet.c \
ping.c \
preload_ncsvc.c \
route.c \
resolv.c \
ncsvc_main.c \
log.c

TNCC_SOURCES=\
preload_tncc.c

LIB_OBJS=$(LIB_SOURCES:.c=.o)
_NCSVC_OBJS=$(NCSVC_SOURCES:.c=.o)
_TNCC_OBJS=$(TNCC_SOURCES:.c=.o)

NCSVC_OBJDIR=ncsvc_build
TNCC_OBJDIR=tncc_build

NCSVC_OBJS=$(addprefix $(NCSVC_OBJDIR)/,$(LIB_OBJS) $(_NCSVC_OBJS))
TNCC_OBJS=$(addprefix $(TNCC_OBJDIR)/,$(LIB_OBJS) $(_TNCC_OBJS))

LIBS=-L. -L$(LWIP) -ldl -levent_core -lpthread -ltunsock -nostdlib -lpcap

all: $(NCSVC_OBJDIR)/ncsvc_preload.so $(TNCC_OBJDIR)/tncc_preload.so

$(NCSVC_OBJDIR):
	mkdir -p $@

$(TNCC_OBJDIR):
	mkdir -p $@

$(NCSVC_OBJS): | $(NCSVC_OBJDIR)
$(TNCC_OBJS): | $(TNCC_OBJDIR)

$(NCSVC_OBJDIR)/ncsvc_preload.so: $(NCSVC_OBJS) | $(NCSVC_OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -m32 -shared -Wl,-soname,$@ -o $@ $^ $(LIBS)

$(TNCC_OBJDIR)/tncc_preload.so: $(TNCC_OBJS) | $(TNCC_OBJDIR)
	$(CC) $(CFLAGS) $(LDFLAGS) $(JAVA_32) -shared -Wl,-soname,$@ -o $@ $^ -ldl

$(NCSVC_OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -DAPP_NAME=\"ncsvc\" -m32 -c $< -o $@

$(TNCC_OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -DAPP_NAME=\"tncc\" $(JAVA_32) -c $< -o $@

DESTDIR=$(HOME)/.juniper_networks

install: all
	mkdir -p $(DESTDIR)
	cp $(NCSVC_OBJDIR)/ncsvc_preload.so $(TNCC_OBJDIR)/tncc_preload.so $(DESTDIR)

clean:
	-rm -rf $(NCSVC_OBJDIR) $(TNCC_OBJDIR)
