CDEBUGFLAGS = -Os -g -Wall

DEFINES = $(PLATFORM_DEFINES)

CFLAGS = -I/usr/include/libnl3 $(CDEBUGFLAGS) $(DEFINES) $(EXTRA_DEFINES)

LDLIBS = -lnl-genl-3 -lnl-route-3 -lnl-3

SRCS = sroamd.c client.c lease.c ra.c dhcpv4.c interface.c netlink.c \
       flood.c prefix.c util.c

OBJS = sroamd.o client.o lease.o ra.o dhcpv4.o interface.o netlink.o \
       flood.o prefix.o util.o

sroamd: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o sroamd $(OBJS) $(LDLIBS)

.PHONY: clean

clean:
	-rm -f sroamd *.o *~ core TAGS gmon.out
