BINARIES= redis-ipset

TARGET: $(BINARIES)

CC=gcc
LD=gcc

CFLAGS=-ggdb -O0 -Wall `pkg-config --cflags libevent libmnl dbus-1 hiredis` -I./uthash/src
LDFLAGS=`pkg-config --libs libevent libmnl dbus-1 hiredis`

.PHONY: clean

redis-ipset.o: redis-ipset.c
	$(CC) -c -o $@ $(CFLAGS) $<

redis-ipset: redis-ipset.o
	$(LD) -o $@ $(LDFLAGS) $<

clean:
	$(RM) $(BINARIES) *.o
