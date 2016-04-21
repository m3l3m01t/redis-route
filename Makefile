BINARIES= redis-ipset

TARGET: $(BINARIES)

CFLAGS=-Wall `pkg-config --cflags libevent libmnl dbus-1` -I/usr/include/hiredis
LDFLAGS=`pkg-config --libs libevent libmnl dbus-1` -lhiredis

.PHONY: clean

clean:
	$(RM) $(BINARIES)
