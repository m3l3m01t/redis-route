BINARIES= redis-ipset

TARGET: $(BINARIES)

CFLAGS=-Wall `pkg-config --cflags libevent libmnl` -I/usr/include/hiredis
LDFLAGS=`pkg-config --libs libevent libmnl` -lhiredis

.PHONY: clean

clean:
	$(RM) $(BINARIES)
