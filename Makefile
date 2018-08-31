INCS = -I/usr/include/libnl3
LIBS = -lnl-3
CPPFLAGS = -D_GNU_SOURCE ${INCS}
CFLAGS = -pipe -g -Wall -Wextra -O2

6brd: netlink.o ndp.o 6brd.o nloop.o ${LIBS}

clean:
	rm -f *.o

distclean: clean
	rm -f 6brd

