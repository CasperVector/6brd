INCS = -I/usr/include/libnl3
LIBS = -lnl-3 -lubox
CPPFLAGS = -D_GNU_SOURCE ${INCS}
CFLAGS = -pipe -g -Wall -Wextra -O2

odhcpd: netlink.o ndp.o odhcpd.o ${LIBS}

clean:
	rm -f *.o

distclean: clean
	rm -f odhcpd
