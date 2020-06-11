PROGNAME=nfq2pcap
CC=gcc
CFLAGS=-Wall -O2 -g
OBJS=nfq2pcap.c pcap-writer.c strings.c
LIBS=-lc -lnetfilter_queue

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)

all: $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) $(LIBS)  -o $(PROGNAME)

debug: $(OBJS)
	$(CC) $(OBJS) $(CFLAGS) -DDEBUG $(LIBS) -o $(PROGNAME)

clean-all: clean
	rm -f *.pcap

clean:
	rm -f *.o
	rm -f $(PROGNAME)
	rm -f *~

install:
	cp $(PROGNAME) /usr/local/bin
	install nfq2pcap.1 /usr/share/man/man1/nfq2pcap.1

valgrind: all
	valgrind --track-origins=yes --leak-check=full ./nfq2pcap -q 100