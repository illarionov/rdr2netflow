CC?=gcc
#CFLAGS?= -O3 -pipe -DNDEBUG
CFLAGS=-W  -Wall -g -O0

DESTDIR?=/usr/local

all: rdr2netflow

clean:
	rm *.o rdr2netflow

rdr2netflow: rdr.o rdr.h netflow.h rdr2netflow.c
	$(CC) $(CFLAGS) $(LDFLAGS) rdr2netflow.c \
	   rdr.o -o rdr2netflow

rdr.o:	rdr.h rdr.c
	$(CC) $(CFLAGS) -c rdr.c

install:
	mkdir -p ${DESTDIR}/bin 2> /dev/null
	install -d -o root -g wheel -m 755 rdr2netflow ${DESTDIR}/bin

