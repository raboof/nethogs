VERSION      := 0
SUBVERSION   := 6
MINORVERSION := pre

bin  := /usr/local/bin
man8 := /usr/local/man/man8/

all: nethogs

CFLAGS=-g
OBJS=structs.o packet.o connection.o process.o hashtbl.o refresh.o
GCC=g++

.PHONY tgz

tgz: clean
	cd .. ; tar czvf nethogs-$(VERSION).$(SUBVERSION).$(MINORVERSION).tar.gz nethogs-$(VERSION).$(SUBVERSION)/*

.PHONY check
check:
	echo "Not implemented"

install: nethogs nethogs.8
	cp nethogs $(bin)
	cp nethogs.8 $(man8)

nethogs: nethogs.cpp $(OBJS)
	$(GCC) $(CFLAGS) nethogs.cpp $(OBJS) -o nethogs -lpcap -lncurses -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

#-lefence

refresh.o: refresh.cpp refresh.h nethogs.h
	$(GCC) $(CFLAGS) -c refresh.cpp
structs.o: structs.cpp structs.h nethogs.h
	$(GCC) $(CFLAGS) -c structs.cpp
process.o: process.cpp process.h inodeproc.cpp nethogs.h
	$(GCC) $(CFLAGS) -c process.cpp
packet.o: packet.cpp packet.h nethogs.h
	$(GCC) $(CFLAGS) -c packet.cpp
connection.o: connection.cpp connection.h nethogs.h
	$(GCC) $(CFLAGS) -c connection.cpp
hashtbl.o: hashtbl.cpp hashtbl.h nethogs.h
	$(GCC) $(CFLAGS) -c hashtbl.cpp

.PHONY clean
clean:
	rm -f $(OBJS)
	rm -f nethogs
