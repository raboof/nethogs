VERSION      := 0
SUBVERSION   := 6
MINORVERSION := 2pre2

#DESTDIR := /usr
DESTDIR := /usr/local

bin  := $(DESTDIR)/bin
man8 := $(DESTDIR)/share/man/man8/

all: nethogs

#CFLAGS=-g -Wall
CFLAGS=-O2
OBJS=structs.o packet.o connection.o process.o refresh.o decpcap.o cui.o inode2prog.o
GCC=g++
.PHONY: tgz

tgz: clean
	cd .. ; tar czvf nethogs-$(VERSION).$(SUBVERSION).$(MINORVERSION).tar.gz nethogs/*

.PHONY: check
check:
	echo "Not implemented"

install: nethogs nethogs.8
	cp nethogs $(bin)
	cp nethogs.8 $(man8)

nethogs: nethogs.cpp $(OBJS)
	$(GCC) $(CFLAGS) nethogs.cpp $(OBJS) -o nethogs -lpcap -lm -lncurses -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

#-lefence

refresh.o: refresh.cpp refresh.h nethogs.h
	$(GCC) $(CFLAGS) -c refresh.cpp
structs.o: structs.cpp structs.h nethogs.h
	$(GCC) $(CFLAGS) -c structs.cpp
process.o: process.cpp process.h nethogs.h
	$(GCC) $(CFLAGS) -c process.cpp
packet.o: packet.cpp packet.h nethogs.h
	$(GCC) $(CFLAGS) -c packet.cpp
connection.o: connection.cpp connection.h nethogs.h
	$(GCC) $(CFLAGS) -c connection.cpp
decpcap.o: decpcap.c decpcap.h
	gcc $(CFLAGS) -c decpcap.c
inode2prog.o: inode2prog.cpp inode2prog.h nethogs.h
	$(GCC) $(CFLAGS) -c inode2prog.cpp
cui.o: cui.cpp cui.h nethogs.h
	$(GCC) $(CFLAGS) -c cui.cpp -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f nethogs
