VERSION      := 0
SUBVERSION   := 8
MINORVERSION := 2-SNAPSHOT

#prefix := /usr
prefix := /usr/local

sbin := $(prefix)/sbin
man8 := $(prefix)/share/man/man8/

all: nethogs decpcap_test

runtests: test
	./test
	
	
# nethogs_testsum

CFLAGS?=-Wall -Wextra
CXXFLAGS?=-Wall -Wextra

OBJS=packet.o connection.o process.o refresh.o decpcap.o cui.o inode2prog.o conninode.o devices.o

NCURSES_LIBS?=-lncurses

.PHONY: tgz

tgz: clean
	cd .. ; tar czvf nethogs-$(VERSION).$(SUBVERSION).$(MINORVERSION).tar.gz --exclude-vcs nethogs/*

.PHONY: check
check:
	echo "Not implemented"

install: nethogs nethogs.8
	install -d -m 755 $(DESTDIR)$(sbin)
	install -m 755 nethogs $(DESTDIR)$(sbin)
	install -d -m 755 $(DESTDIR)$(man8)
	install -m 644 nethogs.8 $(DESTDIR)$(man8)

test: test.cpp 
	$(CXX) $(CXXFLAGS) $(LDFLAGS) test.cpp -o test -lpcap -lm ${NCURSES_LIBS} -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

nethogs: main.cpp nethogs.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) main.cpp $(OBJS) -o nethogs -lpcap -lm ${NCURSES_LIBS} -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"
nethogs_testsum: nethogs_testsum.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) nethogs_testsum.cpp $(OBJS) -o nethogs_testsum -lpcap -lm ${NCURSES_LIBS} -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

decpcap_test: decpcap_test.cpp decpcap.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) decpcap_test.cpp decpcap.o -o decpcap_test -lpcap -lm

#-lefence

refresh.o: refresh.cpp refresh.h nethogs.h
	$(CXX) $(CXXFLAGS) -c refresh.cpp
process.o: process.cpp process.h nethogs.h
	$(CXX) $(CXXFLAGS) -c process.cpp
packet.o: packet.cpp packet.h nethogs.h
	$(CXX) $(CXXFLAGS) -c packet.cpp
connection.o: connection.cpp connection.h nethogs.h
	$(CXX) $(CXXFLAGS) -c connection.cpp
decpcap.o: decpcap.c decpcap.h
	$(CC) $(CFLAGS) -c decpcap.c
inode2prog.o: inode2prog.cpp inode2prog.h nethogs.h
	$(CXX) $(CXXFLAGS) -c inode2prog.cpp
conninode.o: conninode.cpp nethogs.h conninode.h
	$(CXX) $(CXXFLAGS) -c conninode.cpp
#devices.o: devices.cpp devices.h
#	$(CXX) $(CXXFLAGS) -c devices.cpp
cui.o: cui.cpp cui.h nethogs.h
	$(CXX) $(CXXFLAGS) -c cui.cpp -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f nethogs
	rm -f test
	rm -f decpcap_test
