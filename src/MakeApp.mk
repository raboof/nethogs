sbin := $(PREFIX)/sbin

all: nethogs decpcap_test

# nethogs_testsum

CFLAGS?=-Wall -Wextra
CXXFLAGS?=-Wall -Wextra -Wno-missing-field-initializers

OBJS=packet.o connection.o process.o decpcap.o cui.o inode2prog.o conninode.o devices.o

NCURSES_LIBS?=-lncurses

.PHONY: check uninstall
check:
	@echo "Not implemented"

install: nethogs
	install -d -m 755 $(DESTDIR)$(sbin)
	install -m 755 nethogs $(DESTDIR)$(sbin)
	@echo
	@echo "Installed nethogs to $(DESTDIR)$(sbin)"
	@echo
	@echo "You might have to add this directory to your PATH and/or refresh your shells' path cache with a command like 'hash -r'."

uninstall:
	rm $(DESTDIR)$(sbin)/nethogs || true

nethogs: main.cpp nethogs.cpp $(OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) main.cpp $(OBJS) -o nethogs -lpcap -lm ${NCURSES_LIBS} -DVERSION=\"$(VERSION)\"
nethogs_testsum: nethogs_testsum.cpp $(OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) nethogs_testsum.cpp $(OBJS) -o nethogs_testsum -lpcap -lm ${NCURSES_LIBS} -DVERSION=\"$(VERSION)\"

decpcap_test: decpcap_test.cpp decpcap.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) decpcap_test.cpp decpcap.o -o decpcap_test -lpcap -lm

#-lefence

process.o: process.cpp process.h nethogs.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c process.cpp
packet.o: packet.cpp packet.h nethogs.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c packet.cpp
connection.o: connection.cpp connection.h nethogs.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c connection.cpp
decpcap.o: decpcap.c decpcap.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c decpcap.c
inode2prog.o: inode2prog.cpp inode2prog.h nethogs.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c inode2prog.cpp
conninode.o: conninode.cpp nethogs.h conninode.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c conninode.cpp
#devices.o: devices.cpp devices.h
#	$(CXX) $(CXXFLAGS) -c devices.cpp
cui.o: cui.cpp cui.h nethogs.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c cui.cpp -DVERSION=\"$(VERSION)\"

TESTS=conninode_test

.PHONY: test
test: $(TESTS)
	for test in $(TESTS); do echo $$test ; ./$$test ; done

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f $(TESTS)
	rm -f nethogs
	rm -f test
	rm -f decpcap_test
