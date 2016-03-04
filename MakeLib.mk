VERSION      := 0
SUBVERSION   := 8
MINORVERSION := 2-SNAPSHOT

#prefix := /usr
prefix := /usr/local
sbin := $(prefix)/lib

all: libnethogs
		
LDFLAGS:= -shared
CXXINCLUDES :=
VISIBILITY=-fvisibility=hidden
ODIR_BASE := obj

ifeq ($(DEBUG),1)
  # Debug mode options
  $(info Bulding debug version)
  ODIR:=$(ODIR_BASE)/lib/debug
  CFLAGS?=-Wall -Wextra -O0 -g -fPIC $(VISIBILITY)
  CXXFLAGS?=--std=c++0x -Wall -Wextra -O0 -g -fPIC $(VISIBILITY) $(CXXINCLUDES)
else
  # Release mode options
  ODIR:=$(ODIR_BASE)/lib/release
  CFLAGS?=-Wall -Wextra -O3 -fPIC $(VISIBILITY)
  CXXFLAGS?=-Wall --std=c++11 -Wextra -O3 -fPIC $(VISIBILITY) $(CXXINCLUDES)
endif

OBJ_NAMES= libnethogs.o packet.o connection.o process.o refresh.o decpcap.o inode2prog.o conninode.o devices.o
OBJS=$(addprefix $(ODIR)/,$(OBJ_NAMES))

#$(info $(OBJS))

.PHONY: tgz

.PHONY: uninstall

install: libnethogs
	install -d -m 755 $(DESTDIR)$(sbin)
	install -m 755 libnethogs $(DESTDIR)$(sbin)
	@echo
	@echo "Installed libnethogs to $(DESTDIR)$(sbin)"
	@echo
	@echo "You might have to add this directory to your PATH and/or refresh your shells' path cache with a command like 'hash -r'."

uninstall:
	rm $(DESTDIR)$(sbin)/libnethogs

libnethogs: $(OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o libnethogs.so -lpcap

#-lefence

$(ODIR)/refresh.o: refresh.cpp refresh.h nethogs.h
	@mkdir -p $(ODIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c refresh.cpp

$(ODIR)/process.o: process.cpp process.h nethogs.h
	@mkdir -p $(ODIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c process.cpp

$(ODIR)/packet.o: packet.cpp packet.h nethogs.h
	@mkdir -p $(ODIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c packet.cpp

$(ODIR)/connection.o: connection.cpp connection.h nethogs.h
	@mkdir -p $(ODIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c connection.cpp

$(ODIR)/decpcap.o: decpcap.c decpcap.h
	@mkdir -p $(ODIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c decpcap.c

$(ODIR)/inode2prog.o: inode2prog.cpp inode2prog.h nethogs.h
	@mkdir -p $(ODIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c inode2prog.cpp

$(ODIR)/conninode.o: conninode.cpp nethogs.h conninode.h
	@mkdir -p $(ODIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ -c conninode.cpp

$(ODIR)/devices.o: devices.cpp devices.h
	@mkdir -p $(ODIR)
	$(CXX) $(CXXFLAGS) -o $@ -c devices.cpp

$(ODIR)/libnethogs.o: libnethogs.cpp libnethogs.h
	@mkdir -p $(ODIR)
	$(CXX) $(CXXFLAGS) -o $@ -c libnethogs.cpp -DVERSION=\"$(VERSION)\" -DSUBVERSION=\"$(SUBVERSION)\" -DMINORVERSION=\"$(MINORVERSION)\"

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f libnethogs.so
	mkdir -p $(ODIR)
	rmdir -p --ignore-fail-on-non-empty $(ODIR)

