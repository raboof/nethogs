LIBRARY=libnethogs.so
LIBVERSION=$(VERSION)
LIBNAME=$(LIBRARY).$(LIBVERSION)
SO_NAME=$(LIBRARY).$(LIBVERSION)

libdir := $(PREFIX)/lib
incdir := $(PREFIX)/include

all: $(LIBNAME) libnethogs.a

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
  LDFLAGS:= -shared -Wl,-soname,$(SO_NAME)
else ifeq ($(UNAME_S),FreeBSD)
  LDFLAGS:= -shared -Wl,-soname,$(SO_NAME)
else
  LDFLAGS:= -shared -Wl,-install_name,$(SO_NAME)
endif

CXXINCLUDES :=
VISIBILITY=-fvisibility=hidden
ODIR_BASE := obj

ifeq ($(DEBUG),1)
  # Debug mode options
  $(info Building debug version)
  ODIR:=$(ODIR_BASE)/lib/debug
  CFLAGS?=-Wall -Wextra -O0 -g -fPIC $(VISIBILITY)
  CXXFLAGS?=-Wall -Wextra -Wno-missing-field-initializers --std=c++0x -O0 -g -fPIC $(VISIBILITY) $(CXXINCLUDES)
else
  # Release mode options
  ODIR:=$(ODIR_BASE)/lib/release
  CFLAGS?=-Wall -Wextra -O3 -fPIC $(VISIBILITY)
  CXXFLAGS?=-Wall -Wextra -Wno-missing-field-initializers --std=c++0x -O3 -fPIC $(VISIBILITY) $(CXXINCLUDES)
endif

OBJ_NAMES= libnethogs.o packet.o connection.o process.o decpcap.o inode2prog.o conninode.o devices.o
OBJS=$(addprefix $(ODIR)/,$(OBJ_NAMES))

#$(info $(OBJS))

.PHONY: uninstall

install: $(LIBNAME)
	install -d -m 755 $(DESTDIR)$(libdir)
	install -m 755 $(LIBNAME) $(DESTDIR)$(libdir)
	@echo "Installed $(LIBNAME) to $(DESTDIR)$(libdir)"
	ldconfig || true

install_dev: install
	@ln -f -s $(DESTDIR)$(libdir)/$(LIBNAME) $(DESTDIR)$(libdir)/$(LIBRARY)
	install -m 755 libnethogs.a $(DESTDIR)$(libdir)
	@echo "Installed libnethogs.a to $(DESTDIR)$(libdir)"
	install -d -m 755 $(DESTDIR)$(incdir)
	install -m 755 libnethogs.h $(DESTDIR)$(incdir)
	@echo "Installed libnethogs.h to $(DESTDIR)$(incdir)"
	ldconfig || true

uninstall:
	rm -f $(DESTDIR)$(libdir)/$(LIBNAME)
	rm -f $(DESTDIR)$(libdir)/$(LIBRARY)
	rm -f $(DESTDIR)$(libdir)/libnethogs.a
	rm -f $(DESTDIR)$(incdir)/libnethogs.h
	ldconfig || true

$(LIBNAME): $(OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(LDFLAGS) $(OBJS) -o $@ -lpcap

libnethogs.a: $(OBJS)
	$(AR) rcs $@ $(OBJS)

#-lefence

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
	$(CXX) $(CXXFLAGS) -o $@ -c libnethogs.cpp -DVERSION=\"$(LIBVERSION)\"

.PHONY: clean
clean:
	rm -f $(OBJS)
	rm -f $(LIBNAME)
	rm -f libnethogs.a
	mkdir -p $(ODIR)
	rmdir -p --ignore-fail-on-non-empty $(ODIR)
