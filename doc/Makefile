all:

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),FreeBSD)
  ifeq ($(PREFIX),/usr/local)
    man8 := $(PREFIX)/man/man8
  else
    man8 := $(PREFIX)/share/man/man8
  endif
else
  man8 := $(PREFIX)/share/man/man8
endif

install: nethogs.8
	install -d -m 755 $(DESTDIR)$(man8)
	install -m 644 nethogs.8 $(DESTDIR)$(man8)

uninstall:
	rm $(DESTDIR)$(man8)/nethogs.8 || true

