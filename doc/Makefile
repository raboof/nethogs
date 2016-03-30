all:

man8 := $(PREFIX)/share/man/man8

install: nethogs.8
	install -d -m 755 $(DESTDIR)$(man8)
	install -m 644 nethogs.8 $(DESTDIR)$(man8)

uninstall:
	rm $(DESTDIR)$(man8)/nethogs.8 || true

