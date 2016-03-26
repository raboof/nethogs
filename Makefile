export VERSION      := 0
export SUBVERSION   := 8
export MINORVERSION := 2-SNAPSHOT

all: nethogs decpcap_test
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

runtests: test
	./test

.PHONY:
tgz: clean
	cd .. ; tar czvf nethogs-$(VERSION).$(SUBVERSION).$(MINORVERSION).tar.gz --exclude-vcs nethogs/*

check:
	$(MAKE) -f MakeApp.mk $@

install:
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

install_dev:
	$(MAKE) -f MakeLib.mk $@

uninstall:
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

nethogs:
	$(MAKE) -f MakeApp.mk $@

decpcap_test:
	$(MAKE) -f MakeApp.mk $@

clean:
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

format:
	clang-format -i *.c *.cpp *.h
