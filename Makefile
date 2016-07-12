export VERSION      := $(shell ./determineVersion.sh)

#export PREFIX := /usr
export PREFIX ?= /usr/local

all: nethogs decpcap_test test
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C src -f MakeLib.mk $@

.PHONY: tgz release
tgz: clean
	git archive --prefix="nethogs-$(VERSION)/" -o "../nethogs-$(VERSION).tar.gz" HEAD

release: clean
	git tag -s v$(RELEASE) -m "Release $(RELEASE)"
	git archive --prefix="nethogs-$(RELEASE)/" -o "../nethogs-$(RELEASE).tar.gz" "v$(RELEASE)"
	gpg --armor --detach-sign "../nethogs-$(RELEASE).tar.gz"
	git push --tags
	echo "now upload the detached signature to https://github.com/raboof/nethogs/releases/edit/v$VERSION"

check:
	$(MAKE) -C src -f MakeApp.mk $@

install:
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C src -f MakeLib.mk $@
	$(MAKE) -C doc $@

install_dev:
	$(MAKE) -C src -f MakeLib.mk $@
	$(MAKE) -C doc $@

uninstall:
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C src -f MakeLib.mk $@
	$(MAKE) -C doc $@

nethogs:
	$(MAKE) -C src -f MakeApp.mk $@

decpcap_test:
	$(MAKE) -C src -f MakeApp.mk $@

test:
	$(MAKE) -C src -f MakeApp.mk $@

clean:
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C src -f MakeLib.mk $@

format:
	clang-format -i src/*.c src/*.cpp src/*.h
