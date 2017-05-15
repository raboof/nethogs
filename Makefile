export VERSION := $(shell ./determineVersion.sh)

#export PREFIX := /usr
export PREFIX ?= /usr/local

all: decpcap_test test nethogs

.PHONY: tgz release check install install_lib install_dev uninstall uninstall_lib nethogs libnethogs decpcap_test test clean all
tgz: clean
	git archive --prefix="nethogs-$(VERSION)/" -o "../nethogs-$(VERSION).tar.gz" HEAD

release: clean
	git tag -s v$(RELEASE) -m "Release $(RELEASE)"
	git archive --prefix="nethogs-$(RELEASE)/" -o "../nethogs-$(RELEASE).tar.gz" "v$(RELEASE)"
	gpg --armor --detach-sign "../nethogs-$(RELEASE).tar.gz"
	git push --tags
	echo "now upload the detached signature ../nethogs-$(RELEASE).tar.gz.asc to https://github.com/raboof/nethogs/releases/new?tag=v$(VERSION)"

check:
	$(MAKE) -C src -f MakeApp.mk $@

install:
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C doc $@

install_lib:
	$(MAKE) -C src -f MakeLib.mk install

install_dev:
	$(MAKE) -C src -f MakeLib.mk $@

uninstall:
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C doc $@

uninstall_lib:
	$(MAKE) -C src -f MakeLib.mk uninstall

nethogs:
	$(MAKE) -C src -f MakeApp.mk $@

libnethogs:
	$(MAKE) -C src -f MakeLib.mk all

decpcap_test:
	$(MAKE) -C src -f MakeApp.mk $@

test:
	$(MAKE) -C src -f MakeApp.mk $@

clean:
	$(MAKE) -C src -f MakeApp.mk $@
	$(MAKE) -C src -f MakeLib.mk $@

format:
	clang-format -i src/*.c src/*.cpp src/*.h
