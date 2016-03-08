export VERSION      := 0
export SUBVERSION   := 8
export MINORVERSION := 2-SNAPSHOT

all: nethogs decpcap_test
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

runtests: test
	./test
	
.PHONY: tgz
tgz: clean
	cd .. ; tar czvf nethogs-$(VERSION).$(SUBVERSION).$(MINORVERSION).tar.gz --exclude-vcs nethogs/*

.PHONY: check uninstall
check:
	$(MAKE) -f MakeApp.mk $@

install: nethogs nethogs.8
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

uninstall:
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@
	 
nethogs: main.cpp nethogs.cpp $(OBJS)
	$(MAKE) -f MakeApp.mk $@
	 
decpcap_test: decpcap_test.cpp decpcap.o
	$(MAKE) -f MakeApp.mk $@
	 
.PHONY: clean
clean:
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@
