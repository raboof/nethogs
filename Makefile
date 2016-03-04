all: nethogs decpcap_test
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@

runtests: test
	./test
	
.PHONY: tgz
tgz: clean
	$(MAKE) -f MakeApp.mk $@

.PHONY: check uninstall
check:
	$(MAKE) -f MakeApp.mk $@

install: nethogs nethogs.8
	$(MAKE) -f MakeApp.mk $@
	 
uninstall:
	$(MAKE) -f MakeApp.mk $@
	 
nethogs: main.cpp nethogs.cpp $(OBJS)
	$(MAKE) -f MakeApp.mk $@
	 
decpcap_test: decpcap_test.cpp decpcap.o
	$(MAKE) -f MakeApp.mk $@
	 
.PHONY: clean
clean:
	$(MAKE) -f MakeApp.mk $@
	$(MAKE) -f MakeLib.mk $@
