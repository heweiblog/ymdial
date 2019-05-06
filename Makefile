TGT=ymdial
SRCS=$(wildcard ./src/*.cpp)

LIBRAYS= -lrt -lpthread -ldl -lz -lresolv -lcrypto -lssl -lnetsnmp ./lib/*.a
#LIBRAYS= -lrt -lpthread -ldl -lz -lresolv -lcrypto -lssl -lnetsnmp ./lib/*.a -L/usr/lib/oracle/12.1/client64/lib/ -lclntsh -locci -lmql1 -lipc1 -lnnz12 -lons -lclntshcore

COMPILE_FLAGS= -g -W -O2 -DHAVE_NETINET_IN_H -I./include -I./clib/include -I/usr/include/openssl
#COMPILE_FLAGS= -g -W -O2 -DHAVE_NETINET_IN_H -I./include -I./clib/include -I/usr/include/openssl -I/usr/include/oracle/12.1/client64/

CC=g++

all:$(TGT)
	@echo Generation target!	

$(TGT):$(SRCS:.cpp=.o)
	$(CC) -o $@ $^ $(LIBRAYS) $(COMPILE_FLAGS) 
	
%.o : %.cpp
	$(CC) -c $(COMPILE_FLAGS) $< -o $@
	
.PHONY:	clean rpmclean 

clean:
	rm -rf $(TGT) $(SRCS:.cpp=.o)


RPM_VERSION = $(shell sed -ne 's/\#define\(\ \)\{1,\}VERSION\(\ \)\{1,\}\"\(.*\)\"/\3/p' ./include/version.h)
COMMIT = $(shell git rev-list HEAD |head -1|cut -c 1-6)
#RPM_RELEASE = $(shell git branch --no-color 2> /dev/null | sed -e '/^[^*]/d' -e 's/* \(.*\)/\1/' -e 's/-/_/g')_$(COMMIT)
RPM_RELEASE = edns_dial
RPM_TOP_DIR = $(shell rpm -E %{_topdir})
PRJHOME = $(shell pwd)

rpm:
	@echo [RPM] ; \
    	sed -e "s/@VERSION@/$(RPM_VERSION)/g" -e "s/@RELEASE@/$(RPM_RELEASE)/g" $(TGT).spec.tmp > ${RPM_TOP_DIR}/SPECS/$(TGT).spec ; \
    	cp -a -r ${PRJHOME} /tmp/$(TGT)-$(RPM_VERSION) ; \
    	cd /tmp ; \
    	tar zcvf $(RPM_TOP_DIR)/SOURCES/$(TGT)-$(RPM_VERSION).tar.gz $(TGT)-$(RPM_VERSION) ; \
    	rm -rf $(TGT)-$(RPM_VERSION) ; \
    	rpmbuild -bb $(RPM_TOP_DIR)/SPECS/$(TGT).spec ; \

rpmclean:	
	cp -r ~/rpmbuild/RPMS/x86_64/$(TGT)*$(RPM_VERSION)* ./  
	rm -rf ~/rpmbuild/SOURCES/$(TGT)* \
	~/rpmbuild/BUILD/$(TGT)* \
	~/rpmbuild/RPMS/x86_64/$(TGT)* \
	~/rpmbuild/SPEC/$(TGT)* 



