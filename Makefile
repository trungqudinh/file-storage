BINDIR = build
APPS = client server
client_source = client.cpp
server_source = server.cpp

CXX = g++ -Wall -std=c++14 -Iwebsocketpp -Iinclude
LIBS = -pthread -pthread -lssl -lcrypto -lboost_serialization -lboost_iostreams -lboost_filesystem
DESTDIR = /usr/local/bin/
BUILD_CMD = $(CXX) $(SOURCES) -o $(BINDIR)/$(APPS) $(LIBS)

all: $(APPS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(APPS): SOURCES = $@/$($@_source)
$(APPS): $(BINDIR)
	@echo BUILDING $@
	$(CXX) $(SOURCES) -o $(BINDIR)/$@ $(LIBS)

clean:
	rm -rf $(BINDIR)

deb:
	@debuild -us -uc -b -d

install:
	install -m 0755 $(BINDIR)/$(APPS) $(DESTDIR)

.PHONY: $(APPS)
