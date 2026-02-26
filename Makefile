# Makefile for mod_sip_pcap
FREESWITCH_PREFIX ?= /usr/local/freeswitch
FS_INCLUDE        := $(FREESWITCH_PREFIX)/include/freeswitch
SOFIA_INCLUDE     := $(shell pkg-config --cflags sofia-sip-ua 2>/dev/null || echo "-I/usr/include/sofia-sip-1.13")
PCAP_LIBS         := $(shell pkg-config --libs libpcap 2>/dev/null || echo "-lpcap")

CXX      := g++
CXXFLAGS := -std=c++14 -fPIC -shared -O2 -Wall -Wextra \
            -Wno-unused-parameter \
            -Wno-missing-field-initializers \
            -isystem $(FS_INCLUDE) \
            $(SOFIA_INCLUDE) \
            -DSWITCH_API_VERSION=5

LDFLAGS  := $(PCAP_LIBS) -lpthread

TARGET   := mod_sip_pcap.so
SRC      := mod_sip_pcap.cpp

.PHONY: all install clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LDFLAGS)

install: $(TARGET)
	install -m 0755 $(TARGET) $(FREESWITCH_PREFIX)/mod/

clean:
	rm -f $(TARGET)
