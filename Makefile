NAME := traceroute
PROGRAM := traceroute/traceroute
LIBSUPP := libsupp/libsupp.a

CROSS ?=
CC = $(CROSS)gcc
AR = $(CROSS)ar
RANLIB = $(CROSS)ranlib
PKG_CONFIG ?= pkg-config

prefix ?= /usr/local
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
datadir ?= $(prefix)/share
mandir ?= $(datadir)/man
DESTDIR ?=

INSTALL ?= install
INSTALL_PROGRAM ?= $(INSTALL) -m 0755
INSTALL_DATA ?= $(INSTALL) -m 0644
MKDIR_P ?= mkdir -p

CPPFLAGS += -D_GNU_SOURCE -Iinclude -Ilibsupp -Itraceroute
CFLAGS ?= -g -Wall -std=c99 -O0
LDFLAGS ?= -g
LDLIBS += -lm -lpthread

ifndef DISABLE_OPENSSL
OPENSSL_PKG := $(shell $(PKG_CONFIG) --exists openssl3 2>/dev/null && echo openssl3 || echo openssl)
OPENSSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(OPENSSL_PKG) 2>/dev/null)
OPENSSL_LDLIBS := $(shell $(PKG_CONFIG) --libs $(OPENSSL_PKG) 2>/dev/null)
ifeq ($(strip $(OPENSSL_LDLIBS)),)
OPENSSL_LDLIBS := -lssl -lcrypto
endif
CPPFLAGS += -DHAVE_OPENSSL3 $(OPENSSL_CFLAGS)
LDLIBS += $(OPENSSL_LDLIBS)
endif

SUPP_SRCS := $(wildcard libsupp/*.c)
SUPP_OBJS := $(SUPP_SRCS:.c=.o)

TR_SRCS := $(wildcard traceroute/*.c)
TR_OBJS := $(TR_SRCS:.c=.o)

DEPS := $(SUPP_OBJS:.o=.d) $(TR_OBJS:.o=.d)

.PHONY: all traceroute clean distclean install uninstall libclean depend

all: $(PROGRAM)

traceroute: $(PROGRAM)

$(PROGRAM): $(TR_OBJS) $(LIBSUPP)
	$(CC) $(LDFLAGS) -o $@ $(TR_OBJS) $(LIBSUPP) $(LDLIBS) $(LIBS)

$(LIBSUPP): $(SUPP_OBJS)
	$(AR) rc $@ $^
	$(RANLIB) $@

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c -o $@ $<

depend: $(TR_OBJS) $(SUPP_OBJS)

install: $(PROGRAM)
	$(MKDIR_P) $(DESTDIR)$(bindir)
	$(MKDIR_P) $(DESTDIR)$(mandir)/man8
	$(INSTALL_PROGRAM) $(PROGRAM) $(DESTDIR)$(bindir)/$(NAME)
	$(INSTALL_DATA) traceroute/traceroute.8 $(DESTDIR)$(mandir)/man8/$(NAME).8

uninstall:
	rm -f $(DESTDIR)$(bindir)/$(NAME)
	rm -f $(DESTDIR)$(mandir)/man8/$(NAME).8

libclean:
	rm -f $(LIBSUPP)

clean:
	rm -f $(TR_OBJS) $(SUPP_OBJS) $(DEPS) $(PROGRAM) $(LIBSUPP)

distclean: clean

-include $(DEPS)
