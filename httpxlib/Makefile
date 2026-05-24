CC ?= cc
PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -g
WARN_CFLAGS := -Wall -Wextra -Werror -std=c99
LIBCURL_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcurl 2>/dev/null)
LIBCURL_LIBS := $(shell $(PKG_CONFIG) --libs libcurl 2>/dev/null || curl-config --libs)

all: libci_httpx.a ci-httpx

ci_httpx.o: ci_httpx.c ci_httpx.h
	$(CC) $(WARN_CFLAGS) $(CFLAGS) $(LIBCURL_CFLAGS) -c ci_httpx.c -o $@

libci_httpx.a: ci_httpx.o
	ar rcs $@ $<

ci-httpx: ../tools/ci_httpx_cli.c libci_httpx.a ci_httpx.h
	$(CC) $(WARN_CFLAGS) $(CFLAGS) -I. $(LIBCURL_CFLAGS) ../tools/ci_httpx_cli.c libci_httpx.a $(LIBCURL_LIBS) -o $@

clean:
	rm -f ci_httpx.o libci_httpx.a ci-httpx
	rm -rf ci-httpx.dSYM

.PHONY: all clean
