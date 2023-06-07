SRCS=evil.c

CWARNEXTRA=-Wno-infinite-recursion

PG_ARCH!=uname -m
PG_MAJOR!=uname -r | sed 's/\..*//'

KMOD=evil-${PG_ARCH}-${PG_MAJOR}

DEBUG_FLAGS=-g -Wno-error

.include <bsd.kmod.mk>
