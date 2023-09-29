SRCS=klutz.c

CWARNEXTRA=-Wno-infinite-recursion

KMOD=klutz

DEBUG_FLAGS=-g -Wno-error

.include <bsd.kmod.mk>
