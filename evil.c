/*-
 * Copyright (c) 2023 The FreeBSD Foundation.
 * Copyright (c) 2007-2012 Sandvine Incorporated. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
*/

#include <sys/param.h>
#include <sys/module.h>
#include <sys/systm.h>  /* uprintf */ 
#include <sys/errno.h>
#include <sys/param.h>  /* defines used in kernel.h */
#include <sys/lock.h>
#include <sys/kernel.h> /* types used in module initialization */
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <machine/cpufunc.h>
#include <sys/mutex.h>

#define MUTEX_NOINLINE
MALLOC_DEFINE(M_PLAYGROUND, "memleak", "Memory test tool");

/* Panic from a callout */
static void panic_callback(void *arg)
{
	panic("test panic from callout");
}

static int panic_timeout_proc(SYSCTL_HANDLER_ARGS)
{
	struct callout panic_callout;
	int error;
        int foo = 0;

        error = sysctl_handle_int(oidp, &foo, 0, req);
        if (error || !req->newptr)
                return error;

	callout_init(&panic_callout, 1);
	callout_reset(&panic_callout, 1*hz, panic_callback, NULL);
        printf("panic callback in 1 second\n");
	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, callout_panic, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, panic_timeout_proc, "I", "panic from callback");

/* Leak memory */
static int leakmem_proc(SYSCTL_HANDLER_ARGS)
{
	int error;
	int size = 0;
	error = sysctl_handle_int(oidp, &size, 0, req);
	if (!error && req->newptr) {
		void *m = malloc(size, M_PLAYGROUND, M_NOWAIT);
		printf("Allocated %d bytes at %p\n", size, m);
	}
	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, leakmem, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, leakmem_proc, "I", "Leak memory");

/* RedZone(9) test: write past the end of an allocation */
static int test_redzone(SYSCTL_HANDLER_ARGS)
{
	int error;
	int size = 0;
	error = sysctl_handle_int(oidp, &size, 0, req);
	if (!error && req->newptr) {
		char *m = (char *)malloc(size, M_PLAYGROUND, M_NOWAIT);
		printf("Allocated %d bytes at %p\n", size, m);
		/* Write 1 byte past end of allocation */
		*(m + size) = 'x';
		free(m, M_PLAYGROUND);
	}
	return error;

}
SYSCTL_PROC(_debug, OID_AUTO, test_redzone, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, test_redzone, "I", "Test redzone");

#if 0
/* Spin in a callout handler */
/* rdtsc() seems to be failing on i386 svos9 */
static struct callout_handle test_timeout_handle;
extern unsigned int tsc_freq;
static void test_timeout(void *arg)
{
        int64_t endat;
	int64_t now;
	int delay = (int)(uintptr_t)arg;
#if __FreeBSD_version < 800000
        printf("waiting for %d ms, ticks=%d softticks=%d\n", delay, ticks,
	    softticks);
#else
        printf("waiting for %d ms, ticks=%d\n", delay, ticks);
#endif

	now = (int64_t)rdtsc();
        endat = now + (int64_t)tsc_freq * (delay / 1000);
	printf("now=%jd end=%jd\n", (intmax_t)now, (intmax_t)endat);

        while ((int64_t)rdtsc() - endat < 0)
                ;

	printf("tsc=%jd\n", (intmax_t)rdtsc());
#if __FreeBSD_version < 800000
        printf("done waiting, ticks=%d softticks=%d\n", ticks, softticks);
#else
        printf("done waiting, ticks=%d\n", ticks);
#endif
}

static int timeout_proc(SYSCTL_HANDLER_ARGS)
{
	int error;
        int delay = 0;
        error = sysctl_handle_int(oidp, &delay, 0, req);
        if (error || !req->newptr)
                return error;

        test_timeout_handle = timeout(test_timeout, (void *)(uintptr_t)delay,
	    1*hz);
        printf("timeout will go off in 1s\n");
	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, callout_spin, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, timeout_proc, "I", "spin in callout handler");
#endif

#if 0
/* Call mtx_lock after disabling interrupts */
static int lock_with_cli(SYSCTL_HANDLER_ARGS)
{
        struct mtx test_mtx;
        int foo = 0;
        int error;

        __asm __volatile("pushf; pop %0" : "=r" (foo));
        error = sysctl_handle_int(oidp, &foo, 0, req);

        mtx_init(&test_mtx, "test mutex", NULL, MTX_DEF);
        __asm __volatile("cli");
        __asm __volatile("pushf; pop %0" : "=r" (foo));
        mtx_lock(&test_mtx);
        mtx_unlock(&test_mtx);
        __asm __volatile("sti");

        printf("\nFlags=0x%x\n", foo);

        
        return error;
}
SYSCTL_PROC(_debug, OID_AUTO, lock_with_cli, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, lock_with_cli, "I", "Test locking with CLI");
#endif

/* Turn off interrupts from within a callout handler */
static void timeout_cli(void *arg)
{
        printf("turning off ints in timeout\n");
        __asm ("cli");
}

static int timeout_cli_proc(SYSCTL_HANDLER_ARGS)
{
	struct callout test_timeout_handle;
	int error;
        int delay = 0;
        error = sysctl_handle_int(oidp, &delay, 0, req);
        if (error || !req->newptr)
                return error;

	callout_init(&test_timeout_handle, 1);
	callout_reset(&test_timeout_handle, 1*hz, timeout_cli,
	    (void *)(uintptr_t)delay);
        printf("timeout to turn cli off will go off in 1s\n");
	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, callout_cli, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, timeout_cli_proc, "I", "disable interrupts from callout handler");

/* Trap by writing to address 0 */
static int testtrap(SYSCTL_HANDLER_ARGS)
{
        int error;
        int foo = 0;
        error = sysctl_handle_int(oidp, &foo, 0, req);
        if (error || req->newptr == NULL)
                return error;
        /* And a trap */
	__builtin_trap();

        /* Make GCC happy */
        return error;
}
SYSCTL_PROC(_debug, OID_AUTO, testtrap, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, testtrap, "I", "Force trap by writing to addr 0");

/* Attempt to overwrite module .text */
static void overwrite_me(void)
{
	printf("Sacrificial function\n");
}

static int writetext(SYSCTL_HANDLER_ARGS)
{
	int error;
        int foo = 0;
	char *addr = (char *)overwrite_me;
        error = sysctl_handle_int(oidp, &foo, 0, req);
        if (error || req->newptr == NULL)
                return error;
        /* Write to the fn */
	printf("Trying to write to function at %p\n", addr);
	*addr = 0xff;

        /* Make GCC happy */
        return error;
}
SYSCTL_PROC(_debug, OID_AUTO, writetext, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, writetext, "I", "Write to module's .text section");

/* Sleep with nonsleepable lock */
static void grab_lock(void *arg)
{
	struct mtx *m = (struct mtx *)arg;
	printf("In callback, taking lock %p\n", m);
	mtx_lock(m);
	printf("In callback, got lock %p\n", m);
	mtx_unlock(m);
	printf("In callback, released lock %p\n", m);
}
static int nonsleepable_lock(SYSCTL_HANDLER_ARGS)
{
	struct callout lock_callout;
	int error;
	int foo = 0;
	struct mtx m;
	error = sysctl_handle_int(oidp, &foo, 0, req);
	if (error || req->newptr == NULL)
		return error;
        mtx_init(&m, "test mutex", NULL, MTX_DEF);
	callout_init(&lock_callout, 1);
	callout_reset(&lock_callout, 2*hz, grab_lock, &m);
	printf("Callback scheduled for 2s with lock %p\n", &m);

	mtx_lock(&m);
	printf("Lock %p grabbed in sysctl handler, sleeping for 10s\n", &m);
	tsleep(&m, PWAIT, "waiting", 10 * hz);
	mtx_unlock(&m);
	mtx_destroy(&m);

	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, nslock, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, nonsleepable_lock, "I", "Test nonsleepable lock debug");

/* Call null function pointer */
static int call_null_pointer(SYSCTL_HANDLER_ARGS)
{
	int error;
	int foo = 0;
	void (*func)(void);
	error = sysctl_handle_int(oidp, &foo, 0, req);
	if (error || req->newptr == NULL)
		return error;
	printf("Calling null function pointer\n");
	func = (void (*)(void))0;
	func();

	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, call_null_fp, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, call_null_pointer, "I", "Call null function pointer");

/* Infinite recursion (to test doublefault handler) */
static void recurse(void *arg)
{
	volatile int i = 1;
	int level = (int)(uintptr_t)arg;
	(void)i;
	printf("recurse(), level=%d frame_address=%p\n", level,
	    __builtin_frame_address(0));
	recurse((void *)(uintptr_t)(level + 1));
}

static int sysctl_recurse(SYSCTL_HANDLER_ARGS)
{
	int error;
	int foo = 0;
	error = sysctl_handle_int(oidp, &foo, 0, req);
	if (error || req->newptr == NULL)
		return error;
	printf("Calling recursive function\n");
	recurse(0);

	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, recursive_fn, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, sysctl_recurse, "I", "Call infinitely recursive function");

/* Infinite recursion from a callout */
static int recurse_timeout_proc(SYSCTL_HANDLER_ARGS)
{
	struct callout recurse_callout;
	int error;
        int foo = 0;
        error = sysctl_handle_int(oidp, &foo, 0, req);
        if (error || !req->newptr)
                return error;

	callout_init(&recurse_callout, 1);
	callout_reset(&recurse_callout, 1*hz, recurse, NULL);
        printf("recursive function will start in 1s\n");
	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, callout_recursive_fn, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, recurse_timeout_proc, "I", "Start recursive function from callback handler");

#if 0
/* Use floating point in kernel */
static int
fpu_in_kernel(SYSCTL_HANDLER_ARGS)
{
	int error;
	int v = 0;
	float f = 2.5;
	error = sysctl_handle_int(oidp, &v, 0, req);
	if (error || !req->newptr)
		return error;
#if __FreeBSD_version < 800000
	__asm__ ( "fild %1;"
		  "fild %2;"
		  "faddp;"
		  "fistp %0;" : "=g" (v) : "g" (v), "g" (v) ) ;
#endif

	//printf("value * 0.375 = %f\n", (double)v * 0.375);
	return error;
}
SYSCTL_PROC(_debug, OID_AUTO, fpu_in_kernel, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, fpu_in_kernel, "I", "Start recursive function from callback handler");
#endif

/* 
 * Load handler that deals with the loading and unloading of a KLD.
 */
static int
playground_modevent(struct module *m, int cmd, void *arg)
{
	int err = 0;
 
	switch (cmd) {
	case MOD_LOAD:                /* kldload */
		printf("kernel-evil playground KLD loaded.\n");
		uprintf("kernel-evil playground KLD loaded.\n\n");
		uprintf("sysctl debug.callout_panic=1            panic from a callout\n");
                uprintf("sysctl debug.leakmem=1024               leak 1K\n");
		uprintf("sysctl debug.test_redzone=1             redzone test\n");
#if 0
		uprintf("sysctl debug.callout_spin=1500          spin in callout handler (1.5s)\n");
#endif
		uprintf("sysctl debug.lock_with_cli=1            mtx lock after cli\n");
		uprintf("sysctl debug.callout_cli=1              turn off interrupts from callout\n");
		uprintf("sysctl debug.testtrap=1                 write to addr 0\n");
		uprintf("sysctl debug.writetext=1                write to module .text\n");
		uprintf("sysctl debug.nslock=1                   sleep with nonsleepable lock held\n");
		uprintf("sysctl debug.call_null_fp=1             call null function pointer\n");
		uprintf("sysctl debug.recursive_fn=1             infinitely recursive function\n");
		uprintf("sysctl debug.callout_recursive_fn=1     infinite recursion from callout\n");
#if 0
		uprintf("sysctl debug.fpu_in_kernel=1		execute fpu code\n");
#endif
		break;
	case MOD_UNLOAD:              /* kldunload */
		uprintf("Playground KLD unloaded.\n");
		break;
	default:
		err = EINVAL;
		break;
	}
	return(err);
}

/* Declare this module to the rest of the kernel */

static moduledata_t playground_mod = {
	"playground",
	playground_modevent,
	NULL
};

DECLARE_MODULE(playground, playground_mod, SI_SUB_KLD, SI_ORDER_ANY);
