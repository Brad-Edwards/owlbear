/*
 * speed_hook.so - LD_PRELOAD speed hack shared object
 *
 * Intercepts clock_gettime() via dlsym(RTLD_NEXT). For CLOCK_MONOTONIC
 * only, returns elapsed time * 2 (2x speed hack). Other clock IDs pass
 * through unmodified.
 *
 * This should be detected by:
 *   - LD_PRELOAD environment variable scanning (preload_detect)
 *   - Clock drift detection (MONOTONIC vs MONOTONIC_RAW divergence)
 *   - vDSO integrity (if patching vDSO directly)
 *
 * Compile: gcc -shared -fPIC -ldl -o speed_hook.so speed_hook_so.c
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static int (*real_clock_gettime)(clockid_t, struct timespec *);
static struct timespec first_real;
static int first_call = 1;

__attribute__((constructor))
static void speed_hook_init(void)
{
	real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
	if (!real_clock_gettime) {
		fprintf(stderr, "[speed_hook] dlsym failed: %s\n", dlerror());
		return;
	}

	/* Capture initial real time */
	real_clock_gettime(CLOCK_MONOTONIC, &first_real);
	first_call = 0;

	fprintf(stderr, "[speed_hook] Loaded into PID %d (2x speed hack)\n",
		getpid());
}

/*
 * Intercepted clock_gettime:
 *   - CLOCK_MONOTONIC: returns elapsed * 2 (time runs at 2x speed)
 *   - All other clocks: passthrough to real function
 */
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	if (!real_clock_gettime) {
		real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");
		if (!real_clock_gettime)
			return -1;
	}

	int ret = real_clock_gettime(clk_id, tp);
	if (ret != 0)
		return ret;

	if (clk_id != CLOCK_MONOTONIC)
		return 0;

	if (first_call) {
		first_real = *tp;
		first_call = 0;
		return 0;
	}

	/* Compute real elapsed */
	int64_t elapsed_ns = ((int64_t)tp->tv_sec - (int64_t)first_real.tv_sec)
			     * 1000000000LL
			     + ((int64_t)tp->tv_nsec - (int64_t)first_real.tv_nsec);

	/* Double it */
	int64_t fake_ns = elapsed_ns * 2;

	/* Add to first_real base */
	int64_t total_ns = (int64_t)first_real.tv_sec * 1000000000LL
			   + (int64_t)first_real.tv_nsec + fake_ns;

	tp->tv_sec = (time_t)(total_ns / 1000000000LL);
	tp->tv_nsec = (long)(total_ns % 1000000000LL);

	return 0;
}

__attribute__((destructor))
static void speed_hook_fini(void)
{
	fprintf(stderr, "[speed_hook] Unloaded\n");
}
