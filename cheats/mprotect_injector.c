/*
 * mprotect_injector - Test cheat using mmap(RW) + mprotect(RX)
 *
 * Allocates RW memory, writes ARM64 machine code, flips to RX via
 * mprotect, then executes. This exercises the RW->RX detection path
 * in the eBPF LSM file_mprotect hook (OWL_EVENT_MPROTECT_EXEC).
 *
 * Must be run AS the protected process or in its context for the
 * LSM hook to fire. For E2E testing, run standalone — the daemon
 * monitors via kprobe fallback even for non-protected processes.
 *
 * Usage: mprotect_injector
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
	const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);

	printf("[mprotect_injector] Allocating RW page...\n");

	/* Step 1: mmap a page with RW permissions */
	void *page = mmap(NULL, page_size,
			  PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) {
		fprintf(stderr, "[mprotect_injector] mmap failed: %s\n",
			strerror(errno));
		return EXIT_FAILURE;
	}

	printf("[mprotect_injector] RW page at %p\n", page);

	/*
	 * Step 2: Write ARM64 shellcode that returns 42.
	 *
	 * ARM64 instructions (little-endian):
	 *   mov x0, #42     -> 0xD2800540
	 *   ret              -> 0xD65F03C0
	 *
	 * On x86-64:
	 *   mov eax, 42      -> 0xB8 0x2A 0x00 0x00 0x00
	 *   ret               -> 0xC3
	 */
#if defined(__aarch64__)
	uint32_t code[] = {
		0xD2800540,  /* mov x0, #42 */
		0xD65F03C0,  /* ret */
	};
#elif defined(__x86_64__)
	uint8_t code[] = {
		0xB8, 0x2A, 0x00, 0x00, 0x00,  /* mov eax, 42 */
		0xC3,                           /* ret */
	};
#else
	#error "Unsupported architecture"
#endif

	memcpy(page, code, sizeof(code));
	printf("[mprotect_injector] Shellcode written (%zu bytes)\n",
	       sizeof(code));

	/* Step 3: Flip to RX — this is the detection trigger */
	printf("[mprotect_injector] Calling mprotect(RX) — should trigger detection\n");

	if (mprotect(page, page_size, PROT_READ | PROT_EXEC) < 0) {
		fprintf(stderr, "[mprotect_injector] mprotect failed: %s\n",
			strerror(errno));
		if (errno == EPERM)
			fprintf(stderr, "[mprotect_injector] Blocked by anti-cheat (EPERM)\n");
		munmap(page, page_size);
		return EXIT_FAILURE;
	}

	printf("[mprotect_injector] RW->RX transition succeeded\n");

	/* Step 4: Execute the shellcode */
	typedef long (*shellcode_fn)(void);
	shellcode_fn fn = (shellcode_fn)page;

	long result = fn();
	printf("[CHEAT] Shellcode executed, returned: %ld\n", result);

	if (result != 42) {
		fprintf(stderr, "[mprotect_injector] Unexpected return value\n");
		munmap(page, page_size);
		return EXIT_FAILURE;
	}

	munmap(page, page_size);
	printf("[mprotect_injector] Done.\n");
	return EXIT_SUCCESS;
}
