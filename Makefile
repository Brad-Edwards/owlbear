# Owlbear Anti-Cheat — Top-Level Build Orchestrator
#
# Targets:
#   all           Build everything (kernel, ebpf, daemon, game, cheats)
#   kernel        Build the kernel module
#   ebpf          Build eBPF programs
#   daemon        Build the userspace daemon
#   game          Build the test game
#   cheats        Build all test cheat programs
#   test          Run unit tests (userspace only, no root required)
#   integration   Run integration tests (requires root + ARM64)
#   clean         Remove all build artifacts
#   help          Show this help
#
# Variables:
#   ARCH           Target architecture (default: detected)
#   CROSS_COMPILE  Cross-compiler prefix (e.g., aarch64-linux-gnu-)
#   KDIR           Kernel source/headers directory
#   V              Verbose build (V=1)
#   DEBUG          Debug build with sanitizers (DEBUG=1)

.PHONY: all kernel ebpf daemon game cheats test integration clean help

# Detect architecture
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),aarch64)
  ARCH := arm64
endif

# Kernel headers location
KDIR ?= /lib/modules/$(shell uname -r)/build

# Compiler settings
CC       ?= gcc
CLANG    ?= clang
LLC      ?= llc
BPFTOOL  ?= bpftool

# Shared include directory
INCLUDES := -I$(CURDIR)/include

# Export for sub-makes
export ARCH CROSS_COMPILE KDIR CC CLANG LLC BPFTOOL INCLUDES

# Debug mode
ifdef DEBUG
  export CFLAGS_EXTRA := -g -O0 -fsanitize=address,undefined -DOWL_DEBUG=1
else
  export CFLAGS_EXTRA := -O2 -DNDEBUG
endif

# -------------------------------------------------------------------------
# Top-level targets
# -------------------------------------------------------------------------

all: kernel ebpf daemon game cheats
	@echo ""
	@echo "=== Owlbear build complete ==="
	@echo "  Kernel module:  kernel/owlbear.ko"
	@echo "  Daemon:         daemon/owlbeard"
	@echo "  Game:           game/owlbear-game"
	@echo "  Cheats:         cheats/*.bin"
	@echo ""

kernel:
	@echo "=== Building kernel module ==="
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules

ebpf:
	@echo "=== Building eBPF programs ==="
	$(MAKE) -C ebpf

daemon:
	@echo "=== Building daemon ==="
	$(MAKE) -C daemon

game:
	@echo "=== Building test game ==="
	$(MAKE) -C game

cheats:
	@echo "=== Building test cheats ==="
	$(MAKE) -C cheats

# -------------------------------------------------------------------------
# Testing
# -------------------------------------------------------------------------

test:
	@echo "=== Running unit tests ==="
	$(MAKE) -C tests unit

integration:
	@echo "=== Running integration tests (requires root + ARM64) ==="
	$(MAKE) -C tests integration

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------

clean:
	@echo "=== Cleaning all build artifacts ==="
	-$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel clean 2>/dev/null || true
	-$(MAKE) -C ebpf clean 2>/dev/null || true
	-$(MAKE) -C daemon clean 2>/dev/null || true
	-$(MAKE) -C game clean 2>/dev/null || true
	-$(MAKE) -C cheats clean 2>/dev/null || true
	-$(MAKE) -C tests clean 2>/dev/null || true

# -------------------------------------------------------------------------
# Help
# -------------------------------------------------------------------------

help:
	@echo "Owlbear Anti-Cheat Build System"
	@echo ""
	@echo "Usage: make [target] [VAR=value ...]"
	@echo ""
	@echo "Targets:"
	@echo "  all           Build everything"
	@echo "  kernel        Build kernel module (owlbear.ko)"
	@echo "  ebpf          Build eBPF programs"
	@echo "  daemon        Build userspace daemon (owlbeard)"
	@echo "  game          Build test game application"
	@echo "  cheats        Build test cheat programs"
	@echo "  test          Run unit tests"
	@echo "  integration   Run integration tests (root + ARM64)"
	@echo "  clean         Remove all build artifacts"
	@echo "  help          Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  ARCH=arm64              Target architecture"
	@echo "  CROSS_COMPILE=prefix-   Cross-compiler prefix"
	@echo "  KDIR=/path/to/kernel    Kernel headers directory"
	@echo "  DEBUG=1                 Enable debug build"
	@echo "  V=1                     Verbose output"
