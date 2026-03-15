# Owlbear test cheats — programs that exercise anti-cheat detection
#
# Each cheat compiles to a .bin binary for easy identification.
# The kernel_reader/ subdirectory has its own Kbuild for the kmod cheat.

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror \
            -D_GNU_SOURCE \
            $(INCLUDES) $(CFLAGS_EXTRA)
LDFLAGS  :=
DEPFLAGS  = -MMD -MP -MF $(@:.o=.d)

# Each .c file produces a corresponding .bin
CHEAT_SRCS := mem_reader.c \
              proc_mem_reader.c \
              ptrace_injector.c \
              ptrace_writer.c \
              vm_writer.c \
              mprotect_injector.c \
              mprotect_inject_via_ptrace.c \
              ld_preload_hook.c \
              debug_reg_setter.c \
              dev_mem_reader.c \
              net_exfil.c

CHEAT_BINS := $(CHEAT_SRCS:.c=.bin)
CHEAT_DEPS := $(CHEAT_SRCS:.c=.d)

# The LD_PRELOAD shared object
PRELOAD_SO := preload_hook.so

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all clean kernel_cheat

all: $(CHEAT_BINS) $(PRELOAD_SO)

%.bin: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -o $@ $< $(LDFLAGS)

$(PRELOAD_SO): preload_hook_so.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $<

kernel_cheat:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel_reader modules

clean:
	$(RM) $(CHEAT_BINS) $(PRELOAD_SO) $(CHEAT_DEPS) *.o
	-$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel_reader clean 2>/dev/null || true

-include $(CHEAT_DEPS)
