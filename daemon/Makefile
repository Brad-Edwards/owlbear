# Owlbear daemon — userspace event processor
#
# Builds: owlbeard (the daemon binary)
#
# Requires: libbpf, libelf, zlib for BPF skeleton loading.
# eBPF skeleton headers must be pre-generated in ../ebpf/ via `make -C ebpf`.

TARGET   := owlbeard

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror \
            -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 \
            $(INCLUDES) $(CFLAGS_EXTRA) \
            -I../ebpf
LDFLAGS  := -lpthread -lcurl -lbpf -lelf -lz -lssl -lcrypto
DEPFLAGS  = -MMD -MP -MF $(@:.o=.d)

# Source files
SRCS     := main.c \
            bpf_loader.c \
            event_pipeline.c \
            process_tree.c \
            sig_loader.c \
            integrity.c \
            hmac_sha256.c \
            self_protect.c \
            debugger_detect.c \
            preload_detect.c \
            clock_validator.c \
            vdso_integrity.c \
            policy.c \
            scanner.c \
            heartbeat.c \
            net_allowlist.c
OBJS     := $(SRCS:.c=.o)
DEPS     := $(SRCS:.c=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

# bpf_loader.c includes generated skeleton headers with overlength string literals.
bpf_loader.o: CFLAGS += -Wno-overlength-strings
bpf_loader.o: bpf_loader.c ../ebpf/owlbear_lsm.skel.h ../ebpf/owlbear_trace.skel.h ../ebpf/owlbear_kprobe.skel.h ../ebpf/owlbear_net.skel.h

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
