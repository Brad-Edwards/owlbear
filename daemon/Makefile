# Owlbear daemon — userspace event processor
#
# Builds: owlbeard (the daemon binary)
#
# Requires: libbpf, libelf, zlib for BPF skeleton loading.
# eBPF skeleton headers must be pre-generated in ../ebpf/ via `make -C ebpf`.

TARGET   := owlbeard

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror -Wpedantic \
            -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 \
            $(INCLUDES) $(CFLAGS_EXTRA) \
            -I../ebpf
LDFLAGS  := -lpthread -lcurl -lbpf -lelf -lz
DEPFLAGS  = -MMD -MP -MF $(@:.o=.d)

# Source files
SRCS     := main.c \
            bpf_loader.c \
            event_pipeline.c \
            sig_loader.c \
            integrity.c \
            self_protect.c \
            policy.c \
            scanner.c \
            heartbeat.c
OBJS     := $(SRCS:.c=.o)
DEPS     := $(SRCS:.c=.d)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

# bpf_loader.c depends on skeleton headers from the ebpf build
bpf_loader.o: bpf_loader.c ../ebpf/owlbear_lsm.skel.h ../ebpf/owlbear_trace.skel.h ../ebpf/owlbear_kprobe.skel.h

clean:
	$(RM) $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
