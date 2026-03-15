# Owlbear eBPF programs — BPF CO-RE with libbpf
#
# Requires: clang, llvm, bpftool, libbpf headers

CLANG    ?= clang
BPFTOOL  ?= bpftool

BPF_CFLAGS := -g -O2 -target bpf \
              -D__TARGET_ARCH_arm64 \
              -I$(CURDIR)/../include \
              -Wall -Werror

# eBPF program sources
BPF_SRCS := owlbear_lsm.bpf.c \
            owlbear_trace.bpf.c \
            owlbear_kprobe.bpf.c \
            owlbear_net.bpf.c

BPF_OBJS := $(BPF_SRCS:.c=.o)
BPF_SKELS := $(BPF_SRCS:.bpf.c=.skel.h)

# vmlinux.h is generated from the running kernel's BTF
VMLINUX_H := vmlinux.h

.PHONY: all clean vmlinux

all: $(VMLINUX_H) $(BPF_OBJS) $(BPF_SKELS)

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

%.bpf.o: %.bpf.c $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<

%.skel.h: %.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

clean:
	$(RM) $(BPF_OBJS) $(BPF_SKELS) $(VMLINUX_H)
