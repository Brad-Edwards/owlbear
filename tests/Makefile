# Owlbear test suite

CC       ?= gcc
CFLAGS   := -std=c11 -Wall -Wextra -Werror \
            -D_GNU_SOURCE \
            -I$(CURDIR)/../include \
            -I$(CURDIR)/../daemon \
            $(CFLAGS_EXTRA)
LDFLAGS  :=
DEPFLAGS  = -MMD -MP -MF $(@:.o=.d)

DAEMON_DIR := $(CURDIR)/../daemon

# Test binaries — one per test file
TEST_BINS := test_events \
             test_policy \
             test_scanner \
             test_heartbeat \
             test_info_parse \
             test_bpf_loader \
             test_sig_loader \
             test_event_pipeline \
             test_integrity \
             test_self_protect \
             test_debugger_detect \
             test_preload_detect \
             test_process_tree \
             test_hmac_sha256 \
             test_net_allowlist \
             test_clock_validator \
             test_vdso_integrity \
             test_log

.PHONY: all unit integration clean

all: unit

unit: $(TEST_BINS)
	@failed=0; total=0; \
	for t in $(TEST_BINS); do \
		echo "--- Running $$t ---"; \
		./$$t || failed=$$((failed + 1)); \
		total=$$((total + 1)); \
		echo ""; \
	done; \
	if [ $$failed -gt 0 ]; then \
		echo "=== $$failed/$$total test suites FAILED ==="; \
		exit 1; \
	else \
		echo "=== All $$total test suites passed ==="; \
	fi

test_events: test_harness.o test_events.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_policy: test_harness.o test_policy.o $(DAEMON_DIR)/policy.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_scanner: test_harness.o test_scanner.o $(DAEMON_DIR)/scanner.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_heartbeat: test_harness.o test_heartbeat.o $(DAEMON_DIR)/heartbeat.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_info_parse: test_harness.o test_info_parse.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_bpf_loader: test_harness.o test_bpf_loader.o $(DAEMON_DIR)/bpf_event_convert.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_sig_loader: test_harness.o test_sig_loader.o $(DAEMON_DIR)/sig_loader.o $(DAEMON_DIR)/scanner.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_event_pipeline: test_harness.o test_event_pipeline.o $(DAEMON_DIR)/event_pipeline.o $(DAEMON_DIR)/policy.o $(DAEMON_DIR)/scanner.o $(DAEMON_DIR)/preload_detect.o $(DAEMON_DIR)/process_tree.o $(DAEMON_DIR)/net_allowlist.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_integrity: test_harness.o test_integrity.o $(DAEMON_DIR)/integrity.o $(DAEMON_DIR)/hmac_sha256.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

test_self_protect: test_harness.o test_self_protect.o $(DAEMON_DIR)/self_protect.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_debugger_detect: test_harness.o test_debugger_detect.o $(DAEMON_DIR)/debugger_detect.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_preload_detect: test_harness.o test_preload_detect.o $(DAEMON_DIR)/preload_detect.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_process_tree: test_harness.o test_process_tree.o $(DAEMON_DIR)/process_tree.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_hmac_sha256: test_harness.o test_hmac_sha256.o $(DAEMON_DIR)/hmac_sha256.o $(DAEMON_DIR)/integrity.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

test_net_allowlist: test_harness.o test_net_allowlist.o $(DAEMON_DIR)/net_allowlist.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_clock_validator: test_harness.o test_clock_validator.o $(DAEMON_DIR)/clock_validator.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_vdso_integrity: test_harness.o test_vdso_integrity.o $(DAEMON_DIR)/vdso_integrity.o $(DAEMON_DIR)/hmac_sha256.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lssl -lcrypto

test_log: test_harness.o test_log.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Daemon objects needed by tests
$(DAEMON_DIR)/%.o: $(DAEMON_DIR)/%.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c -o $@ $<

integration:
	@echo "Running integration tests..."
	@for t in integration/test_*.sh; do \
		echo "  $$t"; \
		bash "$$t" || exit 1; \
	done
	@echo "All integration tests passed."

clean:
	$(RM) $(TEST_BINS) *.o *.d
	$(RM) $(DAEMON_DIR)/policy.o $(DAEMON_DIR)/scanner.o $(DAEMON_DIR)/heartbeat.o
	$(RM) $(DAEMON_DIR)/bpf_event_convert.o $(DAEMON_DIR)/sig_loader.o
	$(RM) $(DAEMON_DIR)/event_pipeline.o $(DAEMON_DIR)/integrity.o $(DAEMON_DIR)/hmac_sha256.o
	$(RM) $(DAEMON_DIR)/self_protect.o $(DAEMON_DIR)/debugger_detect.o $(DAEMON_DIR)/preload_detect.o $(DAEMON_DIR)/process_tree.o $(DAEMON_DIR)/net_allowlist.o
	$(RM) $(DAEMON_DIR)/clock_validator.o $(DAEMON_DIR)/vdso_integrity.o
	$(RM) $(DAEMON_DIR)/*.d

-include $(wildcard *.d)
